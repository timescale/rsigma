//! An in-process UDP stub nameserver for the DNS enricher tests and benchmark.
//!
//! It answers from a static zone built only from RFC 2606 names and RFC 5737 /
//! RFC 3849 addresses, and counts queries per `(name, type)`. The module stays
//! self-contained so `benches/dns.rs` can include it with `#[path]`.

#![allow(dead_code)]

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use hickory_resolver::proto::op::{Message, MessageType, Query, ResponseCode};
use hickory_resolver::proto::rr::rdata::{A, AAAA, CAA, CNAME, MX, NS, PTR, SOA, SRV, TXT};
use hickory_resolver::proto::rr::{Name, RData, Record, RecordType};
use tokio::net::UdpSocket;

/// An in-process UDP nameserver bound to `127.0.0.1:0`.
pub struct StubDnsServer {
    addr: SocketAddr,
    queries: Arc<Mutex<HashMap<(String, RecordType), u64>>>,
    total: Arc<AtomicU64>,
}

impl StubDnsServer {
    /// Bind the stub and start serving in a background Tokio task.
    pub async fn start() -> Self {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = socket.local_addr().unwrap();
        let queries = Arc::new(Mutex::new(HashMap::new()));
        let total = Arc::new(AtomicU64::new(0));

        let task_socket = Arc::clone(&socket);
        let task_queries = Arc::clone(&queries);
        let task_total = Arc::clone(&total);
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                let (len, peer) = match task_socket.recv_from(&mut buf).await {
                    Ok(value) => value,
                    Err(_) => break,
                };
                let Ok(request) = Message::from_vec(&buf[..len]) else {
                    continue;
                };
                let Some(query) = request.queries.first().cloned() else {
                    continue;
                };
                let name = query.name().to_ascii().to_lowercase();
                task_total.fetch_add(1, Ordering::SeqCst);
                *task_queries
                    .lock()
                    .unwrap()
                    .entry((name.clone(), query.query_type()))
                    .or_insert(0) += 1;
                if name == "slow.example.com." {
                    continue;
                }
                let response = answer(&request, &query);
                let Ok(wire) = response.to_vec() else {
                    continue;
                };
                let _ = task_socket.send_to(&wire, peer).await;
            }
        });

        Self {
            addr,
            queries,
            total,
        }
    }

    /// The address to put in `nameservers`.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Queries seen for one name and record type.
    pub fn query_count(&self, name: &str, record_type: RecordType) -> u64 {
        let key = (name.to_ascii_lowercase(), record_type);
        self.queries.lock().unwrap().get(&key).copied().unwrap_or(0)
    }

    /// Total queries seen across every name and type.
    pub fn total_queries(&self) -> u64 {
        self.total.load(Ordering::SeqCst)
    }
}

fn name(raw: &str) -> Name {
    Name::from_utf8(raw).unwrap()
}

fn record(owner: &str, data: RData) -> Record {
    Record::from_rdata(name(owner), 300, data)
}

fn reverse_name(ip: &str) -> String {
    Name::from(ip.parse::<IpAddr>().unwrap()).to_ascii()
}

fn soa() -> Record {
    record(
        "example.com.",
        RData::SOA(SOA::new(
            name("ns1.example.com."),
            name("hostmaster.example.com."),
            2024010101,
            3600,
            600,
            86400,
            60,
        )),
    )
}

fn answer(request: &Message, query: &Query) -> Message {
    let owner = query.name().to_ascii().to_lowercase();
    let query_type = query.query_type();
    let mut response = Message::new(
        request.metadata.id,
        MessageType::Response,
        request.metadata.op_code,
    );
    response.add_query(query.clone());
    response.metadata.authoritative = true;

    match (owner.as_str(), query_type) {
        ("host.example.com.", RecordType::A) => {
            response.add_answer(record(
                "host.example.com.",
                RData::A(A("192.0.2.10".parse().unwrap())),
            ));
            response.add_answer(record(
                "host.example.com.",
                RData::A(A("192.0.2.11".parse().unwrap())),
            ));
        }
        ("host.example.com.", RecordType::AAAA) => {
            response.add_answer(record(
                "host.example.com.",
                RData::AAAA(AAAA("2001:db8::10".parse().unwrap())),
            ));
        }
        ("v4only.example.com.", RecordType::A) => {
            response.add_answer(record(
                "v4only.example.com.",
                RData::A(A("198.51.100.7".parse().unwrap())),
            ));
        }
        ("v4only.example.com.", RecordType::AAAA) => {
            response.add_authority(soa());
        }
        ("alias.example.com.", RecordType::A) => {
            response.add_answer(record(
                "alias.example.com.",
                RData::CNAME(CNAME(name("host.example.com."))),
            ));
            response.add_answer(record(
                "host.example.com.",
                RData::A(A("192.0.2.10".parse().unwrap())),
            ));
            response.add_answer(record(
                "host.example.com.",
                RData::A(A("192.0.2.11".parse().unwrap())),
            ));
        }
        ("example.com.", RecordType::MX) => {
            response.add_answer(record(
                "example.com.",
                RData::MX(MX::new(10, name("mail.example.com."))),
            ));
            response.add_answer(record(
                "example.com.",
                RData::MX(MX::new(20, name("backup.example.com."))),
            ));
        }
        ("example.com.", RecordType::TXT) => {
            response.add_answer(record(
                "example.com.",
                RData::TXT(TXT::from_bytes(vec![
                    &b"v=spf1 ip4:192.0.2.0/24"[..],
                    &b" -all"[..],
                ])),
            ));
        }
        ("example.com.", RecordType::NS) => {
            response.add_answer(record(
                "example.com.",
                RData::NS(NS(name("ns1.example.com."))),
            ));
        }
        ("example.com.", RecordType::SOA) => {
            response.add_answer(soa());
        }
        ("example.com.", RecordType::CAA) => {
            response.add_answer(record(
                "example.com.",
                RData::CAA(CAA::new_issue(false, Some(name("ca.example.net")), vec![])),
            ));
        }
        ("_sip._tcp.example.com.", RecordType::SRV) => {
            response.add_answer(record(
                "_sip._tcp.example.com.",
                RData::SRV(SRV::new(10, 60, 5060, name("sip.example.com."))),
            ));
        }
        (owner, RecordType::PTR) if owner == reverse_name("192.0.2.10") => {
            response.add_answer(record(owner, RData::PTR(PTR(name("host.example.com.")))));
        }
        (owner, RecordType::PTR) if owner == reverse_name("2001:db8::10") => {
            response.add_answer(record(owner, RData::PTR(PTR(name("host.example.com.")))));
        }
        ("missing.example.com.", _) => {
            response.metadata.response_code = ResponseCode::NXDomain;
            response.add_authority(soa());
        }
        ("broken.example.com.", _) => {
            response.metadata.response_code = ResponseCode::ServFail;
        }
        _ => {
            response.add_authority(soa());
        }
    }

    response
}
