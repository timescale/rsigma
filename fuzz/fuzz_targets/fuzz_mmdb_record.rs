#![no_main]
use std::collections::BTreeMap;
use std::net::IpAddr;

use libfuzzer_sys::fuzz_target;
use rsigma_runtime::{MmdbDatabase, MmdbFields};

fuzz_target!(|data: &[u8]| {
    let Ok(db) = MmdbDatabase::from_bytes(data.to_vec()) else {
        return;
    };

    let fields = MmdbFields::parse(&BTreeMap::from([
        ("country".to_string(), "country.iso_code".to_string()),
        ("subdivision".to_string(), "subdivisions.0.iso_code".to_string()),
        ("latitude".to_string(), "location.latitude".to_string()),
        ("usage".to_string(), "usage_types.1".to_string()),
    ]))
    .expect("static field paths parse");

    for address in [
        "192.0.2.10",
        "198.51.100.7",
        "203.0.113.5",
        "255.255.255.255",
        "2001:db8::1",
        "::1",
    ] {
        let ip: IpAddr = address.parse().unwrap();
        let _ = db.lookup(ip, None);
        let _ = db.lookup(ip, Some(&fields));
    }
});
