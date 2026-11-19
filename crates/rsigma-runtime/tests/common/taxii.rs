//! In-process TAXII 2.1 collection for source tests.

use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

const MEDIA: &str = "application/taxii+json;version=2.1";

#[derive(Clone)]
pub struct Stored {
    pub added: String,
    pub object: Value,
}

struct State {
    objects: Mutex<Vec<Stored>>,
    object_requests: Mutex<Vec<String>>,
    authorizations: Mutex<Vec<String>>,
    object_hits: AtomicUsize,
    unauthorized_after: AtomicUsize,
    over_count: AtomicBool,
    date_header: AtomicU8,
    collection: String,
}

/// When the objects endpoint sends `X-TAXII-Date-Added-Last`.
#[derive(Clone, Copy)]
pub enum DateHeader {
    Always = 0,
    Never = 1,
    NotOnLastPage = 2,
}

/// API root, collection, and paginated objects.
pub struct Server {
    pub url: String,
    pub collection: String,
    state: Arc<State>,
    // A bare `MockServer` stops accepting connections when dropped.
    _server: MockServer,
}

impl Server {
    pub async fn start(collection: &str) -> Self {
        // `MockServer::start` recycles a process-wide server. A later test can
        // still be answered by the previous test's mock. A bare server is not pooled.
        let server = MockServer::builder().start().await;
        let state = Arc::new(State {
            objects: Mutex::new(Vec::new()),
            object_requests: Mutex::new(Vec::new()),
            authorizations: Mutex::new(Vec::new()),
            object_hits: AtomicUsize::new(0),
            unauthorized_after: AtomicUsize::new(usize::MAX),
            over_count: AtomicBool::new(false),
            date_header: AtomicU8::new(DateHeader::Always as u8),
            collection: collection.to_owned(),
        });
        Mock::given(wiremock::matchers::method("GET"))
            .respond_with(Responder {
                state: Arc::clone(&state),
            })
            .mount(&server)
            .await;
        Self {
            url: format!("{}/api1/", server.uri().trim_end_matches('/')),
            collection: collection.to_owned(),
            state,
            _server: server,
        }
    }

    pub fn push(&self, added: &str, object: Value) {
        self.state.objects.lock().expect("objects").push(Stored {
            added: added.to_owned(),
            object,
        });
    }

    pub fn object_requests(&self) -> Vec<String> {
        self.state.object_requests.lock().expect("requests").clone()
    }

    pub fn authorizations(&self) -> Vec<String> {
        self.state
            .authorizations
            .lock()
            .expect("authorizations")
            .clone()
    }

    pub fn hits(&self) -> usize {
        self.state.object_hits.load(Ordering::SeqCst)
    }

    /// The next objects request after `successful` successes returns 401.
    pub fn unauthorized_after(&self, successful: usize) {
        self.state
            .unauthorized_after
            .store(successful, Ordering::SeqCst);
    }

    pub fn over_count(&self, enabled: bool) {
        self.state.over_count.store(enabled, Ordering::SeqCst);
    }

    pub fn date_header(&self, mode: DateHeader) {
        self.state.date_header.store(mode as u8, Ordering::SeqCst);
    }
}

struct Responder {
    state: Arc<State>,
}

impl Respond for Responder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let path = request.url.path().to_owned();
        if path.ends_with("/objects/") {
            return self.objects(request);
        }
        if path.contains("/collections/") && !path.ends_with("/collections/") {
            return taxii(
                200,
                json!({
                    "id": self.state.collection,
                    "title": "Indicators",
                    "can_read": true,
                    "can_write": false,
                    "media_types": ["application/stix+json;version=2.1"]
                }),
            );
        }
        taxii(
            200,
            json!({
                "title": "Test",
                "versions": ["application/taxii+json;version=2.1"],
                "max_content_length": 104857600
            }),
        )
    }
}

impl Responder {
    fn objects(&self, request: &Request) -> ResponseTemplate {
        let hits = self.state.object_hits.fetch_add(1, Ordering::SeqCst);
        self.state
            .object_requests
            .lock()
            .expect("requests")
            .push(request.url.as_str().to_owned());
        if let Some(value) = request
            .headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
        {
            self.state
                .authorizations
                .lock()
                .expect("authorizations")
                .push(value.to_owned());
        }
        if hits >= self.state.unauthorized_after.load(Ordering::SeqCst) {
            return taxii(401, json!({"title": "Unauthorized", "http_status": "401"}));
        }
        if self.state.over_count.load(Ordering::SeqCst) {
            let objects: Vec<Value> = (1..=3).map(over_count_indicator).collect();
            return taxii(200, json!({"more": false, "objects": objects}));
        }
        let query: std::collections::HashMap<String, String> = request
            .url
            .query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect();
        let added_after = query.get("added_after").cloned();
        // `next` is an index into the stored collection. Later pages of one
        // poll send `next` and omit `added_after`.
        let start = query
            .get("next")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        let stored = self.state.objects.lock().expect("objects").clone();
        let filtered: Vec<(usize, Stored)> = stored
            .into_iter()
            .enumerate()
            .filter(|(index, item)| {
                *index >= start
                    && match &added_after {
                        Some(cursor) => item.added.as_str() > cursor.as_str(),
                        None => true,
                    }
            })
            .collect();
        let limit = query
            .get("limit")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(filtered.len().max(1));
        let end = limit.min(filtered.len());
        let page = &filtered[..end];
        let more = end < filtered.len();
        let mut body = json!({
            "more": more,
            "objects": page.iter().map(|(_, item)| item.object.clone()).collect::<Vec<_>>(),
        });
        if more {
            body["next"] = json!(filtered[end].0.to_string());
        }
        let mut response = taxii(200, body);
        let send_date = match self.state.date_header.load(Ordering::SeqCst) {
            mode if mode == DateHeader::Never as u8 => false,
            mode if mode == DateHeader::NotOnLastPage as u8 => more,
            _ => true,
        };
        if send_date && let Some(added) = page.last().map(|(_, item)| item.added.clone()) {
            response = response.insert_header("X-TAXII-Date-Added-Last", added);
        }
        response
    }
}

fn taxii(status: u16, body: Value) -> ResponseTemplate {
    ResponseTemplate::new(status).set_body_raw(body.to_string(), MEDIA)
}

fn over_count_indicator(n: u8) -> Value {
    indicator(
        n,
        "2024-01-01T00:00:00.000Z",
        "[ipv4-addr:value = '198.51.100.1']",
        "",
    )
}

pub fn indicator(n: u8, modified: &str, pattern: &str, extra: &str) -> Value {
    serde_json::from_str(&format!(
        r#"{{"type":"indicator","spec_version":"2.1","id":"indicator--00000000-0000-4000-8000-{n:012x}","created":"2020-01-01T00:00:00.000Z","modified":"{modified}","pattern":"{pattern}","pattern_type":"stix","valid_from":"2020-01-01T00:00:00.000Z"{extra}}}"#
    ))
    .expect("indicator")
}
