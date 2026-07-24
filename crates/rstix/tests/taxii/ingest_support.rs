//! Wiremock helpers for TAXII collection ingest tests.

use rstix::taxii::{
    CapabilityPolicy, PostSubmitPolicy, PreflightPolicy, TaxiiClient, TaxiiClientConfig,
};
use wiremock::{MockServer, ResponseTemplate};

const TAXII_MEDIA_TYPE: &str = "application/taxii+json;version=2.1";

pub fn wiremock_client_no_preflight(server: &MockServer) -> TaxiiClient {
    TaxiiClient::new(
        TaxiiClientConfig::new(server.uri())
            .allow_insecure_http(true)
            .post_submit(PostSubmitPolicy::ReturnInitial)
            .capability(CapabilityPolicy::Disabled)
            .preflight(PreflightPolicy::Disabled),
    )
    .expect("client")
}

pub fn taxii_json(status: u16, body: serde_json::Value) -> ResponseTemplate {
    ResponseTemplate::new(status).set_body_raw(body.to_string(), TAXII_MEDIA_TYPE)
}

pub fn api_root_url(server: &MockServer) -> String {
    format!("{}/api1/", server.uri().trim_end_matches('/'))
}

pub fn minimal_indicator() -> serde_json::Value {
    serde_json::json!({
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        "created": "2016-04-06T20:03:48.000Z",
        "modified": "2016-04-06T20:03:48.000Z",
        "indicator_types": ["malicious-activity"],
        "name": "Poison Ivy Malware",
        "description": "This file is part of Poison Ivy",
        "pattern": "[ file:hashes.'SHA-256' = '4bac27393bdd9777ce02453256c5577cd02275510b2227f473d03f533924f877' ]",
        "pattern_type": "stix",
        "valid_from": "2016-01-01T00:00:00Z"
    })
}
