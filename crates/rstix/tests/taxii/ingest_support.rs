//! Wiremock helpers for TAXII collection ingest tests.

#[cfg(feature = "validate")]
#[path = "../support/attck_corpus.rs"]
mod attck_corpus;

#[cfg(feature = "validate")]
pub use attck_corpus::{ATTCK_CORPUS_DEFAULT_FILE, resolve_attck_bundle_path};

#[cfg(feature = "validate")]
use rstix::model::ParseOptions;
use rstix::taxii::{
    CapabilityPolicy, PostSubmitPolicy, PreflightPolicy, TaxiiClient, TaxiiClientConfig,
};
#[cfg(feature = "validate")]
use wiremock::Mock;
#[cfg(feature = "validate")]
use wiremock::matchers::{method, path, query_param, query_param_is_missing};
use wiremock::{MockServer, ResponseTemplate};

const TAXII_MEDIA_TYPE: &str = "application/taxii+json;version=2.1";

/// TAXII page size for ATT&CK-scale paginated ingest tests.
#[cfg(feature = "validate")]
pub const ATTCK_INGEST_PAGE_SIZE: usize = 64;

/// Fixed relationship id for synthetic forward-ref fixtures.
#[cfg(feature = "validate")]
pub const SYNTHETIC_FORWARD_REF_RELATIONSHIP_ID: &str =
    "relationship--aaaaaaaa-0000-4000-8000-000000000001";

#[cfg(feature = "validate")]
pub fn synthetic_identity_id(index: usize) -> String {
    format!("identity--{index:08x}-0000-4000-8000-{index:012x}")
}

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

#[cfg(feature = "validate")]
pub fn wiremock_client_attck(server: &MockServer) -> TaxiiClient {
    TaxiiClient::new(
        TaxiiClientConfig::new(server.uri())
            .allow_insecure_http(true)
            .post_submit(PostSubmitPolicy::ReturnInitial)
            .capability(CapabilityPolicy::Disabled)
            .preflight(PreflightPolicy::Disabled)
            .parse_options(ParseOptions::default().allow_custom(true)),
    )
    .expect("client")
}

#[cfg(feature = "validate")]
pub fn synthetic_identity_objects(count: usize) -> Vec<serde_json::Value> {
    (0..count)
        .map(|index| {
            serde_json::json!({
                "type": "identity",
                "spec_version": "2.1",
                "id": synthetic_identity_id(index),
                "created": "2016-05-12T08:17:27.000Z",
                "modified": "2016-05-12T08:17:27.000Z",
                "name": format!("org-{index}"),
                "identity_class": "organization"
            })
        })
        .collect()
}

/// Relationship on page 1 whose `target_ref` is the identity at `target_index` (typically last page).
#[cfg(feature = "validate")]
pub fn synthetic_forward_ref_relationship(
    source_index: usize,
    target_index: usize,
) -> serde_json::Value {
    serde_json::json!({
        "type": "relationship",
        "spec_version": "2.1",
        "id": SYNTHETIC_FORWARD_REF_RELATIONSHIP_ID,
        "created": "2016-05-12T08:17:27.000Z",
        "modified": "2016-05-12T08:17:27.000Z",
        "relationship_type": "related-to",
        "source_ref": synthetic_identity_id(source_index),
        "target_ref": synthetic_identity_id(target_index),
    })
}

/// Mount paginated TAXII object pages for `ingest_collection` (opaque `next` cursors).
#[cfg(feature = "validate")]
pub async fn mount_paginated_taxii_objects(
    server: &MockServer,
    api_root: &str,
    collection_id: &str,
    objects: &[serde_json::Value],
    page_size: usize,
) {
    let pages: Vec<_> = objects.chunks(page_size).collect();
    for (page_index, chunk) in pages.iter().enumerate() {
        let more = page_index + 1 < pages.len();
        let next = more.then(|| format!("page-{}", page_index + 1));
        let mut mock = Mock::given(method("GET")).and(path(format!(
            "{api_root}collections/{collection_id}/objects/"
        )));
        mock = mock.and(query_param("limit", page_size.to_string()));
        if page_index == 0 {
            mock = mock.and(query_param_is_missing("next"));
        } else {
            mock = mock.and(query_param("next", format!("page-{page_index}")));
        }
        mock.respond_with(taxii_json(
            200,
            serde_json::json!({
                "more": more,
                "next": next,
                "objects": chunk,
            }),
        ))
        .mount(server)
        .await;
    }
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
