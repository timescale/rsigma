//! Integration tests for `rsigma taxii sync` (`taxii-sync` feature).

#![cfg(feature = "taxii-sync")]

mod common;

use std::fs;

use common::rsigma;
use predicates::prelude::*;
use rstix::core::StixId;
use rstix::store::{FsStore, StixStore};
use tempfile::tempdir;
use wiremock::matchers::{method, path, query_param, query_param_is_missing};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TAXII_MEDIA_TYPE: &str = "application/taxii+json;version=2.1";
const API_ROOT: &str = "/api1/";

fn taxii_json(status: u16, body: serde_json::Value) -> ResponseTemplate {
    ResponseTemplate::new(status).set_body_raw(body.to_string(), TAXII_MEDIA_TYPE)
}

fn minimal_indicator() -> serde_json::Value {
    serde_json::json!({
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        "created": "2016-04-06T20:03:48.000Z",
        "modified": "2016-04-06T20:03:48.000Z",
        "indicator_types": ["malicious-activity"],
        "name": "Poison Ivy Malware",
        "pattern": "[ file:hashes.'SHA-256' = '4bac27393bdd9777ce02453256c5577cd02275510b2227f473d03f533924f877' ]",
        "pattern_type": "stix",
        "valid_from": "2016-01-01T00:00:00Z"
    })
}

fn invalid_identity_short_timestamp() -> serde_json::Value {
    serde_json::json!({
        "type": "identity",
        "spec_version": "2.1",
        "id": "identity--11111111-1111-4111-8111-111111111111",
        "created": "2020-01-01T00:00:00Z",
        "modified": "2020-01-01T00:00:00.000Z",
        "name": "x",
        "identity_class": "organization"
    })
}

async fn mount_objects(server: &MockServer, objects: &[serde_json::Value]) {
    Mock::given(method("GET"))
        .and(path(format!("{API_ROOT}collections/col1/objects/")))
        .respond_with(taxii_json(
            200,
            serde_json::json!({
                "more": false,
                "objects": objects,
            }),
        ))
        .mount(server)
        .await;
}

fn api_root_url(server: &MockServer) -> String {
    format!("{}/api1/", server.uri().trim_end_matches('/'))
}

#[test]
fn sync_imports_collection_into_fs_store() {
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    rt.block_on(async {
        let server = MockServer::start().await;
        mount_objects(&server, &[minimal_indicator()]).await;

        let store_dir = tempdir().expect("tempdir");
        let api = api_root_url(&server);

        rsigma()
            .args([
                "taxii",
                "sync",
                "--server",
                &server.uri(),
                "--api-root",
                &api,
                "--collection",
                "col1",
                "--store",
                store_dir.path().to_str().unwrap(),
                "--allow-insecure-http",
                "--no-preflight",
                "--disable-capability-check",
                "--output-format",
                "json",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("\"objects_added\":1"));

        let store = FsStore::open(store_dir.path()).expect("reopen store");
        assert!(
            store
                .get(&StixId::parse("indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f").unwrap())
                .expect("get")
                .is_some()
        );
        assert!(store_dir.path().join("objects").read_dir().unwrap().count() >= 1);
    });
}

#[test]
fn sync_rejects_custom_object_id_that_escapes_store() {
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    rt.block_on(async {
        let server = MockServer::start().await;
        let traversal = serde_json::json!({
            "type": "../../escape",
            "spec_version": "2.1",
            "id": "../../escape--11111111-1111-4111-8111-111111111111",
            "created": "2024-01-01T00:00:00.000Z",
            "modified": "2024-01-01T00:00:00.000Z"
        });
        mount_objects(&server, &[traversal]).await;

        let base = tempdir().expect("tempdir");
        let store = base.path().join("store");
        let api = api_root_url(&server);

        rsigma()
            .args([
                "taxii",
                "sync",
                "--server",
                &server.uri(),
                "--api-root",
                &api,
                "--collection",
                "col1",
                "--store",
                store.to_str().unwrap(),
                "--allow-insecure-http",
                "--no-preflight",
                "--disable-capability-check",
                "--allow-custom",
            ])
            .assert()
            .failure()
            .stderr(predicate::str::contains("invalid type name"));

        let escaped: Vec<_> = fs::read_dir(base.path())
            .expect("read base")
            .map(|entry| entry.expect("entry").file_name())
            .filter(|name| name != "store")
            .collect();
        assert!(
            escaped.is_empty(),
            "files written outside the store: {escaped:?}"
        );
        assert_eq!(fs::read_dir(store.join("objects")).unwrap().count(), 0);
    });
}

#[test]
fn resync_is_idempotent() {
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    rt.block_on(async {
        let server = MockServer::start().await;
        mount_objects(&server, &[minimal_indicator()]).await;

        let store_dir = tempdir().expect("tempdir");
        let server_uri = server.uri();
        let api = api_root_url(&server);
        let base_args = [
            "taxii",
            "sync",
            "--server",
            server_uri.as_str(),
            "--api-root",
            api.as_str(),
            "--collection",
            "col1",
            "--store",
            store_dir.path().to_str().unwrap(),
            "--allow-insecure-http",
            "--no-preflight",
            "--disable-capability-check",
            "--output-format",
            "json",
        ];

        rsigma()
            .args(base_args)
            .assert()
            .success()
            .stdout(predicate::str::contains("\"objects_added\":1"));

        rsigma()
            .args(base_args)
            .assert()
            .success()
            .stdout(predicate::str::contains("\"objects_deduplicated\":1"));
    });
}

#[test]
fn strict_rejects_invalid_object() {
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    rt.block_on(async {
        let server = MockServer::start().await;
        mount_objects(&server, &[invalid_identity_short_timestamp()]).await;

        let store_dir = tempdir().expect("tempdir");
        let api = api_root_url(&server);

        rsigma()
            .args([
                "taxii",
                "sync",
                "--server",
                &server.uri(),
                "--api-root",
                &api,
                "--collection",
                "col1",
                "--store",
                store_dir.path().to_str().unwrap(),
                "--allow-insecure-http",
                "--no-preflight",
                "--disable-capability-check",
                "--output-format",
                "json",
            ])
            .assert()
            .code(1)
            .stdout(predicate::str::contains("\"objects_rejected\":1"));

        let entries = fs::read_dir(store_dir.path().join("objects"))
            .expect("objects dir")
            .count();
        assert_eq!(entries, 0, "invalid object must not be persisted");
    });
}

/// Relationship on page 1 references an identity on page 2 — proves `producer_strict`
/// ingest (not page-scoped References) through the CLI path.
#[test]
fn sync_forward_ref_relationship_resolves_across_pages() {
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    rt.block_on(async {
        let server = MockServer::start().await;
        let source_id = "identity--11111111-1111-4111-8111-111111111111";
        let target_id = "identity--22222222-2222-4222-8222-222222222222";
        let relationship_id = "relationship--33333333-3333-4333-8333-333333333333";

        Mock::given(method("GET"))
            .and(path(format!("{API_ROOT}collections/col1/objects/")))
            .and(query_param("limit", "1"))
            .and(query_param_is_missing("next"))
            .respond_with(taxii_json(
                200,
                serde_json::json!({
                    "more": true,
                    "next": "cursor-2",
                    "objects": [{
                        "type": "relationship",
                        "spec_version": "2.1",
                        "id": relationship_id,
                        "created": "2016-04-06T20:03:48.000Z",
                        "modified": "2016-04-06T20:03:48.000Z",
                        "relationship_type": "uses",
                        "source_ref": source_id,
                        "target_ref": target_id
                    }]
                }),
            ))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path(format!("{API_ROOT}collections/col1/objects/")))
            .and(query_param("next", "cursor-2"))
            .respond_with(taxii_json(
                200,
                serde_json::json!({
                    "more": false,
                    "objects": [
                        {
                            "type": "identity",
                            "spec_version": "2.1",
                            "id": source_id,
                            "created": "2016-04-06T20:03:48.000Z",
                            "modified": "2016-04-06T20:03:48.000Z",
                            "name": "Source identity",
                            "identity_class": "organization"
                        },
                        {
                            "type": "identity",
                            "spec_version": "2.1",
                            "id": target_id,
                            "created": "2016-04-06T20:03:48.000Z",
                            "modified": "2016-04-06T20:03:48.000Z",
                            "name": "Target identity",
                            "identity_class": "organization"
                        }
                    ]
                }),
            ))
            .mount(&server)
            .await;

        let store_dir = tempdir().expect("tempdir");
        let api = api_root_url(&server);

        rsigma()
            .args([
                "taxii",
                "sync",
                "--server",
                &server.uri(),
                "--api-root",
                &api,
                "--collection",
                "col1",
                "--store",
                store_dir.path().to_str().unwrap(),
                "--limit",
                "1",
                "--allow-insecure-http",
                "--no-preflight",
                "--disable-capability-check",
                "--output-format",
                "json",
            ])
            .assert()
            .success()
            .stdout(
                predicate::str::contains("\"objects_added\":3")
                    .and(predicate::str::contains("\"unresolved_references\":0")),
            );

        let store = FsStore::open(store_dir.path()).expect("reopen store");
        assert!(
            store
                .get(&StixId::parse(relationship_id).unwrap())
                .expect("get relationship")
                .is_some(),
            "relationship on page 1 must be stored under producer_strict"
        );
        assert!(
            store
                .get(&StixId::parse(target_id).unwrap())
                .expect("get target")
                .is_some()
        );
    });
}

#[test]
fn basic_auth_accepts_user_and_password_together() {
    rsigma()
        .args([
            "taxii",
            "sync",
            "--server",
            "https://example.com",
            "--collection",
            "col1",
            "--store",
            "/tmp/rsigma-taxii-test-store",
            "--basic-user",
            "alice",
            "--basic-password",
            "secret",
            "--limit",
            "0",
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("invalid --limit"));
}
