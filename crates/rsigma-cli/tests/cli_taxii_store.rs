//! Integration tests for `rsigma taxii store` (`taxii-sync` feature).

#![cfg(feature = "taxii-sync")]

mod common;

use std::fs;
use std::path::Path;

use common::rsigma;
use predicates::prelude::*;
use rstix::core::StixId;
use rstix::store::{FsStore, StixStore};
use tempfile::tempdir;

fn fixture_bundle(name: &str) -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(format!("../rstix/tests/fixtures/store/{name}"))
        .to_string_lossy()
        .into_owned()
}

fn write_invalid_identity_bundle(dir: &Path) -> String {
    let path = dir.join("invalid-identity.json");
    fs::write(
        &path,
        serde_json::json!({
            "type": "bundle",
            "id": "bundle--11111111-1111-4111-8111-111111111111",
            "objects": [{
                "type": "identity",
                "spec_version": "2.1",
                "id": "identity--11111111-1111-4111-8111-111111111111",
                "created": "2020-01-01T00:00:00Z",
                "modified": "2020-01-01T00:00:00.000Z",
                "name": "x",
                "identity_class": "organization"
            }]
        })
        .to_string(),
    )
    .expect("write");
    path.to_string_lossy().into_owned()
}

#[test]
fn store_imports_bundle_into_fs_store() {
    let store_dir = tempdir().expect("tempdir");
    let bundle = fixture_bundle("multi-indicators.json");

    rsigma()
        .args([
            "taxii",
            "store",
            "--bundle",
            &bundle,
            "--store",
            store_dir.path().to_str().unwrap(),
            "--output-format",
            "json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"objects_added\":3"));

    let store = FsStore::open(store_dir.path()).expect("reopen store");
    assert!(
        store
            .get(&StixId::parse("indicator--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").unwrap())
            .expect("get")
            .is_some()
    );
    assert!(store_dir.path().join("objects").read_dir().unwrap().count() >= 3);
}

#[test]
fn restore_is_idempotent() {
    let store_dir = tempdir().expect("tempdir");
    let bundle = fixture_bundle("multi-indicators.json");
    let base_args = [
        "taxii",
        "store",
        "--bundle",
        bundle.as_str(),
        "--store",
        store_dir.path().to_str().unwrap(),
        "--output-format",
        "json",
    ];

    rsigma()
        .args(base_args)
        .assert()
        .success()
        .stdout(predicate::str::contains("\"objects_added\":3"));

    rsigma()
        .args(base_args)
        .assert()
        .success()
        .stdout(predicate::str::contains("\"objects_deduplicated\":3"));
}

#[test]
fn strict_rejects_invalid_object() {
    let bundle_dir = tempdir().expect("tempdir");
    let store_dir = tempdir().expect("tempdir");
    let bundle = write_invalid_identity_bundle(bundle_dir.path());

    rsigma()
        .args([
            "taxii",
            "store",
            "--bundle",
            &bundle,
            "--store",
            store_dir.path().to_str().unwrap(),
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
}

#[test]
fn rejects_custom_object_id_that_escapes_store() {
    let bundle_dir = tempdir().expect("tempdir");
    let base = tempdir().expect("tempdir");
    let store = base.path().join("store");
    let bundle = bundle_dir.path().join("traversal.json");
    fs::write(
        &bundle,
        serde_json::json!({
            "type": "bundle",
            "id": "bundle--11111111-1111-4111-8111-111111111111",
            "objects": [{
                "type": "../../escape",
                "spec_version": "2.1",
                "id": "../../escape--11111111-1111-4111-8111-111111111111",
                "created": "2024-01-01T00:00:00.000Z",
                "modified": "2024-01-01T00:00:00.000Z"
            }]
        })
        .to_string(),
    )
    .expect("write bundle");

    rsigma()
        .args([
            "taxii",
            "store",
            "--bundle",
            bundle.to_str().unwrap(),
            "--store",
            store.to_str().unwrap(),
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
}

#[test]
fn store_reads_bundle_from_stdin() {
    let store_dir = tempdir().expect("tempdir");
    let bundle = fs::read_to_string(fixture_bundle("multi-indicators.json")).expect("read");

    rsigma()
        .args([
            "taxii",
            "store",
            "--bundle",
            "-",
            "--store",
            store_dir.path().to_str().unwrap(),
            "--output-format",
            "json",
        ])
        .write_stdin(bundle)
        .assert()
        .success()
        .stdout(predicate::str::contains("\"objects_added\":3"));
}
