//! Integration tests for the `store-fs` feature.

use rstix::parse_bundle;
use rstix::store::{FsStore, StixStore};
use std::fs;

#[test]
fn fs_store_roundtrip_on_disk() {
    let root = std::env::temp_dir().join(format!("rstix-fs-it-{}", uuid::Uuid::new_v4()));
    let _ = fs::remove_dir_all(&root);
    let bundle = parse_bundle(include_str!("fixtures/store/sco-ipv4-minimal.json")).expect("parse");
    {
        let store = FsStore::open(&root).expect("open");
        store.import_bundle(&bundle).expect("import");
    }
    let store = FsStore::open(&root).expect("reopen");
    let sco_id = bundle.objects()[0].id().clone();
    assert!(store.get(&sco_id).expect("get").is_some());
    let _ = fs::remove_dir_all(&root);
}
