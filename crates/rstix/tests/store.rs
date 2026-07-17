//! Integration tests for the `store` feature.

use rstix::core::{QueryableStixObject, SdoKind, StixObjectKind};
use rstix::parse_bundle;
use rstix::store::{MemoryStore, QueryCursor, StixQuery, StixStore, StoreError};

#[test]
fn store_import_bundle_idempotent() {
    let bundle = parse_bundle(include_str!("fixtures/store/sco-ipv4-minimal.json")).expect("parse");
    let store = MemoryStore::new();
    let first = store.import_bundle(&bundle).expect("import");
    assert_eq!(first.objects_added, 1);
    let second = store.import_bundle(&bundle).expect("reimport");
    assert_eq!(second.objects_deduplicated, 1);
}

#[test]
fn store_get_sco_preserves_asserted_id() {
    let bundle = parse_bundle(include_str!("fixtures/store/sco-ipv4-minimal.json")).expect("parse");
    let store = MemoryStore::new();
    store.import_bundle(&bundle).expect("import");
    let sco_id = bundle.objects()[0].id().clone();
    let stored = store.get_sco(&sco_id).expect("lookup").expect("sco");
    assert_eq!(stored.asserted_id, sco_id);
}

#[test]
fn store_query_pagination_integration() {
    let bundle = parse_bundle(include_str!("fixtures/store/multi-indicators.json")).expect("parse");
    let store = MemoryStore::new();
    store.import_bundle(&bundle).expect("import");

    let page = store
        .query(
            &StixQuery::new()
                .type_filter(vec![StixObjectKind::Sdo(SdoKind::Indicator)])
                .max_results(1),
        )
        .expect("query");
    assert_eq!(page.objects.len(), 1);
    assert!(page.next_cursor.is_some());

    let tail = store
        .query(
            &StixQuery::new()
                .type_filter(vec![StixObjectKind::Sdo(SdoKind::Indicator)])
                .cursor(page.next_cursor.unwrap()),
        )
        .expect("tail");
    assert_eq!(tail.objects.len(), 2);
}

#[test]
fn store_invalid_cursor_integration() {
    let bundle = parse_bundle(include_str!("fixtures/store/multi-indicators.json")).expect("parse");
    let store = MemoryStore::new();
    store.import_bundle(&bundle).expect("import");

    let err = store
        .query(
            &StixQuery::new()
                .type_filter(vec![StixObjectKind::Sdo(SdoKind::Indicator)])
                .cursor(QueryCursor { offset: 100 }),
        )
        .expect_err("invalid");
    assert!(matches!(err, StoreError::InvalidQuery(_)));
}

#[test]
fn store_export_and_delete() {
    let bundle = parse_bundle(include_str!("fixtures/store/multi-indicators.json")).expect("parse");
    let store = MemoryStore::new();
    store.import_bundle(&bundle).expect("import");
    let exported = store
        .export_bundle(
            "bundle--00000000-0000-0000-0000-000000000099"
                .parse()
                .expect("id"),
        )
        .expect("export");
    assert_eq!(exported.objects().len(), 3);
    let first_id = bundle.objects()[0].id().clone();
    assert!(store.delete(&first_id).expect("delete"));
    assert!(store.get(&first_id).expect("get").is_none());
}

#[test]
fn store_text_search_finds_indicator_label() {
    let bundle = parse_bundle(include_str!("fixtures/store/multi-indicators.json")).expect("parse");
    let store = MemoryStore::new();
    store.import_bundle(&bundle).expect("import");
    let results = store
        .query(&StixQuery::new().text_search("alpha"))
        .expect("query");
    assert_eq!(results.objects.len(), 1);
    assert_eq!(results.objects[0].type_name(), "indicator");
}
