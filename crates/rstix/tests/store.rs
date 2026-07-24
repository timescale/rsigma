//! Integration tests for the `store` feature.

use rstix::core::{QueryableStixObject, SdoKind, StixId, StixObjectKind};
use rstix::model::Bundle;
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
fn store_import_resolves_refs_against_existing_store() {
    let combined = parse_bundle(
        r#"{
  "type": "bundle",
  "id": "bundle--00000000-0000-0000-0000-000000000099",
  "objects": [
    {
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
      "created": "2016-04-06T20:03:48.000Z",
      "modified": "2016-04-06T20:03:48.000Z",
      "indicator_types": ["malicious-activity"],
      "pattern": "[ipv4-addr:value = '192.0.2.1']",
      "pattern_type": "stix",
      "valid_from": "2016-01-01T00:00:00Z"
    },
    {
      "type": "report",
      "spec_version": "2.1",
      "id": "report--84e4d88f-44ea-4bcd-bbf3-b2c1c320bcb3",
      "created": "2015-12-21T19:59:11.000Z",
      "modified": "2015-12-21T19:59:11.000Z",
      "name": "Follow-on report",
      "published": "2016-01-20T17:00:00.000Z",
      "report_types": ["threat-report"],
      "object_refs": ["indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"]
    }
  ]
}"#,
    )
    .expect("combined bundle");

    let indicator_id = StixId::parse("indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f").unwrap();
    let report_id = StixId::parse("report--84e4d88f-44ea-4bcd-bbf3-b2c1c320bcb3").unwrap();
    let indicator = combined.get(&indicator_id).unwrap().clone();
    let report = combined.get(&report_id).unwrap().clone();

    let store = MemoryStore::new();
    store
        .import_bundle(&Bundle::from_objects(
            StixId::parse("bundle--00000000-0000-0000-0000-000000000001").unwrap(),
            vec![indicator],
        ))
        .expect("first import");
    let report = store
        .import_bundle(&Bundle::from_objects(
            StixId::parse("bundle--00000000-0000-0000-0000-000000000002").unwrap(),
            vec![report],
        ))
        .expect("second import");
    assert!(
        report.unresolved_references.is_empty(),
        "ref to indicator already in store should resolve: {:?}",
        report.unresolved_references
    );
}

#[test]
fn store_import_reports_refs_missing_from_bundle_and_store() {
    let combined = parse_bundle(
        r#"{
  "type": "bundle",
  "id": "bundle--00000000-0000-0000-0000-000000000099",
  "objects": [
    {
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--22222222-2222-2222-2222-222222222222",
      "created": "2016-04-06T20:03:48.000Z",
      "modified": "2016-04-06T20:03:48.000Z",
      "indicator_types": ["malicious-activity"],
      "pattern": "[ipv4-addr:value = '192.0.2.3']",
      "pattern_type": "stix",
      "valid_from": "2016-01-01T00:00:00Z"
    },
    {
      "type": "report",
      "spec_version": "2.1",
      "id": "report--11111111-1111-1111-1111-111111111111",
      "created": "2015-12-21T19:59:11.000Z",
      "modified": "2015-12-21T19:59:11.000Z",
      "name": "Dangling ref report",
      "published": "2016-01-20T17:00:00.000Z",
      "report_types": ["threat-report"],
      "object_refs": ["indicator--22222222-2222-2222-2222-222222222222"]
    }
  ]
}"#,
    )
    .expect("combined bundle");

    let report_id = StixId::parse("report--11111111-1111-1111-1111-111111111111").unwrap();
    let report = combined.get(&report_id).unwrap().clone();

    let store = MemoryStore::new();
    let report = store
        .import_bundle(&Bundle::from_objects(
            StixId::parse("bundle--00000000-0000-0000-0000-000000000003").unwrap(),
            vec![report],
        ))
        .expect("import");
    assert_eq!(report.unresolved_references.len(), 1);
    assert_eq!(
        report.unresolved_references[0].2.as_str(),
        "indicator--22222222-2222-2222-2222-222222222222"
    );
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
