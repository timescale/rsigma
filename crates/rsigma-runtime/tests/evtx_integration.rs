#![cfg(feature = "evtx")]

use rsigma_eval::{Engine, JsonEvent};
use rsigma_parser::parse_sigma_yaml;
use rsigma_runtime::EvtxFileReader;

const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/security.evtx");

#[test]
fn reads_records_from_fixture() {
    let mut reader = EvtxFileReader::open(FIXTURE).expect("failed to open fixture");
    let records: Vec<_> = reader.records().collect();

    assert!(
        !records.is_empty(),
        "expected at least one record from fixture"
    );

    let first = records[0].as_ref().expect("first record should parse");
    assert!(
        first.get("Event").is_some(),
        "expected top-level 'Event' key in EVTX JSON record"
    );
}

#[test]
fn eval_sigma_rule_against_evtx() {
    let rule_yaml = r#"
title: Test Logon Event
id: test-evtx-logon-001
logsource:
    product: windows
    service: security
detection:
    selection:
        Event.System.EventID: 4624
    condition: selection
level: medium
"#;

    let collection = parse_sigma_yaml(rule_yaml).unwrap();
    let mut engine = Engine::new();
    engine.add_collection(&collection).unwrap();

    let mut reader = EvtxFileReader::open(FIXTURE).expect("failed to open fixture");
    let mut match_count = 0usize;
    let mut record_count = 0usize;

    for record in reader.records() {
        record_count += 1;
        let value = match record {
            Ok(v) => v,
            Err(_) => continue,
        };
        let event = JsonEvent::borrow(&value);
        match_count += engine.evaluate(&event).len();
    }

    assert!(record_count > 0, "expected records from fixture");
    assert!(
        match_count > 0,
        "expected at least one EventID 4624 match in security.evtx ({record_count} records scanned)"
    );
}
