//! End-to-end tests for the gated match-detail enrichment.
//!
//! Exercises `Engine::set_match_detail` across `Off` / `Summary` / `Full`,
//! pinning the three behaviors that motivated the feature:
//!
//! 1. `Off` is byte-for-byte the historical shape (field + value only, no
//!    keyword or absence entries).
//! 2. `Summary` attaches the selection, matcher kind, and case sensitivity,
//!    and reports the previously dropped keyword match.
//! 3. `Full` additionally records the matched pattern.

use rsigma_eval::event::JsonEvent;
use rsigma_eval::{Engine, MatchDetailLevel, MatcherKind};
use rsigma_parser::parse_sigma_yaml;
use serde_json::json;

const RULE: &str = r#"
title: PS Encoded
id: ps-enc
logsource:
    product: windows
    category: process_creation
detection:
    selection_img:
        Image|endswith: \powershell.exe
    selection_args:
        CommandLine|contains: -enc
    keywords:
        - FromBase64String
    condition: selection_img and selection_args and keywords
level: high
"#;

fn engine_at(level: MatchDetailLevel) -> Engine {
    let collection = parse_sigma_yaml(RULE).unwrap();
    let mut engine = Engine::new();
    engine.set_match_detail(level);
    engine.add_collection(&collection).unwrap();
    engine
}

fn matching_event() -> serde_json::Value {
    json!({
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell -nop -enc ZWNobwo= ; FromBase64String(x)"
    })
}

#[test]
fn off_level_preserves_historical_shape() {
    let engine = engine_at(MatchDetailLevel::Off);
    let ev = matching_event();
    let results = engine.evaluate(&JsonEvent::borrow(&ev));
    assert_eq!(results.len(), 1);

    let det = results[0].as_detection().unwrap();
    // Only the two field selections contribute; the keyword selection does
    // not, matching pre-enrichment behavior.
    assert_eq!(det.matched_fields.len(), 2);
    for fm in &det.matched_fields {
        assert!(fm.selection.is_none());
        assert!(fm.matcher.is_none());
        assert!(fm.pattern.is_none());
        assert!(fm.case_sensitive.is_none());
        assert!(!fm.negated);
    }
    let fields: Vec<&str> = det
        .matched_fields
        .iter()
        .map(|f| f.field.as_str())
        .collect();
    assert!(fields.contains(&"Image"));
    assert!(fields.contains(&"CommandLine"));
}

#[test]
fn summary_level_adds_descriptor_and_keyword_entry() {
    let engine = engine_at(MatchDetailLevel::Summary);
    let ev = matching_event();
    let results = engine.evaluate(&JsonEvent::borrow(&ev));
    assert_eq!(results.len(), 1);
    let det = results[0].as_detection().unwrap();

    let cmd = det
        .matched_fields
        .iter()
        .find(|f| f.field == "CommandLine")
        .expect("CommandLine match present");
    assert_eq!(cmd.selection.as_deref(), Some("selection_args"));
    assert_eq!(cmd.matcher, Some(MatcherKind::Contains));
    assert_eq!(cmd.case_sensitive, Some(false));
    // Summary withholds the pattern.
    assert!(cmd.pattern.is_none());

    // The keyword match, dropped entirely at Off, now appears.
    let kw = det
        .matched_fields
        .iter()
        .find(|f| f.matcher == Some(MatcherKind::Keyword))
        .expect("keyword match present");
    assert_eq!(kw.field, "keyword");
    assert_eq!(kw.selection.as_deref(), Some("keywords"));
}

#[test]
fn full_level_records_pattern() {
    let engine = engine_at(MatchDetailLevel::Full);
    let ev = matching_event();
    let results = engine.evaluate(&JsonEvent::borrow(&ev));
    let det = results[0].as_detection().unwrap();

    let cmd = det
        .matched_fields
        .iter()
        .find(|f| f.field == "CommandLine")
        .expect("CommandLine match present");
    assert_eq!(cmd.pattern.as_deref(), Some("-enc"));

    let img = det
        .matched_fields
        .iter()
        .find(|f| f.field == "Image")
        .expect("Image match present");
    assert_eq!(img.matcher, Some(MatcherKind::EndsWith));
    assert_eq!(img.pattern.as_deref(), Some("\\powershell.exe"));
}

const NULL_RULE: &str = r#"
title: Missing Image
id: missing-image
logsource:
    category: process_creation
detection:
    selection:
        Image: null
    condition: selection
level: low
"#;

#[test]
fn null_on_absent_field_is_gated_by_level() {
    let collection = parse_sigma_yaml(NULL_RULE).unwrap();
    let ev = json!({ "CommandLine": "whoami" });

    // Off: the absence match fires the rule but records no field entry.
    let mut off = Engine::new();
    off.add_collection(&collection).unwrap();
    let off_res = off.evaluate(&JsonEvent::borrow(&ev));
    assert_eq!(off_res.len(), 1);
    assert!(off_res[0].as_detection().unwrap().matched_fields.is_empty());

    // Summary: the absence match is reported with a null value.
    let mut summary = Engine::new();
    summary.set_match_detail(MatchDetailLevel::Summary);
    summary.add_collection(&collection).unwrap();
    let sum_res = summary.evaluate(&JsonEvent::borrow(&ev));
    let det = sum_res[0].as_detection().unwrap();
    assert_eq!(det.matched_fields.len(), 1);
    let fm = &det.matched_fields[0];
    assert_eq!(fm.field, "Image");
    assert!(fm.value.is_null());
    assert_eq!(fm.matcher, Some(MatcherKind::Null));
}
