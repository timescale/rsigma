//! Custom attributes named after a standard Sigma key or the collection
//! `action` key: the parser keeps and reports them, and every emitter writes
//! them so the document reads back as the same kind with an equal AST.

use rsigma_parser::{
    DiagnosticKind, DiagnosticSeverity, SigmaCollection, emit_correlation_yaml, emit_filter_yaml,
    emit_rule_yaml, is_reserved_attribute_name, parse_sigma_yaml,
};

const RESERVED: &[&str] = &[
    "action",
    "author",
    "correlation",
    "custom_attributes",
    "date",
    "description",
    "detection",
    "falsepositives",
    "fields",
    "filter",
    "generate",
    "id",
    "level",
    "license",
    "logsource",
    "modified",
    "name",
    "references",
    "related",
    "scope",
    "sigma-version",
    "status",
    "tags",
    "taxonomy",
    "title",
];

const RULE: &str = "title: Rule\nid: rule-1\nlogsource:\n    category: test\ndetection:\n    selection:\n        a: b\n    condition: selection\n";
const CORRELATION: &str = "title: Corr\nid: corr-1\ncorrelation:\n    type: event_count\n    rules:\n        - rule-1\n    group-by:\n        - User\n    timespan: 5m\n    condition:\n        gte: 3\n";
const FILTER: &str = "title: Filter\nid: filter-1\nlogsource:\n    category: test\nfilter:\n    rules:\n        - rule-1\n    selection:\n        a: c\n    condition: selection\n";

fn values() -> Vec<yaml_serde::Value> {
    vec![
        yaml_serde::Value::String("reset".into()),
        yaml_serde::from_str("{type: event_count, rules: [x]}").unwrap(),
        yaml_serde::from_str("[a, b]").unwrap(),
        yaml_serde::Value::Bool(true),
    ]
}

fn parse_one(yaml: &str) -> SigmaCollection {
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert!(
        !collection.has_errors(),
        "{yaml}\n{:?}",
        collection.diagnostics
    );
    assert_eq!(collection.len(), 1, "{yaml}");
    collection
}

#[test]
fn every_reserved_name_is_reported_as_reserved() {
    for name in RESERVED {
        assert!(is_reserved_attribute_name(name), "{name}");
    }
    for name in ["rsigma.suppress", "postgres.table", "priority", "Title", ""] {
        assert!(!is_reserved_attribute_name(name), "{name}");
    }
}

#[test]
fn reserved_names_round_trip_through_the_rule_emitter() {
    let base = parse_one(RULE).rules.remove(0);
    for name in RESERVED {
        for value in values() {
            let mut rule = base.clone();
            rule.custom_attributes.insert(name.to_string(), value);
            let emitted = emit_rule_yaml(&rule);
            let reparsed = parse_one(&emitted);
            assert_eq!(reparsed.rules.len(), 1, "{name}:\n{emitted}");
            assert_eq!(reparsed.rules[0], rule, "{name}:\n{emitted}");
        }
    }
}

#[test]
fn reserved_names_round_trip_through_the_correlation_emitter() {
    let base = parse_one(CORRELATION).correlations.remove(0);
    for name in RESERVED {
        for value in values() {
            let mut rule = base.clone();
            rule.custom_attributes.insert(name.to_string(), value);
            let emitted = emit_correlation_yaml(&rule);
            let reparsed = parse_one(&emitted);
            assert_eq!(reparsed.correlations.len(), 1, "{name}:\n{emitted}");
            assert_eq!(reparsed.correlations[0], rule, "{name}:\n{emitted}");
        }
    }
}

#[test]
fn reserved_names_round_trip_through_the_filter_emitter() {
    let base = parse_one(FILTER).filters.remove(0);
    for name in RESERVED {
        for value in values() {
            let mut rule = base.clone();
            rule.custom_attributes.insert(name.to_string(), value);
            let emitted = emit_filter_yaml(&rule);
            let reparsed = parse_one(&emitted);
            assert_eq!(reparsed.filters.len(), 1, "{name}:\n{emitted}");
            assert_eq!(reparsed.filters[0], rule, "{name}:\n{emitted}");
        }
    }
}

#[test]
fn reserved_names_in_the_block_are_kept_with_a_warning() {
    for (base, kind) in [
        (RULE, "rule"),
        (CORRELATION, "correlation"),
        (FILTER, "filter"),
    ] {
        for name in RESERVED {
            let yaml = format!("{base}custom_attributes:\n    {name}: kept\n");
            let collection = parse_sigma_yaml(&yaml).unwrap();
            assert!(
                !collection.has_errors(),
                "{kind} {name}: {:?}",
                collection.diagnostics
            );
            let attrs = match kind {
                "rule" => &collection.rules[0].custom_attributes,
                "correlation" => &collection.correlations[0].custom_attributes,
                _ => &collection.filters[0].custom_attributes,
            };
            assert_eq!(attrs[*name], yaml_serde::Value::String("kept".into()));
            let warning = collection
                .warnings()
                .find(|w| w.kind == DiagnosticKind::CustomAttribute)
                .unwrap_or_else(|| panic!("{kind} {name}: no warning"));
            assert_eq!(warning.severity, DiagnosticSeverity::Warning);
            assert!(warning.message.contains(name), "{}", warning.message);
        }
    }
}

#[test]
fn top_level_keys_of_another_document_kind_are_kept_quietly() {
    let rule = format!("{RULE}generate: true\n");
    let collection = parse_sigma_yaml(&rule).unwrap();
    assert_eq!(
        collection.rules[0].custom_attributes["generate"],
        yaml_serde::Value::Bool(true)
    );
    assert_eq!(collection.warning_count(), 0);

    // A global template's logsource is merged into every document, including
    // a correlation, which keeps it as a custom attribute.
    let global = format!(
        "action: global\nlogsource:\n    product: windows\n---\n{}---\n{CORRELATION}",
        RULE.replace("logsource:\n    category: test\n", "")
    );
    let collection = parse_sigma_yaml(&global).unwrap();
    assert!(!collection.has_errors(), "{:?}", collection.diagnostics);
    assert_eq!(
        collection.warning_count(),
        0,
        "{:?}",
        collection.diagnostics
    );
    assert!(
        collection.correlations[0]
            .custom_attributes
            .contains_key("logsource")
    );
    let emitted = emit_correlation_yaml(&collection.correlations[0]);
    let reparsed = parse_one(&emitted);
    assert_eq!(
        reparsed.correlations[0], collection.correlations[0],
        "{emitted}"
    );
}

#[cfg(feature = "fmt")]
#[test]
fn emitted_reserved_attributes_are_canonical() {
    let mut rule = parse_one(RULE).rules.remove(0);
    for name in RESERVED {
        rule.custom_attributes
            .insert(name.to_string(), yaml_serde::Value::String("x".into()));
    }
    rule.custom_attributes.insert(
        "rsigma.suppress".into(),
        yaml_serde::Value::String("5m".into()),
    );
    let emitted = emit_rule_yaml(&rule);
    let outcome = rsigma_parser::format_yaml(&emitted).unwrap();
    assert!(!outcome.changed, "{emitted}\n---\n{}", outcome.formatted);
}
