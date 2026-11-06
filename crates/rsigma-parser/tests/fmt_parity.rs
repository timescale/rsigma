//! Emitter parity tests for the Sigma YAML formatter.
//!
//! The canonical layout the formatter produces must be a fixed point of the
//! emitter. Every golden output and every detection shape below is parsed,
//! emitted with `emit_rule_yaml`, and then formatted again.

use std::fs;
use std::path::Path;

use rsigma_parser::{emit_rule_yaml, format_yaml, parse_sigma_yaml};

fn assert_emitted_output_is_canonical(label: &str, source: &str) {
    let collection = parse_sigma_yaml(source)
        .unwrap_or_else(|error| panic!("parsing '{label}' failed: {error}"));
    assert!(
        collection
            .diagnostics
            .iter()
            .all(|diagnostic| !diagnostic.is_error()),
        "'{label}' has parser errors: {:#?}",
        collection.diagnostics
    );
    // The emitter writes detection rules only, so goldens that hold just
    // correlations or filters have nothing to compare here.
    if collection.rules.is_empty() {
        return;
    }
    for (index, rule) in collection.rules.iter().enumerate() {
        let emitted = emit_rule_yaml(rule);
        let outcome = format_yaml(&emitted).unwrap_or_else(|error| {
            panic!("formatting emitted '{label}' rule {index} failed: {error}")
        });
        assert!(
            !outcome.changed,
            "'{label}' rule {index} emitted text is not canonical:\n--- emitted ---\n{emitted}\n--- formatted ---\n{}",
            outcome.formatted
        );
        assert_eq!(outcome.formatted, emitted);
    }
}

#[test]
fn golden_outputs_are_canonical() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fmt");
    let mut entries: Vec<_> = fs::read_dir(&base)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", base.display()))
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "yml"))
        .filter(|path| {
            path.file_name()
                .is_some_and(|name| name.to_string_lossy().ends_with(".out.yml"))
        })
        .collect();
    entries.sort();
    assert!(!entries.is_empty(), "no golden outputs found");
    for path in entries {
        let source = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        let label = path.file_name().unwrap().to_string_lossy();
        assert_emitted_output_is_canonical(&label, &source);
    }
}

const INLINE_RULES: &[(&str, &str)] = &[
    (
        "all_fields",
        "title: All Fields
id: 00000000-0000-0000-0000-000000000010
name: all-fields
status: test
description: Covers every root field
references:
    - https://example.com/all
author: Test Author
date: 2024-01-01
modified: 2024-02-01
related:
    - id: 00000000-0000-0000-0000-000000000011
      type: derived
tags:
    - attack.discovery
sigma-version: 2
logsource:
    category: process_creation
    product: windows
    service: sysmon
    definition: Definition text
detection:
    selection:
        Field: value
    condition: selection
fields:
    - Image
falsepositives:
    - Unknown
level: low
scope:
    - process
license: MIT
taxonomy:
    - attack
rsigma.window: 5m
rsigma.gap: 1m
rsigma.timestamp_field: '@timestamp'
rsigma.suppress: true
rsigma.risk_score: 50
",
    ),
    (
        "all_of",
        "title: All Of
logsource:
    category: test
detection:
    selection:
        Alpha: one
        Beta: two
    condition: selection
",
    ),
    (
        "any_of",
        "title: Any Of
logsource:
    category: test
detection:
    selection:
        - Alpha: one
        - Beta: two
    condition: selection
",
    ),
    (
        "keywords",
        "title: Keywords
logsource:
    category: test
detection:
    keywords:
        - foo
        - bar
    condition: keywords
",
    ),
    (
        "array_match",
        "title: Array Match
sigma-version: 3
logsource:
    category: test
detection:
    selection:
        connections[any]:
            protocol: TCP
            ip: 10.0.0.1
            condition: protocol and ip
    condition: selection
",
    ),
    (
        "modifiers",
        "title: Modifiers
logsource:
    category: test
detection:
    selection:
        CommandLine|re: 'foo.*'
        SourceIp|cidr: 10.0.0.0/8
        Field|expand: '%var%'
        Multi: |-
            one
            two
    condition: selection
",
    ),
    (
        "condition_expression",
        "title: Condition Expression
logsource:
    category: test
detection:
    selection_a:
        Alpha: one
    selection_b:
        Beta: two
    condition: selection_a and not selection_b
",
    ),
    (
        "multi_line_values",
        "title: Multi Line Values
logsource:
    category: test
detection:
    selection:
        Literal: |
            one
            two
        Folded: >
            one
            two
    condition: selection
",
    ),
];

#[test]
fn inline_rules_are_canonical_after_emit() {
    for (label, source) in INLINE_RULES {
        assert_emitted_output_is_canonical(label, source);
    }
}
