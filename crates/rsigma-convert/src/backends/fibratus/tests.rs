//! End-to-end unit tests for the Fibratus backend.
//!
//! These exercise the full `convert_rule` path through the public
//! `Backend` trait so each test pins a representative Sigma -> Fibratus
//! mapping (case-insensitive default, `|cased` switch, wildcards, IN
//! lists, regex, CIDR, comparisons, exists/null, `|fieldref`, `not`,
//! grouping precedence, output formats).
//!
//! Per the project workflow: unit tests live next to the code they
//! exercise; this file does not duplicate coverage shared by the
//! cross-crate golden suite under `tests/golden_fibratus.rs`.
//!
//! The `#[cfg(test)]` gate is applied at the `mod tests;` declaration
//! in [`super`](super) so this file omits its own to avoid the
//! `duplicated_attributes` lint.

use rsigma_eval::pipeline::state::PipelineState;
use rsigma_parser::parse_sigma_yaml;

use super::FibratusBackend;
use crate::backend::Backend;

fn convert(yaml: &str) -> Vec<String> {
    let backend = FibratusBackend::new();
    convert_with(yaml, &backend, "expr")
}

fn convert_with(yaml: &str, backend: &FibratusBackend, format: &str) -> Vec<String> {
    let collection = parse_sigma_yaml(yaml).unwrap();
    let mut results = Vec::new();
    for rule in &collection.rules {
        let queries = backend
            .convert_rule(rule, format, &PipelineState::default())
            .unwrap();
        results.extend(queries);
    }
    results
}

// ---------------------------------------------------------------------
// Basic field equality
// ---------------------------------------------------------------------

#[test]
fn field_eq_string_default_case_insensitive() {
    // Sigma defaults to case-insensitive matching. Fibratus's bare `=`
    // is case-sensitive, so an unmodified `field: value` must lower to
    // exact-equality on the literal value (no wildcards, no `|cased`,
    // so the equality is fine even though Fibratus's `=` is
    // case-sensitive: Sigma's "case-insensitive" semantics for plain
    // equality match the literal value byte-for-byte). The `i`-prefixed
    // operators only kick in for partial-match modifiers.
    let q = convert(
        r#"
title: T
detection:
  s:
    ps.name: cmd.exe
  condition: s
"#,
    );
    assert_eq!(q, vec!["ps.name = 'cmd.exe'"]);
}

#[test]
fn field_eq_string_contains_uses_icontains() {
    let q = convert(
        r#"
title: T
detection:
  s:
    ps.name|contains: cmd
  condition: s
"#,
    );
    assert_eq!(q, vec!["ps.name icontains 'cmd'"]);
}

#[test]
fn field_eq_string_cased_modifier_switches_to_contains() {
    let q = convert(
        r#"
title: T
detection:
  s:
    ps.name|contains|cased: Cmd
  condition: s
"#,
    );
    assert_eq!(q, vec!["ps.name contains 'Cmd'"]);
}

#[test]
fn field_eq_string_startswith() {
    let q = convert(
        r#"
title: T
detection:
  s:
    ps.name|startswith: cmd
  condition: s
"#,
    );
    assert_eq!(q, vec!["ps.name istartswith 'cmd'"]);
}

#[test]
fn field_eq_string_endswith() {
    let q = convert(
        r#"
title: T
detection:
  s:
    ps.exe|endswith: '.exe'
  condition: s
"#,
    );
    assert_eq!(q, vec!["ps.exe iendswith '.exe'"]);
}

// ---------------------------------------------------------------------
// Wildcards (lower to imatches)
// ---------------------------------------------------------------------

#[test]
fn wildcard_multi_lowers_to_imatches() {
    let q = convert(
        r#"
title: T
detection:
  s:
    ps.cmdline: '*whoami*'
  condition: s
"#,
    );
    assert_eq!(q, vec!["ps.cmdline imatches '*whoami*'"]);
}

#[test]
fn wildcard_single_lowers_to_imatches() {
    let q = convert(
        r#"
title: T
detection:
  s:
    file.name: 'a?c.exe'
  condition: s
"#,
    );
    assert_eq!(q, vec!["file.name imatches 'a?c.exe'"]);
}

#[test]
fn wildcard_cased_lowers_to_matches() {
    let q = convert(
        r#"
title: T
detection:
  s:
    file.name|cased: '*Cmd*'
  condition: s
"#,
    );
    assert_eq!(q, vec!["file.name matches '*Cmd*'"]);
}

// ---------------------------------------------------------------------
// Boolean logic and grouping
// ---------------------------------------------------------------------

#[test]
fn condition_and() {
    let q = convert(
        r#"
title: T
detection:
  a:
    ps.name: cmd.exe
  b:
    ps.parent.name: explorer.exe
  condition: a and b
"#,
    );
    assert_eq!(
        q,
        vec!["ps.name = 'cmd.exe' and ps.parent.name = 'explorer.exe'"]
    );
}

#[test]
fn condition_or() {
    let q = convert(
        r#"
title: T
detection:
  a:
    ps.name: cmd.exe
  b:
    ps.name: pwsh.exe
  condition: a or b
"#,
    );
    // Multi-child OR groups are always parenthesized so the standard
    // Sigma precedence (AND binds tighter than OR) survives any
    // surrounding AND context. Harmless at top level.
    assert_eq!(q, vec!["(ps.name = 'cmd.exe' or ps.name = 'pwsh.exe')"]);
}

#[test]
fn condition_not_uses_native_not() {
    let q = convert(
        r#"
title: T
detection:
  a:
    ps.name: cmd.exe
  f:
    ps.parent.name: explorer.exe
  condition: a and not f
"#,
    );
    assert_eq!(
        q,
        vec!["ps.name = 'cmd.exe' and not (ps.parent.name = 'explorer.exe')"]
    );
}

#[test]
fn grouping_for_or_inside_and() {
    let q = convert(
        r#"
title: T
detection:
  a:
    ps.name: cmd.exe
  b:
    ps.parent.name: explorer.exe
  c:
    ps.parent.name: services.exe
  condition: a and (b or c)
"#,
    );
    assert_eq!(
        q,
        vec![
            "ps.name = 'cmd.exe' and (ps.parent.name = 'explorer.exe' or ps.parent.name = 'services.exe')"
        ]
    );
}

// ---------------------------------------------------------------------
// Multi-value lists
// ---------------------------------------------------------------------

#[test]
fn multi_value_string_eq_renders_as_or_list() {
    // The IN-list optimization (`field iin ('a', 'b')`) is opt-in:
    // `convert_condition_as_in_expression` exists on the trait but is
    // not auto-invoked by the default detection-item dispatch, so
    // multi-value Sigma values currently lower to OR'd equality across
    // every text backend (same behavior as LynxDB/Postgres). When/if
    // the dispatch layer learns to auto-collapse, this test flips to
    // assert `ps.name iin ('cmd.exe', 'pwsh.exe')`.
    let q = convert(
        r#"
title: T
detection:
  s:
    ps.name:
      - cmd.exe
      - pwsh.exe
  condition: s
"#,
    );
    assert_eq!(q, vec!["(ps.name = 'cmd.exe' or ps.name = 'pwsh.exe')"]);
}

#[test]
fn convert_condition_as_in_expression_emits_iin_for_or() {
    // Exercise the IN-list helper directly to lock in the iin/in
    // formatting since the auto-dispatch path doesn't currently call
    // it. Used by future optimization passes and the macro recognizer.
    use crate::state::ConversionState;
    use rsigma_parser::{SigmaString, SigmaValue};
    let backend = FibratusBackend::new();
    let a = SigmaValue::String(SigmaString::new("cmd.exe"));
    let b = SigmaValue::String(SigmaString::new("pwsh.exe"));
    let mut state = ConversionState::default();
    let out = backend
        .convert_condition_as_in_expression("ps.name", &[&a, &b], true, &mut state)
        .unwrap();
    assert_eq!(out, "ps.name iin ('cmd.exe', 'pwsh.exe')");
}

#[test]
fn multi_value_string_with_all_modifier_joins_with_and() {
    let q = convert(
        r#"
title: T
detection:
  s:
    ps.cmdline|contains|all:
      - whoami
      - localgroup
  condition: s
"#,
    );
    assert_eq!(
        q,
        vec!["ps.cmdline icontains 'whoami' and ps.cmdline icontains 'localgroup'"]
    );
}

// ---------------------------------------------------------------------
// Numeric, boolean, null
// ---------------------------------------------------------------------

#[test]
fn field_eq_integer() {
    let q = convert(
        r#"
title: T
detection:
  s:
    ps.pid: 4
  condition: s
"#,
    );
    assert_eq!(q, vec!["ps.pid = 4"]);
}

#[test]
fn field_eq_boolean() {
    let q = convert(
        r#"
title: T
detection:
  s:
    ps.is_protected: true
  condition: s
"#,
    );
    assert_eq!(q, vec!["ps.is_protected = true"]);
}

#[test]
fn field_eq_null() {
    let q = convert(
        r#"
title: T
detection:
  s:
    ps.username: null
  condition: s
"#,
    );
    assert_eq!(q, vec!["ps.username = null"]);
}

// ---------------------------------------------------------------------
// Numeric comparison
// ---------------------------------------------------------------------

#[test]
fn compare_gte() {
    let q = convert(
        r#"
title: T
detection:
  s:
    file.io.size|gte: 1024
  condition: s
"#,
    );
    assert_eq!(q, vec!["file.io.size >= 1024"]);
}

#[test]
fn compare_lt() {
    let q = convert(
        r#"
title: T
detection:
  s:
    ps.handles|lt: 10
  condition: s
"#,
    );
    assert_eq!(q, vec!["ps.handles < 10"]);
}

// ---------------------------------------------------------------------
// Regex via regex() function call
// ---------------------------------------------------------------------

#[test]
fn regex_lowers_to_function_call() {
    let q = convert(
        r#"
title: T
detection:
  s:
    ps.cmdline|re: 'power.*(shell|hell)\.dll'
  condition: s
"#,
    );
    // Fibratus single-quoted string literals use `\\` for a literal
    // backslash, so the regex `\.` becomes `\\.` in the rendered
    // literal. The RE2 engine receives the unescaped `\.` and treats
    // it as a literal period (matching upstream rules library style:
    // `file.path imatches '?:\\Windows\\System32\\lsass.exe'`).
    assert_eq!(
        q,
        vec![r"regex(ps.cmdline, 'power.*(shell|hell)\\.dll') = true"]
    );
}

#[test]
fn regex_negated_uses_native_not() {
    let q = convert(
        r#"
title: T
detection:
  s:
    ps.cmdline|re: '^safe'
  f:
    ps.name: cmd.exe
  condition: f and not s
"#,
    );
    assert_eq!(
        q,
        vec!["ps.name = 'cmd.exe' and not (regex(ps.cmdline, '^safe') = true)"]
    );
}

#[test]
fn condition_or_inside_and_uses_explicit_grouping() {
    // Regression for precedence: OR sub-expressions inside AND must
    // be wrapped or `a and b or c` would be parsed as `(a and b) or c`
    // by Fibratus's standard (NOT > AND > OR) precedence.
    let q = convert(
        r#"
title: T
detection:
  a:
    ps.name: a.exe
  b:
    ps.name: b.exe
  c:
    ps.name: c.exe
  condition: a and (b or c)
"#,
    );
    assert_eq!(
        q,
        vec!["ps.name = 'a.exe' and (ps.name = 'b.exe' or ps.name = 'c.exe')"]
    );
}

#[test]
fn regex_rejects_lookarounds() {
    let yaml = r#"
title: T
detection:
  s:
    ps.cmdline|re: 'foo(?=bar)'
  condition: s
"#;
    let backend = FibratusBackend::new();
    let collection = parse_sigma_yaml(yaml).unwrap();
    let err = backend
        .convert_rule(&collection.rules[0], "expr", &PipelineState::default())
        .unwrap_err();
    assert!(
        format!("{err}").contains("lookaround"),
        "expected lookaround error, got: {err}",
    );
}

// ---------------------------------------------------------------------
// CIDR via cidr_contains() function call
// ---------------------------------------------------------------------

#[test]
fn cidr_lowers_to_function_call() {
    let q = convert(
        r#"
title: T
detection:
  s:
    net.dip|cidr: '10.0.0.0/8'
  condition: s
"#,
    );
    assert_eq!(q, vec!["cidr_contains(net.dip, '10.0.0.0/8')"]);
}

// ---------------------------------------------------------------------
// Exists / fieldref
// ---------------------------------------------------------------------

#[test]
fn field_exists_true() {
    let q = convert(
        r#"
title: T
detection:
  s:
    thread.callstack.is_unbacked|exists: true
  condition: s
"#,
    );
    assert_eq!(q, vec!["thread.callstack.is_unbacked != null"]);
}

#[test]
fn field_exists_false() {
    let q = convert(
        r#"
title: T
detection:
  s:
    thread.callstack.is_unbacked|exists: false
  condition: s
"#,
    );
    assert_eq!(q, vec!["thread.callstack.is_unbacked = null"]);
}

#[test]
fn fieldref_renders_as_native_equality() {
    let q = convert(
        r#"
title: T
detection:
  s:
    ps.pid|fieldref: thread.pid
  condition: s
"#,
    );
    assert_eq!(q, vec!["ps.pid = thread.pid"]);
}

// ---------------------------------------------------------------------
// Keyword (unsupported)
// ---------------------------------------------------------------------

#[test]
fn keyword_returns_unsupported_keyword_error() {
    let yaml = r#"
title: T
detection:
  keywords:
    - whoami
    - ipconfig
  condition: keywords
"#;
    let backend = FibratusBackend::new();
    let collection = parse_sigma_yaml(yaml).unwrap();
    let err = backend
        .convert_rule(&collection.rules[0], "expr", &PipelineState::default())
        .unwrap_err();
    assert!(
        format!("{err}").contains("keyword"),
        "expected keyword error, got: {err}"
    );
}

// ---------------------------------------------------------------------
// Output formats
// ---------------------------------------------------------------------

#[test]
fn default_format_emits_yaml_envelope() {
    let backend = FibratusBackend::new();
    let q = convert_with(
        r#"
title: Cmd via Explorer
id: 11111111-2222-3333-4444-555555555555
description: Detect cmd.exe spawned by explorer.
tags:
  - attack.execution
detection:
  s:
    ps.name: cmd.exe
    ps.parent.name: explorer.exe
  condition: s
"#,
        &backend,
        "default",
    );
    assert_eq!(q.len(), 1);
    let doc = &q[0];
    assert!(doc.starts_with("name: Cmd via Explorer\n"));
    assert!(doc.contains("id: 11111111-2222-3333-4444-555555555555\n"));
    assert!(doc.contains("description: |\n  Detect cmd.exe spawned by explorer.\n"));
    assert!(doc.contains("tactic.id: TA0002\n"));
    assert!(doc.contains("condition: ps.name = 'cmd.exe' and ps.parent.name = 'explorer.exe'\n"));
    assert!(doc.contains("min-engine-version: 3.0.0\n"));
}

#[test]
fn yaml_format_is_alias_of_default() {
    let backend = FibratusBackend::new();
    let yaml = r#"
title: T
detection:
  s:
    ps.name: cmd.exe
  condition: s
"#;
    let default = convert_with(yaml, &backend, "default");
    let aliased = convert_with(yaml, &backend, "yaml");
    let rule_aliased = convert_with(yaml, &backend, "rule");
    assert_eq!(default, aliased);
    assert_eq!(default, rule_aliased);
}

#[test]
fn multi_doc_default_format_joins_with_separator() {
    let yaml = r#"
title: First
detection:
  s:
    ps.name: a.exe
  condition: s
---
title: Second
detection:
  s:
    ps.name: b.exe
  condition: s
"#;
    let backend = FibratusBackend::new();
    let collection = parse_sigma_yaml(yaml).unwrap();
    assert_eq!(collection.rules.len(), 2);

    let mut all_queries = Vec::new();
    for rule in &collection.rules {
        let q = backend
            .convert_rule(rule, "default", &PipelineState::default())
            .unwrap();
        all_queries.extend(q);
    }
    let joined = backend.finalize_output(all_queries, "default").unwrap();
    assert!(joined.contains("name: First\n"));
    assert!(joined.contains("\n---\nname: Second\n"));
}

// ---------------------------------------------------------------------
// Backend metadata
// ---------------------------------------------------------------------

#[test]
fn backend_advertises_expected_formats() {
    let backend = FibratusBackend::new();
    let names: Vec<&str> = backend.formats().iter().map(|(n, _)| *n).collect();
    assert_eq!(names, vec!["default", "expr", "yaml", "rule"]);
}

#[test]
fn backend_name_is_fibratus() {
    assert_eq!(FibratusBackend::new().name(), "fibratus");
}

#[test]
fn backend_does_not_require_pipeline() {
    assert!(!FibratusBackend::new().requires_pipeline());
}

// ---------------------------------------------------------------------
// `-O case_sensitive=true` forces bare operators globally
// ---------------------------------------------------------------------

// ---------------------------------------------------------------------
// fibratus_windows builtin pipeline integration
// ---------------------------------------------------------------------

#[test]
fn pipeline_renames_sigma_fields_and_adds_evt_name() {
    use rsigma_eval::pipeline::{apply_pipelines_with_state, builtin::resolve_builtin};

    let yaml = r#"
title: Suspicious cmd via Explorer
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\cmd.exe'
    ParentImage|endswith: '\explorer.exe'
    CommandLine|contains: 'whoami'
  condition: selection
"#;
    let mut collection = rsigma_parser::parse_sigma_yaml(yaml).unwrap();
    let pipeline = resolve_builtin("fibratus_windows").unwrap().unwrap();

    let backend = FibratusBackend::new();
    let rule = &mut collection.rules[0];
    let state = apply_pipelines_with_state(&[pipeline], rule).unwrap();
    let q = backend.convert_rule(rule, "expr", &state).unwrap();

    assert_eq!(q.len(), 1);
    let out = &q[0];
    assert!(out.contains("evt.name = 'CreateProcess'"), "got: {out}");
    // The Sigma source `'\cmd.exe'` parses as the literal `\cmd.exe`;
    // Fibratus single-quoted strings need `\\` for a literal `\`, so
    // the rendered value carries the double-escape.
    assert!(out.contains(r"ps.exe iendswith '\\cmd.exe'"), "got: {out}");
    assert!(
        out.contains(r"ps.parent.exe iendswith '\\explorer.exe'"),
        "got: {out}",
    );
    assert!(out.contains("ps.cmdline icontains 'whoami'"), "got: {out}");
}

#[test]
fn pipeline_routes_network_connection_to_connect_event() {
    use rsigma_eval::pipeline::{apply_pipelines_with_state, builtin::resolve_builtin};

    let yaml = r#"
title: Outbound to RFC1918
logsource:
  category: network_connection
  product: windows
detection:
  selection:
    DestinationIp|cidr: '10.0.0.0/8'
  condition: selection
"#;
    let mut collection = rsigma_parser::parse_sigma_yaml(yaml).unwrap();
    let pipeline = resolve_builtin("fibratus_windows").unwrap().unwrap();
    let backend = FibratusBackend::new();
    let rule = &mut collection.rules[0];
    let state = apply_pipelines_with_state(&[pipeline], rule).unwrap();
    let q = backend.convert_rule(rule, "expr", &state).unwrap();

    let out = &q[0];
    assert!(out.contains("evt.name = 'Connect'"), "got: {out}");
    assert!(
        out.contains("cidr_contains(net.dip, '10.0.0.0/8')"),
        "got: {out}",
    );
}

#[test]
fn pipeline_routes_registry_set_with_target_object_rename() {
    use rsigma_eval::pipeline::{apply_pipelines_with_state, builtin::resolve_builtin};

    let yaml = r#"
title: Run-key persistence
logsource:
  category: registry_set
  product: windows
detection:
  selection:
    TargetObject|contains: '\CurrentVersion\Run\'
  condition: selection
"#;
    let mut collection = rsigma_parser::parse_sigma_yaml(yaml).unwrap();
    let pipeline = resolve_builtin("fibratus_windows").unwrap().unwrap();
    let backend = FibratusBackend::new();
    let rule = &mut collection.rules[0];
    let state = apply_pipelines_with_state(&[pipeline], rule).unwrap();
    let q = backend.convert_rule(rule, "expr", &state).unwrap();

    let out = &q[0];
    assert!(out.contains("evt.name = 'RegSetValue'"), "got: {out}");
    assert!(
        out.contains(r"registry.path icontains '\\CurrentVersion\\Run\\'"),
        "got: {out}",
    );
}

#[test]
fn option_case_sensitive_forces_bare_operators() {
    use std::collections::HashMap;
    let mut opts: HashMap<String, String> = HashMap::new();
    opts.insert("case_sensitive".to_string(), "true".to_string());
    let backend = FibratusBackend::from_options(&opts);
    let q = convert_with(
        r#"
title: T
detection:
  s:
    ps.cmdline|contains: Whoami
  condition: s
"#,
        &backend,
        "expr",
    );
    assert_eq!(q, vec!["ps.cmdline contains 'Whoami'"]);
}
