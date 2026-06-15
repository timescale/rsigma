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
    // Sigma defaults to case-insensitive string matching, and Fibratus's
    // bare `=` is case-sensitive. A literal without wildcards therefore
    // uses `~=`, Fibratus's case-insensitive string-equality operator
    // (matches `cmd.exe` and `CMD.EXE`), which is cheaper than a glob
    // match.
    let q = convert(
        r#"
title: T
detection:
  s:
    ps.name: cmd.exe
  condition: s
"#,
    );
    assert_eq!(q, vec!["ps.name ~= 'cmd.exe'"]);
}

#[test]
fn field_eq_string_cased_modifier_uses_exact_equality() {
    // The `|cased` modifier flips to the case-sensitive exact-equality
    // operator `=` (no wildcards in the value).
    let q = convert(
        r#"
title: T
detection:
  s:
    ps.name|cased: Cmd.exe
  condition: s
"#,
    );
    assert_eq!(q, vec!["ps.name = 'Cmd.exe'"]);
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
        vec!["ps.name ~= 'cmd.exe' and ps.parent.name ~= 'explorer.exe'"]
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
    assert_eq!(q, vec!["(ps.name ~= 'cmd.exe' or ps.name ~= 'pwsh.exe')"]);
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
        vec!["ps.name ~= 'cmd.exe' and not (ps.parent.name ~= 'explorer.exe')"]
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
            "ps.name ~= 'cmd.exe' and (ps.parent.name ~= 'explorer.exe' or ps.parent.name ~= 'services.exe')"
        ]
    );
}

// ---------------------------------------------------------------------
// Multi-value lists
// ---------------------------------------------------------------------

#[test]
fn multi_value_string_eq_collapses_to_iin() {
    // A multi-value OR list of plain literals collapses to a single
    // `iin (...)` clause (case-insensitive IN), the idiomatic Fibratus
    // form, rather than OR'd `~=` comparisons.
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
    assert_eq!(q, vec!["ps.name iin ('cmd.exe', 'pwsh.exe')"]);
}

#[test]
fn multi_value_string_eq_with_wildcards_uses_imatches_list() {
    // When any value carries a glob, the list uses `imatches (...)`
    // so the wildcards are honored.
    let q = convert(
        r#"
title: T
detection:
  s:
    ps.name:
      - '*cmd*'
      - 'power?hell'
  condition: s
"#,
    );
    assert_eq!(q, vec!["ps.name imatches ('*cmd*', 'power?hell')"]);
}

#[test]
fn multi_value_contains_collapses_to_icontains_list() {
    let q = convert(
        r#"
title: T
detection:
  s:
    ps.cmdline|contains:
      - whoami
      - localgroup
  condition: s
"#,
    );
    assert_eq!(q, vec!["ps.cmdline icontains ('whoami', 'localgroup')"]);
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
fn field_eq_null_compares_to_empty_string() {
    // Fibratus has no `null` token; a Sigma `field: null` lowers to an
    // empty-string comparison.
    let q = convert(
        r#"
title: T
detection:
  s:
    ps.username: null
  condition: s
"#,
    );
    assert_eq!(q, vec!["ps.username = ''"]);
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
        vec!["ps.name ~= 'cmd.exe' and not (regex(ps.cmdline, '^safe') = true)"]
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
        vec!["ps.name ~= 'a.exe' and (ps.name ~= 'b.exe' or ps.name ~= 'c.exe')"]
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
// Multi-value |re and |cidr (generic-dispatch OR/AND fold)
// ---------------------------------------------------------------------

#[test]
fn multi_value_re_collapses_to_single_regex_call() {
    // Fibratus's `regex()` filter function takes a variadic pattern
    // list and returns true if any pattern matches, so multi-value
    // `|re` collapses to a single call rather than OR'd separate
    // calls (the idiomatic Fibratus form).
    let q = convert(
        r#"
title: T
detection:
  s:
    ps.cmdline|re:
      - '^safe'
      - '^trusted'
  condition: s
"#,
    );
    assert_eq!(q, vec!["regex(ps.cmdline, '^safe', '^trusted') = true"]);
}

#[test]
fn multi_value_re_with_all_modifier_uses_and() {
    let q = convert(
        r#"
title: T
detection:
  s:
    ps.cmdline|re|all:
      - '\bwhoami\b'
      - '\bnet user\b'
  condition: s
"#,
    );
    assert_eq!(
        q,
        vec![
            r"regex(ps.cmdline, '\\bwhoami\\b') = true and regex(ps.cmdline, '\\bnet user\\b') = true"
        ],
    );
}

#[test]
fn multi_value_cidr_collapses_to_single_call() {
    // `cidr_contains()` accepts a variadic list of CIDR masks and
    // returns true if the address is in any of them, so a multi-value
    // `|cidr` (OR) collapses to one call.
    let q = convert(
        r#"
title: T
detection:
  s:
    net.dip|cidr:
      - '10.0.0.0/8'
      - '172.16.0.0/12'
      - '192.168.0.0/16'
  condition: s
"#,
    );
    assert_eq!(
        q,
        vec!["cidr_contains(net.dip, '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')"],
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
    // Fibratus has no `null`; field presence is expressed against the
    // zero value (`!= false` set, `= false` absent).
    let q = convert(
        r#"
title: T
detection:
  s:
    thread.callstack.is_unbacked|exists: true
  condition: s
"#,
    );
    assert_eq!(q, vec!["thread.callstack.is_unbacked != false"]);
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
    assert_eq!(q, vec!["thread.callstack.is_unbacked = false"]);
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
    assert!(
        doc.contains("condition: >\n  ps.name ~= 'cmd.exe' and ps.parent.name ~= 'explorer.exe'\n")
    );
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
    assert!(out.contains("spawn_process"), "got: {out}");
    // The event predicate is emitted first (the pipeline prepends it)
    // so Fibratus short-circuits on the cheapest discriminator.
    assert!(
        out.starts_with("spawn_process"),
        "event predicate must come first, got: {out}",
    );
    // On a Fibratus 3.0.0 `CreateProcess` event `ps.*` is the created
    // (child) process (Sigma `Image` -> `ps.exe`, Sigma `CommandLine`
    // -> `ps.cmdline`) and the spawning process is `ps.parent.*`. The
    // Sigma source `'\cmd.exe'` parses as the literal `\cmd.exe`;
    // Fibratus single-quoted strings need `\\` for a literal `\`, so
    // the rendered value carries the double-escape.
    assert!(out.contains(r"ps.exe iendswith '\\cmd.exe'"), "got: {out}",);
    assert!(
        out.contains(r"ps.parent.exe iendswith '\\explorer.exe'"),
        "got: {out}"
    );
    assert!(out.contains("ps.cmdline icontains 'whoami'"), "got: {out}",);
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
    // `evt.name: Connect` injected by the pipeline matches the
    // `connect_socket` macro after recognition.
    assert!(out.contains("connect_socket"), "got: {out}");
    assert!(
        out.contains("cidr_contains(net.dip, '10.0.0.0/8')"),
        "got: {out}",
    );
}

#[test]
fn pipeline_file_event_excludes_open_disposition() {
    use rsigma_eval::pipeline::{apply_pipelines_with_state, builtin::resolve_builtin};

    let yaml = r#"
title: File creation
logsource:
  category: file_event
  product: windows
detection:
  selection:
    TargetFilename|endswith: '\evil.exe'
  condition: selection
"#;
    let mut collection = rsigma_parser::parse_sigma_yaml(yaml).unwrap();
    let pipeline = resolve_builtin("fibratus_windows").unwrap().unwrap();
    let backend = FibratusBackend::new();
    let rule = &mut collection.rules[0];
    let state = apply_pipelines_with_state(&[pipeline], rule).unwrap();
    let q = backend.convert_rule(rule, "expr", &state).unwrap();

    let out = &q[0];
    // Sigma file_event is file creation: the `CreateFile` event is led
    // with, the path is renamed, and the OPEN disposition is excluded so
    // it does not fire on plain file access (the `create_file` macro
    // semantics).
    assert!(out.starts_with("evt.name = 'CreateFile'"), "got: {out}");
    assert!(
        out.contains(r"file.path iendswith '\\evil.exe'"),
        "got: {out}"
    );
    assert!(
        out.contains("not (file.operation ~= 'OPEN')"),
        "expected OPEN disposition excluded, got: {out}",
    );
}

#[test]
fn pipeline_routes_file_access_to_open_file_macro() {
    use rsigma_eval::pipeline::{apply_pipelines_with_state, builtin::resolve_builtin};

    let yaml = r#"
title: Crypto wallet access
logsource:
  category: file_access
  product: windows
detection:
  selection:
    FileName|contains: '\AppData\Roaming\Ethereum\keystore\'
  condition: selection
"#;
    let mut collection = rsigma_parser::parse_sigma_yaml(yaml).unwrap();
    let pipeline = resolve_builtin("fibratus_windows").unwrap().unwrap();
    let backend = FibratusBackend::new();
    let rule = &mut collection.rules[0];
    let state = apply_pipelines_with_state(&[pipeline], rule).unwrap();
    let q = backend.convert_rule(rule, "expr", &state).unwrap();

    // Sigma file_access is a file open: the `CreateFile` + `OPEN` +
    // `Success` discriminator triple is injected first, in macro order, so
    // the recognizer collapses it to the `open_file` macro. `FileName`
    // renames to `file.path` and `Image` (absent here) would rename to
    // `ps.exe`.
    let out = &q[0];
    assert!(out.starts_with("open_file"), "got: {out}");
    assert!(
        out.contains(r"file.path icontains '\\AppData\\Roaming\\Ethereum\\keystore\\'"),
        "got: {out}",
    );
}

#[test]
fn pipeline_routes_dns_query_with_dns_namespace() {
    use rsigma_eval::pipeline::{apply_pipelines_with_state, builtin::resolve_builtin};

    let yaml = r#"
title: Suspicious DNS
logsource:
  category: dns_query
  product: windows
detection:
  selection:
    QueryName|endswith: '.evil.test'
  condition: selection
"#;
    let mut collection = rsigma_parser::parse_sigma_yaml(yaml).unwrap();
    let pipeline = resolve_builtin("fibratus_windows").unwrap().unwrap();
    let backend = FibratusBackend::new();
    let rule = &mut collection.rules[0];
    let state = apply_pipelines_with_state(&[pipeline], rule).unwrap();
    let q = backend.convert_rule(rule, "expr", &state).unwrap();

    let out = &q[0];
    // `QueryName` maps to the `dns.name` field (not the invalid
    // `net.dns.*`), and the `QueryDns` event is recognized as the
    // `query_dns` macro and emitted first.
    assert!(out.starts_with("query_dns"), "got: {out}");
    assert!(
        out.contains("dns.name iendswith '.evil.test'"),
        "got: {out}"
    );
}

#[test]
fn pipeline_routes_image_load_with_module_namespace() {
    use rsigma_eval::pipeline::{apply_pipelines_with_state, builtin::resolve_builtin};

    let yaml = r#"
title: Unsigned module load
logsource:
  category: image_load
  product: windows
detection:
  selection:
    ImageLoaded|endswith: '\evil.dll'
  condition: selection
"#;
    let mut collection = rsigma_parser::parse_sigma_yaml(yaml).unwrap();
    let pipeline = resolve_builtin("fibratus_windows").unwrap().unwrap();
    let backend = FibratusBackend::new();
    let rule = &mut collection.rules[0];
    let state = apply_pipelines_with_state(&[pipeline], rule).unwrap();
    let q = backend.convert_rule(rule, "expr", &state).unwrap();

    let out = &q[0];
    // `image.*` is deprecated; `ImageLoaded` maps to `module.path`.
    assert!(
        out.contains(r"module.path iendswith '\\evil.dll'"),
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
    // `evt.name: RegSetValue` is the single-clause `set_value` macro
    // body but the registry status guard is not added by the
    // pipeline, so the standalone clause stays as the raw form. The
    // `evt.name` discriminator uses the exact `=` operator.
    assert!(out.contains("evt.name = 'RegSetValue'"), "got: {out}");
    assert!(
        out.contains(r"registry.path icontains '\\CurrentVersion\\Run\\'"),
        "got: {out}",
    );
}

// ---------------------------------------------------------------------
// Macro recognition (use_macros, default on)
// ---------------------------------------------------------------------

#[test]
fn macros_recognize_spawn_process_via_pipeline() {
    // The fibratus_windows pipeline injects `evt.name: CreateProcess`;
    // the backend then renders it as `evt.name = 'CreateProcess'`,
    // which the macro recognizer must rewrite to `spawn_process`.
    use rsigma_eval::pipeline::{apply_pipelines_with_state, builtin::resolve_builtin};

    let yaml = r#"
title: cmd.exe with whoami
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\cmd.exe'
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
    assert!(
        out.contains("spawn_process"),
        "expected spawn_process, got: {out}"
    );
    assert!(
        !out.contains("evt.name = 'CreateProcess'"),
        "macro should have replaced the raw clause, got: {out}",
    );
}

#[test]
fn macros_disabled_emits_raw_clauses() {
    use std::collections::HashMap;
    let mut opts: HashMap<String, String> = HashMap::new();
    opts.insert("use_macros".to_string(), "false".to_string());
    let backend = FibratusBackend::from_options(&opts);

    use rsigma_eval::pipeline::{apply_pipelines_with_state, builtin::resolve_builtin};
    let yaml = r#"
title: t
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\cmd.exe'
  condition: selection
"#;
    let mut collection = rsigma_parser::parse_sigma_yaml(yaml).unwrap();
    let pipeline = resolve_builtin("fibratus_windows").unwrap().unwrap();
    let rule = &mut collection.rules[0];
    let state = apply_pipelines_with_state(&[pipeline], rule).unwrap();
    let q = backend.convert_rule(rule, "expr", &state).unwrap();
    assert!(
        q[0].contains("evt.name = 'CreateProcess'"),
        "expected raw evt.name clause with use_macros=false, got: {}",
        q[0],
    );
    assert!(!q[0].contains("spawn_process"));
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
