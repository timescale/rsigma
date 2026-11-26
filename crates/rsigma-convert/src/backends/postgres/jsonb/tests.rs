use rsigma_eval::pipeline::state::PipelineState;
use rsigma_parser::parse_sigma_yaml;

use super::super::tests::{convert, convert_with, ipv4_in};
use super::*;
use crate::backend::Backend;

// --- JSONB field access ---

#[test]
fn test_jsonb_field_access() {
    let mut backend = PostgresBackend::new();
    backend.json_field = Some("metadata".to_string());
    let queries = convert_with(
        r#"
title: Test
logsource:
    category: test
detection:
    selection:
        CommandLine: whoami
    condition: selection
"#,
        &backend,
    );
    assert_eq!(
        queries,
        vec!["SELECT * FROM security_events WHERE metadata->>'CommandLine' ILIKE 'whoami'"]
    );
}

#[test]
fn test_jsonb_cidr() {
    let mut backend = PostgresBackend::new();
    backend.json_field = Some("metadata".to_string());
    let queries = convert_with(
        r#"
title: Test
logsource:
    category: test
detection:
    selection:
        SourceIP|cidr: '10.0.0.0/8'
    condition: selection
"#,
        &backend,
    );
    assert_eq!(
        queries,
        vec![format!(
            "SELECT * FROM security_events WHERE {}",
            ipv4_in("metadata->>'SourceIP'", "10.0.0.0/8", false)
        )]
    );
}

#[test]
fn test_jsonb_nested_field_access() {
    let mut backend = PostgresBackend::new();
    backend.json_field = Some("data".to_string());
    let queries = convert_with(
        r#"
title: Test
logsource:
    category: test
detection:
    selection:
        securityContext.isProxy: 'true'
    condition: selection
"#,
        &backend,
    );
    assert_eq!(
        queries,
        vec![
            "SELECT * FROM security_events WHERE data->'securityContext'->>'isProxy' ILIKE 'true'"
        ]
    );
}

#[test]
fn test_jsonb_deeply_nested_field() {
    let mut backend = PostgresBackend::new();
    backend.json_field = Some("data".to_string());
    let queries = convert_with(
        r#"
title: Test
logsource:
    category: test
detection:
    selection:
        a.b.c.d: val
    condition: selection
"#,
        &backend,
    );
    assert_eq!(
        queries,
        vec!["SELECT * FROM security_events WHERE data->'a'->'b'->'c'->>'d' ILIKE 'val'"]
    );
}

#[test]
fn test_jsonb_nested_field_exists() {
    let mut backend = PostgresBackend::new();
    backend.json_field = Some("data".to_string());
    let queries = convert_with(
        r#"
title: Test
logsource:
    category: test
detection:
    selection:
        securityContext.isProxy|exists: true
    condition: selection
"#,
        &backend,
    );
    assert_eq!(
        queries,
        vec!["SELECT * FROM security_events WHERE data->'securityContext'->'isProxy' IS NOT NULL"]
    );
}

#[test]
fn test_jsonb_numeric_values_cast_numeric_text() {
    let queries = convert_json(
        r#"
title: Test
logsource:
    category: test
detection:
    pid:
        ProcessId: 4
    port:
        Port|gt: 1000
    condition: pid and port
"#,
    );
    let num = |f: &str| format!("(CASE WHEN {f} ~ '{NUMERIC_TEXT}' THEN ({f})::numeric END)");
    assert_eq!(
        queries,
        vec![format!(
            "SELECT * FROM security_events WHERE {} = 4 AND {} > 1000",
            num("data->>'ProcessId'"),
            num("data->>'Port'")
        )]
    );
}

const NUMERIC_TEXT: &str =
    r"^[-+]?([0-9]{1,100}\.?[0-9]{0,100}|\.[0-9]{1,100})([eE][-+]?[0-9]{1,3})?$";

#[test]
fn test_jsonb_scalar_array_elements_compare_as_text() {
    let queries = convert_json(
        r#"
sigma-version: 3
title: Test
logsource:
    category: test
detection:
    selection:
        ports[any]: 4444
        flags[any]: true
    condition: selection
"#,
    );
    assert_eq!(
        queries,
        vec![format!(
            "SELECT * FROM security_events WHERE \
             (jsonb_typeof(data->'ports') = 'array' AND EXISTS (SELECT 1 FROM jsonb_array_elements_text(data->'ports') AS __sigma_e0 \
             WHERE (CASE WHEN __sigma_e0 ~ '{NUMERIC_TEXT}' THEN (__sigma_e0)::numeric END) = 4444)) AND \
             (jsonb_typeof(data->'flags') = 'array' AND EXISTS (SELECT 1 FROM jsonb_array_elements_text(data->'flags') AS __sigma_e1 \
             WHERE __sigma_e1 ILIKE 'true'))"
        )]
    );
}

#[test]
fn test_caseless_equality_uses_eq() {
    let queries = convert(
        r#"
title: Test
logsource:
    category: test
detection:
    selection:
        EventID: '4624'
        SourceIp: '10.0.0.1'
        User: 'admin'
    condition: selection
"#,
    );
    assert_eq!(
        queries,
        vec![
            r#"SELECT * FROM security_events WHERE "EventID" = '4624' AND "SourceIp" = '10.0.0.1' AND "User" ILIKE 'admin'"#
        ]
    );
}

#[test]
fn test_jsonb_bool_compares_text() {
    let queries = convert_json(
        r#"
title: Test
logsource:
    category: test
detection:
    selection:
        Elevated: true
    condition: selection
"#,
    );
    assert_eq!(
        queries,
        vec!["SELECT * FROM security_events WHERE data->>'Elevated' ILIKE 'true'"]
    );
}

#[test]
fn test_columns_keep_typed_comparisons() {
    let queries = convert(
        r#"
title: Test
logsource:
    category: test
detection:
    selection:
        ProcessId|gte: 4
        Elevated: false
    condition: selection
"#,
    );
    assert_eq!(
        queries,
        vec![r#"SELECT * FROM security_events WHERE "ProcessId" >= 4 AND "Elevated" = false"#]
    );
}

#[test]
fn test_jsonb_nested_field_cidr() {
    let mut backend = PostgresBackend::new();
    backend.json_field = Some("data".to_string());
    let queries = convert_with(
        r#"
title: Test
logsource:
    category: test
detection:
    selection:
        client.ipAddress|cidr: '10.0.0.0/8'
    condition: selection
"#,
        &backend,
    );
    assert_eq!(
        queries,
        vec![format!(
            "SELECT * FROM security_events WHERE {}",
            ipv4_in("data->'client'->>'ipAddress'", "10.0.0.0/8", false)
        )]
    );
}

#[test]
fn test_jsonb_nested_field_regex() {
    let mut backend = PostgresBackend::new();
    backend.json_field = Some("data".to_string());
    let queries = convert_with(
        r#"
title: Test
logsource:
    category: test
detection:
    selection:
        actor.displayName|re: '.*admin.*'
    condition: selection
"#,
        &backend,
    );
    assert_eq!(
        queries,
        vec!["SELECT * FROM security_events WHERE data->'actor'->>'displayName' ~ '.*admin.*'"]
    );
}

#[test]
fn test_jsonb_flat_field_unchanged() {
    let mut backend = PostgresBackend::new();
    backend.json_field = Some("data".to_string());
    let queries = convert_with(
        r#"
title: Test
logsource:
    category: test
detection:
    selection:
        eventType: user.session.start
    condition: selection
"#,
        &backend,
    );
    assert_eq!(
        queries,
        vec!["SELECT * FROM security_events WHERE data->>'eventType' ILIKE 'user.session.start'"]
    );
}

// --- Array object-scope matching ---

fn convert_json(yaml: &str) -> Vec<String> {
    let mut backend = PostgresBackend::new();
    backend.json_field = Some("data".to_string());
    convert_with(yaml, &backend)
}

#[test]
fn array_any_object_scope_emits_exists() {
    let queries = convert_json(
        r#"
title: T
sigma-version: 3
logsource: { category: test }
detection:
    selection:
        connections[any]:
            protocol: 'TCP'
            ip|cidr: '123.1.0.0/16'
    condition: selection
"#,
    );
    assert_eq!(
        queries,
        vec![format!(
            "SELECT * FROM security_events WHERE \
                 (jsonb_typeof(data->'connections') = 'array' AND EXISTS \
                 (SELECT 1 FROM jsonb_array_elements(data->'connections') AS __sigma_e0 \
                 WHERE __sigma_e0->>'protocol' ILIKE 'TCP' AND {}))",
            ipv4_in("__sigma_e0->>'ip'", "123.1.0.0/16", false)
        )]
    );
}

#[test]
fn array_all_object_scope_emits_not_exists_with_nonempty_guard() {
    let queries = convert_json(
        r#"
title: T
sigma-version: 3
logsource: { category: test }
detection:
    selection:
        connections[all]:
            protocol: 'TCP'
    condition: selection
"#,
    );
    let q = &queries[0];
    assert!(
        q.contains("jsonb_array_length(data->'connections') > 0"),
        "{q}"
    );
    assert!(
        q.contains(
            "NOT EXISTS (SELECT 1 FROM jsonb_array_elements(data->'connections') AS __sigma_e0 \
             WHERE (__sigma_e0->>'protocol' ILIKE 'TCP') IS NOT TRUE)"
        ),
        "{q}"
    );
}

#[test]
fn array_all_or_empty_object_scope_drops_nonempty_guard() {
    let queries = convert_json(
        r#"
title: T
sigma-version: 3
logsource: { category: test }
detection:
    selection:
        connections[all_or_empty]:
            protocol: 'TCP'
    condition: selection
"#,
    );
    // No jsonb_array_length(...) > 0 guard (that is the `all`-only difference);
    // an empty/missing array matches via the CASE ELSE branch.
    assert_eq!(
        queries,
        vec![
            "SELECT * FROM security_events WHERE \
             (CASE WHEN jsonb_typeof(data->'connections') = 'array' \
             THEN NOT EXISTS (SELECT 1 FROM jsonb_array_elements(data->'connections') AS __sigma_e0 \
             WHERE (__sigma_e0->>'protocol' ILIKE 'TCP') IS NOT TRUE) \
             ELSE data->'connections' IS NULL OR jsonb_typeof(data->'connections') = 'null' END)"
        ]
    );
    assert!(!queries[0].contains("jsonb_array_length"), "{}", queries[0]);
}

#[test]
fn array_extended_block_lowers_boolean_inner_predicate() {
    let queries = convert_json(
        r#"
title: T
sigma-version: 3
logsource: { category: test }
detection:
    selection:
        connections[any]:
            condition: in_cidr and not is_tcp
            in_cidr:
                ip|cidr: '123.1.0.0/16'
            is_tcp:
                protocol: 'TCP'
    condition: selection
"#,
    );
    let q = &queries[0];
    // Same EXISTS primitive as the basic block, with a richer inner predicate.
    assert!(
        q.contains("EXISTS (SELECT 1 FROM jsonb_array_elements(data->'connections') AS __sigma_e0"),
        "{q}"
    );
    assert!(
        q.contains(&ipv4_in("__sigma_e0->>'ip'", "123.1.0.0/16", false)),
        "{q}"
    );
    // The per-element negation lowers to IS NOT TRUE inside the element scope.
    assert!(
        q.contains("(__sigma_e0->>'protocol' ILIKE 'TCP') IS NOT TRUE"),
        "{q}"
    );
    assert!(q.contains(" AND "), "{q}");
}

#[test]
fn array_none_object_scope_emits_guarded_not_exists() {
    let queries = convert_json(
        r#"
title: T
sigma-version: 3
logsource: { category: test }
detection:
    selection:
        containers[none]:
            privileged: 'true'
    condition: selection
"#,
    );
    // `none` must match an empty/missing array, so it lowers to a CASE that
    // only runs jsonb_array_elements on an actual array and treats a
    // missing/null value as a match.
    assert_eq!(
        queries,
        vec![
            "SELECT * FROM security_events WHERE \
             (CASE WHEN jsonb_typeof(data->'containers') = 'array' \
             THEN NOT EXISTS (SELECT 1 FROM jsonb_array_elements(data->'containers') AS __sigma_e0 \
             WHERE __sigma_e0->>'privileged' ILIKE 'true') \
             ELSE data->'containers' IS NULL OR jsonb_typeof(data->'containers') = 'null' END)"
        ]
    );
}

#[test]
fn array_scalar_member_uses_elements_text() {
    let queries = convert_json(
        r#"
title: T
sigma-version: 3
logsource: { category: test }
detection:
    selection:
        tags[all]|startswith: '123.'
    condition: selection
"#,
    );
    let q = &queries[0];
    assert!(
        q.contains("jsonb_array_elements_text(data->'tags') AS __sigma_e0"),
        "{q}"
    );
    assert!(q.contains("__sigma_e0 ILIKE '123.%'"), "{q}");
    assert!(q.contains("NOT EXISTS"), "{q}");
}

#[test]
fn array_nested_quantifiers_use_distinct_aliases() {
    let queries = convert_json(
        r#"
title: T
sigma-version: 3
logsource: { category: test }
detection:
    selection:
        rules[any]:
            type: 'allow'
            ip[all]|startswith: '123.1.1'
    condition: selection
"#,
    );
    let q = &queries[0];
    // Outer array over rules.
    assert!(
        q.contains("jsonb_array_elements(data->'rules') AS __sigma_e0"),
        "{q}"
    );
    assert!(q.contains("__sigma_e0->>'type' ILIKE 'allow'"), "{q}");
    // Inner array over each rule's ip, with a distinct alias.
    assert!(
        q.contains("jsonb_array_elements_text(__sigma_e0->'ip') AS __sigma_e1"),
        "{q}"
    );
    assert!(q.contains("__sigma_e1 ILIKE '123.1.1%'"), "{q}");
}

#[test]
fn array_mixed_map_emits_and() {
    let queries = convert_json(
        r#"
title: T
sigma-version: 3
logsource: { category: test }
detection:
    selection:
        eventName: 'AuthorizeSecurityGroupIngress'
        ipPermissions[any]:
            ipRanges: '0.0.0.0/0'
    condition: selection
"#,
    );
    let q = &queries[0];
    assert!(
        q.contains("data->>'eventName' ILIKE 'AuthorizeSecurityGroupIngress'"),
        "{q}"
    );
    assert!(
        q.contains("EXISTS (SELECT 1 FROM jsonb_array_elements(data->'ipPermissions')"),
        "{q}"
    );
    assert!(q.contains(" AND "), "{q}");
}

#[test]
fn array_positional_index_scalar_sql() {
    let queries = convert_json(
        r#"
title: T
sigma-version: 3
logsource: { category: test }
detection:
    selection:
        args[0]|endswith: '.exe'
        args[1]: '-enc'
    condition: selection
"#,
    );
    let q = &queries[0];
    assert!(q.contains("data->'args'->>0 ILIKE '%.exe'"), "{q}");
    assert!(q.contains("data->'args'->>1 ILIKE '-enc'"), "{q}");
}

#[test]
fn array_negative_index_sql() {
    let queries = convert_json(
        r#"
title: T
sigma-version: 3
logsource: { category: test }
detection:
    selection:
        args[-1]: '-enc'
    condition: selection
"#,
    );
    // PostgreSQL JSONB supports negative subscripts (-1 is the last element).
    let q = &queries[0];
    assert!(q.contains("data->'args'->>-1 ILIKE '-enc'"), "{q}");
}

#[test]
fn array_positional_index_dotted_sql() {
    let queries = convert_json(
        r#"
title: T
sigma-version: 3
logsource: { category: test }
detection:
    selection:
        connections[0].ip|cidr: '10.0.0.0/8'
    condition: selection
"#,
    );
    assert_eq!(
        queries,
        vec![format!(
            "SELECT * FROM security_events WHERE {}",
            ipv4_in("data->'connections'->0->>'ip'", "10.0.0.0/8", false)
        )]
    );
}

#[test]
fn array_positional_index_unsupported_in_flat_column_mode() {
    // Flat-column mode has no JSONB array; a positional index must fail loudly
    // rather than emit a literal field reference.
    let backend = PostgresBackend::new();
    let collection = parse_sigma_yaml(
        r#"
title: T
sigma-version: 3
logsource: { category: test }
detection:
    selection:
        args[0]: 'cmd.exe'
    condition: selection
"#,
    )
    .unwrap();
    let err = backend.convert_rule(&collection.rules[0], "default", &PipelineState::default());
    assert!(matches!(err, Err(ConvertError::UnsupportedArrayMatching)));
}

#[test]
fn array_unsupported_without_jsonb_mode() {
    // Flat-column mode has no JSONB array to unnest.
    let backend = PostgresBackend::new();
    let collection = parse_sigma_yaml(
        r#"
title: T
sigma-version: 3
logsource: { category: test }
detection:
    selection:
        connections[any]:
            protocol: 'TCP'
    condition: selection
"#,
    )
    .unwrap();
    let err = backend.convert_rule(&collection.rules[0], "default", &PipelineState::default());
    assert!(matches!(err, Err(ConvertError::UnsupportedArrayMatching)));
}

#[test]
fn array_object_body_with_a_field_less_item_is_unsupported() {
    // The field-less item matches the element itself, which per-field SQL
    // over the element object cannot express.
    let mut backend = PostgresBackend::new();
    backend.json_field = Some("data".to_string());
    let collection = parse_sigma_yaml(
        r#"
title: T
sigma-version: 3
logsource: { category: test }
detection:
    selection:
        items[any]:
            name: 'x'
            '|contains': 'y'
    condition: selection
"#,
    )
    .unwrap();
    let err = backend.convert_rule(&collection.rules[0], "default", &PipelineState::default());
    assert!(matches!(err, Err(ConvertError::UnsupportedArrayMatching)));
}

// --- Field path parsing ---

#[test]
fn field_ops_mix_keys_and_indexes() {
    assert_eq!(
        parse_field_ops("process.args[0][-1].name").unwrap(),
        vec![
            FieldOp::Key("process".into()),
            FieldOp::Key("args".into()),
            FieldOp::Index(0),
            FieldOp::Index(-1),
            FieldOp::Key("name".into()),
        ]
    );
}

#[test]
fn field_ops_accept_a_leading_index() {
    assert_eq!(parse_field_ops("[2]").unwrap(), vec![FieldOp::Index(2)]);
}

#[test]
fn jsonb_path_extracts_text_only_on_the_last_hop() {
    assert_eq!(
        jsonb_path("data", "args[-1]", true).unwrap(),
        "data->'args'->>-1"
    );
    assert_eq!(
        jsonb_path("data", "args[-1]", false).unwrap(),
        "data->'args'->-1"
    );
    assert_eq!(jsonb_path("data", "a.b", true).unwrap(), "data->'a'->>'b'");
}

#[test]
fn field_ops_reject_malformed_brackets() {
    for field in [
        "args[",
        "args[0",
        "args[]",
        "args[x]",
        "args[0]x",
        "args[0]]",
        "args[1.5]",
    ] {
        assert!(
            matches!(
                parse_field_ops(field),
                Err(ConvertError::InvalidIdentifier(_))
            ),
            "{field} should be rejected"
        );
    }
}

#[test]
fn field_ops_reject_keys_that_are_not_identifiers() {
    for field in ["a]", "a b", "a'b", "1a", "a.b-c"] {
        assert!(
            matches!(
                parse_field_ops(field),
                Err(ConvertError::InvalidIdentifier(_))
            ),
            "{field} should be rejected"
        );
    }
}

#[test]
fn field_ops_reject_an_empty_path() {
    for field in ["", ".", ".."] {
        assert!(
            matches!(
                parse_field_ops(field),
                Err(ConvertError::InvalidIdentifier(_))
            ),
            "{field:?} should be rejected"
        );
    }
}
