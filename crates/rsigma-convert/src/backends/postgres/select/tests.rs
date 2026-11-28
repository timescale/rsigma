use rsigma_eval::pipeline::state::PipelineState;
use rsigma_parser::parse_sigma_yaml;

use super::*;
use crate::backend::Backend;

const FORMATS: &[&str] = &[
    "default",
    "view",
    "timescaledb",
    "continuous_aggregate",
    "sliding_window",
];

fn rule_with_fields(fields: &[&str]) -> rsigma_parser::SigmaRule {
    let mut rule = parse_sigma_yaml(
        "title: T\nid: 00000000-0000-0000-0000-000000000001\nlogsource: {category: test}\ndetection:\n  sel: {action: login}\n  condition: sel\n",
    )
    .unwrap()
    .rules
    .remove(0);
    rule.fields = fields.iter().map(|f| f.to_string()).collect();
    rule
}

fn flat() -> PostgresBackend {
    PostgresBackend::new()
}

fn jsonb() -> PostgresBackend {
    let mut backend = PostgresBackend::new();
    backend.json_field = Some("data".to_string());
    backend
}

fn select(backend: &PostgresBackend, fields: &[&str]) -> String {
    backend
        .convert_rule(
            &rule_with_fields(fields),
            "default",
            &PipelineState::default(),
        )
        .unwrap()
        .remove(0)
}

const HOSTILE: &[&str] = &[
    "Image; DROP TABLE security_events",
    "Image;",
    "Image -- comment",
    "Image--",
    "a--b",
    "count(*) -- x",
    "Image /* x */",
    "Image/**/",
    "/* x */ Image",
    "count(*)/**/",
    "\"Image\"",
    "'Image'",
    "Image AS \"x\"",
    "Image AS 'x'",
    "(SELECT password FROM users)",
    "(SELECT 1)",
    "max((SELECT 1))",
    "count((SELECT 1))",
    "lower(upper(Image))",
    "max(max(Image))",
    "pg_sleep(10)",
    "version()",
    "lower(Image)",
    "current_setting(x)",
    "count()",
    "x count(*)",
    "count(*) x",
    "count(*)x",
    "max(Image) extra",
    "prefix max(Image)",
    "count(*",
    "count*)",
    "count((*)",
    "count(*))",
    "(count(*)",
    "count(Image, CommandLine)",
    "count(Image,CommandLine)",
    "count(DISTINCT Image)",
    "sum(*)",
    "max(*)",
    "Image, CommandLine",
    "Image AS cmd; DROP TABLE x",
    "Image AS cmd -- x",
    "Image AS 1x",
    "Image AS a b",
    "Image AS",
    "Image cmd",
    "count(*) AS c AS d",
    "* AS x",
    "*, Image",
    "Image\nFROM pg_shadow",
    "",
    "   ",
    "Imagé",
    "a\0b",
    "Image = 1",
    "Image || 'x'",
    "Image::text",
    "1Image",
    "Image.",
    "Image-",
    ".Image",
    "a..b",
];

/// Entries only a JSONB column can serve: positional indices.
const FLAT_ONLY_HOSTILE: &[&str] = &["args[0]", "count(args[0])", "a[0]b"];

#[test]
fn hostile_entries_fail_conversion_in_every_format_and_mode() {
    for backend in [flat(), jsonb()] {
        let flat_only = if backend.json_field.is_none() {
            FLAT_ONLY_HOSTILE
        } else {
            &[]
        };
        for entry in HOSTILE.iter().chain(flat_only) {
            let rule = rule_with_fields(&["EventID", entry]);
            for format in FORMATS {
                let err = backend
                    .convert_rule(&rule, format, &PipelineState::default())
                    .unwrap_err();
                assert!(
                    matches!(&err, ConvertError::InvalidSelectField { entry: e, .. } if e == entry),
                    "{entry:?} ({format}, json_field {:?}): {err}",
                    backend.json_field
                );
            }
        }
    }
}

#[test]
fn error_names_the_entry_and_the_reason() {
    let err = flat()
        .convert_rule(
            &rule_with_fields(&["pg_sleep(10)"]),
            "default",
            &PipelineState::default(),
        )
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "invalid `fields` entry \"pg_sleep(10)\": `pg_sleep` is not an allowed function (count, sum, avg, min, max)"
    );
}

#[test]
fn allowed_entries_flat() {
    let backend = flat();
    let cases: &[(&str, &str)] = &[
        ("*", "*"),
        ("count(*)", "count(*)"),
        ("COUNT( * ) as total", "COUNT(*) AS total"),
        ("Count(*) As Total", "Count(*) AS \"Total\""),
        ("max(EventID)", "max(\"EventID\")"),
        ("min(bytes) AS low", "min(bytes) AS low"),
        ("sum(bytes)", "sum(bytes)"),
        ("avg(bytes) AS mean", "avg(bytes) AS mean"),
        ("count(Image)", "count(\"Image\")"),
        ("CommandLine as cmd", "\"CommandLine\" AS cmd"),
        ("CommandLine AS Cmd", "\"CommandLine\" AS \"Cmd\""),
        ("  CommandLine  ", "\"CommandLine\""),
        ("user", "\"user\""),
        ("group", "\"group\""),
        ("order AS o", "\"order\" AS o"),
        ("action AS user", "action AS \"user\""),
        ("max(user)", "max(\"user\")"),
        ("current_user", "\"current_user\""),
        ("c-uri", "\"c-uri\""),
        ("@timestamp", "\"@timestamp\""),
        ("userIdentity.arn", "\"userIdentity.arn\""),
        ("src_ip", "src_ip"),
        ("as", "\"as\""),
        ("time", "time"),
        ("Field$1", "\"Field$1\""),
    ];
    for (entry, expected) in cases {
        assert_eq!(
            select(&backend, &[entry]),
            format!("SELECT {expected} FROM security_events WHERE action ILIKE 'login'"),
            "{entry:?}"
        );
    }
}

#[test]
fn allowed_entries_jsonb() {
    let backend = jsonb();
    let num = |f: &str| {
        format!(
            "(CASE WHEN data->>'{f}' ~ '^[-+]?([0-9]{{1,100}}\\.?[0-9]{{0,100}}|\\.[0-9]{{1,100}})([eE][-+]?[0-9]{{1,3}})?$' \
             THEN (data->>'{f}')::numeric END)"
        )
    };
    let cases: Vec<(&str, String)> = vec![
        ("*", "*".into()),
        ("count(*)", "count(*)".into()),
        ("Image", "data->>'Image' AS \"Image\"".into()),
        ("user", "data->>'user' AS \"user\"".into()),
        ("src_ip", "data->>'src_ip' AS src_ip".into()),
        (
            "userIdentity.arn",
            "data->'userIdentity'->>'arn' AS \"userIdentity.arn\"".into(),
        ),
        ("args[0]", "data->'args'->>0 AS \"args[0]\"".into()),
        ("c-uri", "data->>'c-uri' AS \"c-uri\"".into()),
        ("@timestamp", "data->>'@timestamp' AS \"@timestamp\"".into()),
        ("CommandLine as cmd", "data->>'CommandLine' AS cmd".into()),
        ("max(EventID)", "max(data->>'EventID')".into()),
        ("count(Image) AS n", "count(data->>'Image') AS n".into()),
        ("sum(bytes)", format!("sum({})", num("bytes"))),
        (
            "avg(bytes) AS mean",
            format!("avg({}) AS mean", num("bytes")),
        ),
    ];
    for (entry, expected) in cases {
        assert_eq!(
            select(&backend, &[entry]),
            format!("SELECT {expected} FROM security_events WHERE data->>'action' ILIKE 'login'"),
            "{entry:?}"
        );
    }
}

#[test]
fn jsonb_rejects_fields_outside_path_syntax() {
    for entry in ["a[0]b", "max(a[x])", "a[]", "a[0", "@"] {
        let err = jsonb()
            .convert_rule(
                &rule_with_fields(&[entry]),
                "default",
                &PipelineState::default(),
            )
            .unwrap_err();
        assert!(
            matches!(&err, ConvertError::InvalidSelectField { entry: e, .. } if e == entry),
            "{entry:?}: {err}"
        );
    }
}

#[test]
fn several_entries_keep_their_order() {
    assert_eq!(
        select(&flat(), &["user_id", "count(*) AS n", "CommandLine as cmd"]),
        "SELECT user_id, count(*) AS n, \"CommandLine\" AS cmd FROM security_events \
         WHERE action ILIKE 'login' GROUP BY user_id, \"CommandLine\""
    );
}

fn convert_format(fields: &[&str], format: &str) -> Result<String> {
    flat()
        .convert_rule(&rule_with_fields(fields), format, &PipelineState::default())
        .map(|mut q| q.remove(0))
}

const CAGG: &str = "CREATE MATERIALIZED VIEW sigma_00000000_0000_0000_0000_000000000001 \
                    WITH (timescaledb.continuous) AS ";

#[test]
fn aggregates_group_by_the_bucket_and_the_other_fields() {
    let tail = "FROM security_events WHERE action ILIKE 'login' \
                GROUP BY time_bucket('1 hour', time), \"user\"";
    let select = "SELECT time_bucket('1 hour', time) AS bucket, \"user\", max(\"EventID\")";
    assert_eq!(
        convert_format(&["user", "max(EventID)"], "timescaledb").unwrap(),
        format!("{select} {tail}")
    );
    assert_eq!(
        convert_format(&["user", "max(EventID)"], "continuous_aggregate").unwrap(),
        format!("{CAGG}{select} {tail} WITH NO DATA")
    );
    assert_eq!(
        convert_format(&["count(*)"], "default").unwrap(),
        "SELECT count(*) FROM security_events WHERE action ILIKE 'login'"
    );
    assert_eq!(
        convert_format(&["count(*)"], "timescaledb").unwrap(),
        "SELECT time_bucket('1 hour', time) AS bucket, count(*) FROM security_events \
         WHERE action ILIKE 'login' GROUP BY time_bucket('1 hour', time)"
    );
}

#[test]
fn timescaledb_rows_without_aggregates_are_not_grouped() {
    assert_eq!(
        convert_format(&["user", "CommandLine"], "timescaledb").unwrap(),
        "SELECT time_bucket('1 hour', time) AS bucket, \"user\", \"CommandLine\" \
         FROM security_events WHERE action ILIKE 'login'"
    );
    assert_eq!(
        convert_format(&[], "timescaledb").unwrap(),
        "SELECT time_bucket('1 hour', time) AS bucket, * FROM security_events WHERE action ILIKE 'login'"
    );
}

#[test]
fn a_continuous_aggregate_counts_events_when_fields_do_not_aggregate() {
    assert_eq!(
        convert_format(&["user"], "continuous_aggregate").unwrap(),
        format!(
            "{CAGG}SELECT time_bucket('1 hour', time) AS bucket, \"user\", count(*) AS event_count \
             FROM security_events WHERE action ILIKE 'login' \
             GROUP BY time_bucket('1 hour', time), \"user\" WITH NO DATA"
        )
    );
    assert_eq!(
        convert_format(&[], "continuous_aggregate").unwrap(),
        format!(
            "{CAGG}SELECT time_bucket('1 hour', time) AS bucket, count(*) AS event_count \
             FROM security_events WHERE action ILIKE 'login' \
             GROUP BY time_bucket('1 hour', time) WITH NO DATA"
        )
    );
}

#[test]
fn star_cannot_be_grouped() {
    for (fields, format) in [
        (&["*", "count(*)"][..], "default"),
        (&["count(*)", "*"][..], "timescaledb"),
        (&["*"][..], "continuous_aggregate"),
        (&["user", "*"][..], "continuous_aggregate"),
    ] {
        let err = convert_format(fields, format).unwrap_err();
        assert!(
            matches!(&err, ConvertError::InvalidSelectField { entry, .. } if entry == "*"),
            "{fields:?} {format}: {err}"
        );
    }
    assert_eq!(
        convert_format(&["*", "user"], "view").unwrap(),
        "CREATE OR REPLACE VIEW sigma_00000000_0000_0000_0000_000000000001 AS \
         SELECT *, \"user\" FROM security_events WHERE action ILIKE 'login'"
    );
}

#[test]
fn a_query_expression_template_ignores_the_fields() {
    let mut state = PipelineState::default();
    state.set_state(
        "query_expression_template".to_string(),
        serde_json::json!("SELECT id FROM {table} WHERE {query}"),
    );
    let q = flat()
        .convert_rule(&rule_with_fields(&["pg_sleep(10)"]), "default", &state)
        .unwrap();
    assert_eq!(
        q,
        vec!["SELECT id FROM security_events WHERE action ILIKE 'login'"]
    );
}

// --- Parser ---

#[test]
fn parser_shapes() {
    assert_eq!(parse_select_field("*"), Ok(SelectItem::Star));
    assert_eq!(
        parse_select_field("a AS b"),
        Ok(SelectItem::Field {
            field: "a",
            alias: Some("b")
        })
    );
    assert_eq!(
        parse_select_field("max ( a ) as b"),
        Ok(SelectItem::Call {
            name: "max",
            func: Aggregate::Max,
            arg: Some("a"),
            alias: Some("b"),
        })
    );
    assert_eq!(
        parse_select_field("COUNT(*)"),
        Ok(SelectItem::Call {
            name: "COUNT",
            func: Aggregate::Count,
            arg: None,
            alias: None,
        })
    );
}

#[test]
fn parser_reports_unexpected_characters() {
    assert_eq!(
        parse_select_field("a;b"),
        Err("unexpected character ';'".to_string())
    );
    assert_eq!(
        parse_select_field("a\u{7}"),
        Err("unexpected character '\\u{7}'".to_string())
    );
}
