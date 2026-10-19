# `rsigma-convert`

Convert Sigma rules into backend-native query strings. A rule is lowered to the intermediate representation (`rsigma-ir`) once, and the `Backend` trait renders from that HIR; ships with PostgreSQL/TimescaleDB, LynxDB, and Fibratus backends, and lets you add your own.

- [docs.rs/rsigma-convert](https://docs.rs/rsigma-convert)
- [README](https://github.com/timescale/rsigma/blob/main/crates/rsigma-convert/README.md)
- [crates.io/crates/rsigma-convert](https://crates.io/crates/rsigma-convert)

## When to use

- Generate SQL for an existing log store: PostgreSQL, TimescaleDB.
- Generate SPL2 for LynxDB.
- Build a custom backend (Elasticsearch DSL, Loki LogQL, ClickHouse SQL, Splunk SPL, KQL, anything that can be expressed as a text query). Implement `Backend` once and reuse the rule-walking machinery.

For event evaluation (running rules against in-memory events), use [`rsigma-eval`](eval.md).

## Install

```toml
[dependencies]
rsigma-parser = "{{ rsigma.version }}"
rsigma-convert = "{{ rsigma.version }}"
```

No features. The crate is pure Rust + `regex`.

## Public surface

| Type | Purpose |
|------|---------|
| `Backend` trait | The plug-in surface. Value leaves consume the faithful HIR (`IrPattern`, `IrStrOp`, `IrNumber`, `RegexFlags`, `CompareOp`) with no parser types; implement one leaf per matcher shape and return the query as a string. |
| `TextQueryConfig` | ~90-field config struct that drives most text-query backends declaratively. Mirrors pySigma's `TextQueryBackend` class variables (precedence, boolean operators, wildcards, string and field quoting, regex and CIDR templates, IN-list optimization, deferred parts, query envelope). |
| `PostgresBackend` | The PostgreSQL/TimescaleDB backend. Output formats: `default`, `view`, `timescaledb`, `continuous_aggregate`, `sliding_window`. |
| `LynxDbBackend` | The LynxDB backend. Output formats: `default`, `minimal`. |
| `FibratusBackend` | The Fibratus backend. Output formats: `default`, `expr`, `yaml`, `rule`. |
| `TextQueryTestBackend` | A backend-neutral text format used by the test suite and useful for debugging how a rule lowers to a generic boolean expression. It renders values, in-lists, and CIDR matches the way pySigma's `TextQueryTestBackend` does, so the two can be compared output for output. `cased` values stay out of in-lists, which pySigma would render case-insensitively, and selections keep name order rather than definition order. {{ added "0.24.0" }} |
| `convert_collection(backend, &SigmaCollection, &[Pipeline], output_format)` | Convert a whole collection, applying pipelines per rule. Returns a `ConversionOutput` with per-rule `queries` and per-rule `errors`. The collection's filters are merged into the rules they target before pipelines run, and each correlation is an `UnsupportedCorrelation` error on a backend without correlation support. {{ added "0.24.0" }} |
| `Backend::convert_rule(rule, output_format, &PipelineState)` | Lower-level single-rule entry point on the trait. |
| `ConversionOutput`, `ConversionResult`, `ConversionState`, `PipelineState` | Collection/result wrappers, the per-condition conversion state (`ConversionState`), and the per-rule pipeline state (`PipelineState` from `rsigma-eval`). |

The full Backend trait method list and the per-backend modifier mapping are in [the crate README](https://github.com/timescale/rsigma/blob/main/crates/rsigma-convert/README.md) and in the [PostgreSQL](../reference/backends/postgres.md) and [LynxDB](../reference/backends/lynxdb.md) backend references.

## Minimum example

```rust
use rsigma_convert::{convert_collection, backends::postgres::PostgresBackend};
use rsigma_parser::parse_sigma_yaml;

let rule_yaml = r#"
title: Whoami
id: 8b1d8c97-5b3a-4d77-9b48-7c5f7c8b1a2a
logsource: { product: windows, category: process_creation }
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
"#;

let collection = parse_sigma_yaml(rule_yaml)?;
let backend = PostgresBackend::new();

let output = convert_collection(&backend, &collection, &[], "default")?;
for result in &output.queries {
    for q in &result.queries {
        println!("-- {}\n{}\n", result.rule_title, q);
    }
}
// -- Whoami
// SELECT * FROM security_events WHERE "CommandLine" ILIKE '%whoami%'
```

## Backend options

`PostgresBackend::from_options(&HashMap<String, String>)` reads the CLI `-O key=value` map. Recognised keys:

| Key | Effect |
|-----|--------|
| `table` | Default table name (default `security_events`). |
| `schema` | PostgreSQL schema. |
| `database` | Connection-level metadata for some output formats. |
| `timestamp_field` | Column name for the timestamp (default `time`). |
| `json_field` | Treat field references as JSONB extraction paths in this column. |

LynxDB has no CLI `-O` options; its only knob is the target index, controlled via pipeline `set_state` with `key: index` (default `main`).

## Writing a custom backend

The smallest viable backend implements `Backend`, returns a `TextQueryConfig`, and lets the trait's default methods do the heavy lifting:

```rust
use rsigma_convert::{Backend, TextQueryConfig, TokenType};

pub struct MyBackend;

static MY_CONFIG: TextQueryConfig = TextQueryConfig {
    precedence: (TokenType::NOT, TokenType::AND, TokenType::OR),
    group_expression: "({expr})",
    token_separator: " ",
    and_token: "AND",
    or_token: "OR",
    not_token: "NOT",
    eq_token: " = ",
    not_eq_token: Some(" <> "),
    // ... 80+ other knobs, see the docs.rs page
    .. TextQueryConfig::PYSIGMA_DEFAULTS
};

impl Backend for MyBackend {
    fn name(&self) -> &str { "my_backend" }

    fn formats(&self) -> &[(&str, &str)] {
        &[("default", "Plain MyBackend query")]
    }

    fn text_query_config(&self) -> Option<&TextQueryConfig> {
        Some(&MY_CONFIG)
    }
}
```

The default `convert_rule` lowers the rule to `IrRule`, walks the resulting `IrDetection` and `IrCondition`, and dispatches into `text_*` helpers (e.g. `text_convert_field_str_ir`, `text_convert_ir_pattern`) that consult the config. Only override the leaves that your backend needs to behave differently from pySigma's `TextQueryBackend` default.

The numeric leaves (`convert_field_eq_num`, `convert_field_compare_op`, `convert_keyword_num`) receive a `rsigma_ir::NumericLiteral` rather than an `f64`, so integers above 2^53 reach the backend exactly. Render it with `to_string()` to get the exact digits. {{ added "0.25.0" }}

See [Adding Backends](../developers/adding-backends.md) for the step-by-step walkthrough, the testing pattern, and how to wire a new backend into `rsigma backend convert` if you also want CLI integration.

## Error handling

`ConvertError` from `thiserror`. Variants include `RuleConversion` (a rule could not be converted with the chosen backend or format), `UnsupportedModifier`, `InvalidIdentifier` (table/schema name failed validation), and `Pipeline` (a pre-conversion pipeline step failed).

## See also

- [Rule Conversion](../guide/rule-conversion.md) for the operator-facing workflow.
- [PostgreSQL backend reference](../reference/backends/postgres.md), [LynxDB backend reference](../reference/backends/lynxdb.md), and [Fibratus backend reference](../reference/backends/fibratus.md).
- [Adding Backends](../developers/adding-backends.md) for the contributor walkthrough.
- [`rsigma-convert` README](https://github.com/timescale/rsigma/blob/main/crates/rsigma-convert/README.md) for the full Backend trait reference.
- [docs.rs/rsigma-convert](https://docs.rs/rsigma-convert).
