---
description: "rsigma-convert Rust crate: convert Sigma rules into backend query strings through a shared IR, with PostgreSQL, LynxDB, and Fibratus backends included."
---

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
| `TextQueryTestBackend` | A backend-neutral text format used by the test suite and useful for debugging how a rule lowers to a generic boolean expression. It renders values, in-lists, and CIDR matches the way pySigma's `TextQueryTestBackend` does, so the two can be compared output for output. `cased` values stay out of in-lists, which pySigma would render case-insensitively, and selections keep name order rather than definition order. {{ added "0.24.0" }} A `fieldref` with `startswith`, `endswith`, or `contains` renders as `A=fieldref_startswith(B)`, `A=fieldref_endswith(B)`, or `A=fieldref_contains(B)`, a field-less `contains` value gets `*` on both ends, and regexes escape `bar` as well as `/`, all as in pySigma. {{ added "unreleased" }} |
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

`timestamp_field` and `json_field` must be plain SQL identifiers; conversion fails with `InvalidIdentifier` otherwise. `PostgresBackend::timestamp_column` returns the timestamp column as the backend renders it in SQL, quoted when it is mixed-case or a reserved word. {{ added "unreleased" }}

LynxDB has no CLI `-O` options; its only knob is the target index, controlled via pipeline `set_state` with `key: index` (default `main`).

## Writing a custom backend

A backend implements `Backend`. The required methods are `name`, `formats`, `convert_rule`, the condition combinators (`convert_condition_and`, `convert_condition_or`, `convert_condition_not`), `escape_and_quote_field`, the value leaves (`convert_field_str`, `convert_field_eq_num`, `convert_field_regex`, `convert_keyword_str`, and the rest), `finish_query`, `finalize_query`, and `finalize_output`. The other methods have defaults.

`convert_rule` usually delegates to `condition_ir::convert_rule_via_ir`, which lowers the rule to `IrRule`, walks the resulting `IrDetection` and `IrCondition`, and calls the leaves. A text backend holds a `&'static TextQueryConfig` and implements the leaves with the `text_*` helpers in `rsigma_convert::backend` (e.g. `text_convert_field_str_ir`, `text_convert_ir_pattern`), which render values the way pySigma's `TextQueryBackend` does, and writes its own rendering only where the target differs. `TextQueryConfig` has no `Default` impl, so start from an existing config such as `backends::test::TEXT_QUERY_TEST_CONFIG` and set every field.

A keyword with `cased` goes to `convert_keyword_str_cased` instead of `convert_keyword_str`. The default rejects it with `UnsupportedModifier`, since a full-text search usually ignores case; override it when your backend can match a keyword case-sensitively. {{ added "unreleased" }}

A field-less value with `contains`, such as `'|contains': whoami`, goes to `convert_keyword_contains`. The default renders it as a regular keyword, which already matches a substring; the test backend overrides it to add `*` on both ends, as pySigma does. {{ added "unreleased" }}

`TextQueryConfig` has `field_eq_field_startswith_expression`, `field_eq_field_endswith_expression`, and `field_eq_field_contains_expression` next to `field_eq_field_expression`, for `fieldref` with `startswith`, `endswith`, or `contains`. {{ added "unreleased" }}

A keyword with `base64` or `base64offset` encodes to fragments of a longer base64 string, and each fragment goes to `convert_keyword_substr`. The default renders it as a regular keyword; override it when your keyword search matches whole words only, as PostgreSQL and LynxDB do. {{ added "unreleased" }}

The numeric leaves (`convert_field_eq_num`, `convert_field_compare_op`, `convert_keyword_num`) receive a `rsigma_ir::NumericLiteral` rather than an `f64`, so integers above 2^53 reach the backend exactly. Render it with `to_string()` to get the exact digits. {{ added "0.25.0" }}

`Backend::correlation_source_query` returns the query a correlation embeds for a detection rule it references, which `convert_collection` passes to the correlation in the `_rule_queries` state. The default `None` reuses the rule's first converted query; PostgreSQL returns the rule's `default` query without its `fields` projection. {{ added "unreleased" }}

`render_query_template(template, lookup)` substitutes `{name}` placeholders in a query template in one pass: `lookup` returns the text for a name, or `None` to keep the placeholder as written. Substituted text is never scanned again, so a rule value or title that contains a placeholder stays literal. `text_finish_query` uses it, and a backend with its own `finish_query` should too, rather than calling `str::replace` on a string that already holds the rendered detection. {{ added "0.28.0" }} The built-in backends substitute `{rule.title}` and `{rule.id}` through `rsigma_parser::sanitize_single_line`, so a line break in rule metadata cannot leave a comment or a line of the template. {{ added "unreleased" }}

See [Adding Backends](../developers/adding-backends.md) for the step-by-step walkthrough, the testing pattern, and how to wire a new backend into `rsigma backend convert` if you also want CLI integration.

## Error handling

`ConvertError` from `thiserror`. Variants include `RuleConversion` (a rule could not be converted with the chosen backend or format), `UnsupportedModifier`, `InvalidIdentifier` (a table, schema, `timestamp_field`, `json_field`, or JSONB path segment failed validation), and `Pipeline` (a pre-conversion pipeline step failed).

`InvalidSelectField` reports a rule's `fields` entry outside the PostgreSQL SELECT list grammar, with the `entry` and a `reason`. {{ added "unreleased" }}

## See also

- [Rule Conversion](../guide/rule-conversion.md) for the operator-facing workflow.
- [PostgreSQL backend reference](../reference/backends/postgres.md), [LynxDB backend reference](../reference/backends/lynxdb.md), and [Fibratus backend reference](../reference/backends/fibratus.md).
- [Adding Backends](../developers/adding-backends.md) for the contributor walkthrough.
- [`rsigma-convert` README](https://github.com/timescale/rsigma/blob/main/crates/rsigma-convert/README.md) for the full Backend trait reference.
- [docs.rs/rsigma-convert](https://docs.rs/rsigma-convert).
