# rsigma-convert

[![CI](https://github.com/timescale/rsigma/actions/workflows/ci.yml/badge.svg)](https://github.com/timescale/rsigma/actions/workflows/ci.yml)

`rsigma-convert` is a Sigma rule conversion engine that transforms parsed Sigma rules into backend-native query strings (SQL, SPL, KQL, Lucene, etc.).

This library is part of [rsigma].

## Overview

The crate provides a generic conversion framework that any backend can plug into:

- **`Backend` trait** with ~30 methods covering condition dispatch, detection item conversion, field/value escaping, regex, CIDR, comparison operators, field existence, field references, keywords, IN-list optimization, deferred expressions, and query finalization.
- **`TextQueryConfig`** with ~90 configuration fields mirroring pySigma's `TextQueryBackend` class variables: precedence, boolean operators, wildcards, string/field quoting, match expressions (startswith/endswith/contains + case-sensitive variants), regex/CIDR templates, compare ops, IN-list optimization, unbound values, deferred parts, and query envelope.
- **Condition tree walker** that recursively converts `ConditionExpr` nodes into query strings with selector/quantifier support.
- **Orchestrator** via `convert_collection()`, which applies pipelines, converts each rule, and collects results and errors.
- **Deferred expressions** through the `DeferredExpression` trait and `DeferredTextExpression` for backends that need post-query appendages (e.g. Splunk `| regex`, `| where`).
- **Test backend** with `TextQueryTestBackend` and `MandatoryPipelineTestBackend` for backend-neutral foundation testing.

## Usage

```rust
use rsigma_parser::parse_sigma_yaml;
use rsigma_convert::{convert_collection, Backend};
use rsigma_convert::backends::test::TextQueryTestBackend;

let yaml = r#"
title: Detect Whoami
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
level: medium
"#;

let collection = parse_sigma_yaml(yaml).unwrap();
let backend = TextQueryTestBackend::new();

let output = convert_collection(&backend, &collection, &[], "default").unwrap();
for result in &output.queries {
    for query in &result.queries {
        println!("{query}");
        // Output: CommandLine contains "whoami"
    }
}
```

## Backend Trait

Backends implement the `Backend` trait to produce query strings from Sigma AST nodes. The trait operates on **parsed** types from `rsigma-parser` (not compiled matchers) because conversion needs the original field names, modifiers, and values.

Key methods:

| Method | Description |
|--------|-------------|
| `convert_rule` | Convert a single `SigmaRule` into query strings |
| `convert_condition` | Walk a `ConditionExpr` tree |
| `convert_detection` | Convert a `Detection` (AllOf/AnyOf/Keywords) |
| `convert_detection_item` | Convert a single `DetectionItem` (field + modifiers + values) |
| `convert_field_eq_str` | String value matching with modifier dispatch |
| `convert_field_eq_re` | Regex matching |
| `convert_field_eq_cidr` | CIDR matching |
| `convert_field_compare` | Numeric comparison (`gt`, `gte`, `lt`, `lte`) |
| `convert_field_exists` | Field existence check |
| `convert_keyword` | Unbound/keyword value matching |
| `finish_query` | Assemble final query with deferred parts |
| `finalize_query` | Apply output format to a query |
| `finalize_output` | Finalize the complete output |

## TextQueryConfig

For text-based query backends (the vast majority), create a `TextQueryConfig` with your backend's tokens and expressions, then delegate to the `text_convert_*` free functions:

| Function | Description |
|----------|-------------|
| `text_escape_and_quote_field` | Escape and optionally quote a field name |
| `text_convert_value_str` | Convert a `SigmaString` with escaping and quoting |
| `text_convert_value_re` | Escape a regex pattern |
| `text_convert_condition_and` | Join expressions with AND token |
| `text_convert_condition_or` | Join expressions with OR token |
| `text_convert_condition_not` | Negate an expression |
| `text_convert_condition_group` | Precedence-aware grouping |
| `text_convert_field_eq_str` | String match dispatch (contains/startswith/endswith/wildcard/exact) |
| `text_finish_query` | Assemble query with deferred parts and state substitution |

## Implementing a Backend

1. Define a `TextQueryConfig` constant with your backend's tokens and expressions.
2. Create a struct that implements `Backend`, delegating most methods to the `text_convert_*` helpers.
3. Override specific methods for backend-specific behavior (e.g. deferred regex for Splunk, SQL-specific CIDR handling for PostgreSQL).
4. Register your backend in the CLI's `get_backend()` registry.

See `backends/test.rs` for a complete reference implementation.

## License

MIT License.

[rsigma]: https://github.com/timescale/rsigma
