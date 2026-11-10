---
description: "How to add a Sigma conversion backend to RSigma: implement the Backend trait in rsigma-convert, render queries, add golden tests, and wire it into the CLI."
---

# Adding a new backend

The `Backend` trait in [`rsigma-convert`](../library/convert.md) is the plug-in surface for SIEM query generation. The shipped implementations are `PostgresBackend`, `LynxDbBackend`, `FibratusBackend`, and the two test backends; this page walks through adding your own (Splunk, Elastic, KQL, ClickHouse, …) and wiring it into the CLI.

A native backend always takes precedence over [sigma-cli delegation](../reference/backends/sigma-cli.md): adding one for a target (for example `splunk`) transparently replaces the delegated path for that target, with no change to how users invoke `rsigma backend convert -t splunk`.

## Decide on the shape

Two flavors of backend, depending on how much pySigma-style boilerplate you want to inherit:

1. **Text-query backend.** Hold a `&'static TextQueryConfig` on your struct and implement the `Backend` methods by calling the `text_convert_*` helpers (and usually `convert_rule_via_ir` for `convert_rule`). There is no `Backend::text_query_config()` method. This is how `PostgresBackend`, `LynxDbBackend`, and `FibratusBackend` are built. Use this if your target language is a flat boolean expression with `field op value` shapes.
2. **Custom backend.** Override `convert_rule` outright (and the leaf converters as needed). Use this when your target language has fundamentally different structure (a tree-shaped JSON DSL like Elasticsearch query DSL, or a pipeline of stages like Splunk SPL).

Most SIEMs fit shape 1. See `crates/rsigma-convert/src/backends/lynxdb/mod.rs` or `postgres/mod.rs` for complete references.

## Walkthrough: a text-query backend

Step 1: scaffold the crate module.

```text
crates/rsigma-convert/src/backends/
├── fibratus/
├── lynxdb/
├── postgres/
├── splunk/                  ← new
│   └── mod.rs
└── mod.rs                   ← register the new module here
```

Add `pub mod splunk;` to `crates/rsigma-convert/src/backends/mod.rs`.

Step 2: write the `TextQueryConfig` constant. The full schema lives on [docs.rs/rsigma-convert](https://docs.rs/rsigma-convert). `TextQueryConfig` does not have a `Default` impl; the cleanest pattern is to copy `crates/rsigma-convert/src/backends/postgres/mod.rs` (the `POSTGRES_CONFIG` block at the top of the file) or `lynxdb/mod.rs` (the `LYNXDB_CONFIG` block) as a starting template and edit the operators, quoting, and templates to match your target language. The fields you almost always need to set:

| Field | Example |
|-------|---------|
| `precedence` | `(TokenType::NOT, TokenType::AND, TokenType::OR)` |
| `and_token`, `or_token`, `not_token` | `"AND"`, `"OR"`, `"NOT"` |
| `eq_token` | `"="` (Splunk) or `" = "` (Postgres). |
| `group_expression` | `"({expr})"` |
| `str_quote`, `escape_char` | How to wrap and escape string literals. |
| `wildcard_multi`, `wildcard_single` | `"*"`, `"?"` for most SIEMs. |
| `re_expression`, `cidr_expression` | Format strings for regex and CIDR comparisons. |

Run `rustdoc` (`cargo doc --open -p rsigma-convert`) for the full list of ~90 fields.

Step 3: implement the trait. Hold the config as `&'static TextQueryConfig`, delegate `convert_rule` to `convert_rule_via_ir`, and implement leaf converters plus `finish_query` and `finalize_query`. `ConversionState` is from `rsigma_convert::state`; `PipelineState` is from `rsigma_eval::pipeline::state`.

The condition walker passes every compound operand through `convert_condition_group` before combining it. Delegating to `text_convert_condition_group` parenthesizes by the config's `precedence`, so a target where `OR` binds tighter than `AND` only needs a different `precedence` tuple. {{ added "0.24.0" }}

```rust
use rsigma_convert::{
    Backend, TextQueryConfig, TokenType,
    condition_ir::convert_rule_via_ir,
    error::Result,
    state::ConversionState,
    text_convert_condition_and, text_convert_condition_group, text_convert_condition_not,
    text_convert_condition_or,
    text_convert_field_str_ir, text_escape_and_quote_field,
    // … other text_convert_* helpers as needed
};
use rsigma_eval::pipeline::state::PipelineState;
use rsigma_ir::{IrPattern, IrStrOp};
use rsigma_parser::SigmaRule;

pub struct SplunkBackend {
    pub config: &'static TextQueryConfig,
    pub index: String,
}

impl SplunkBackend {
    pub fn new() -> Self {
        Self {
            config: &SPLUNK_CONFIG,
            index: "main".to_string(),
        }
    }

    pub fn from_options(options: &std::collections::HashMap<String, String>) -> Self {
        let mut b = Self::new();
        if let Some(v) = options.get("index") {
            b.index = v.clone();
        }
        b
    }
}

impl Backend for SplunkBackend {
    fn name(&self) -> &str { "splunk" }

    fn formats(&self) -> &[(&str, &str)] {
        &[("default", "SPL search command"),
          ("savedsearch", "savedsearches.conf stanza")]
    }

    fn convert_rule(
        &self,
        rule: &SigmaRule,
        output_format: &str,
        pipeline_state: &PipelineState,
    ) -> Result<Vec<String>> {
        convert_rule_via_ir(self, rule, output_format, pipeline_state)
    }

    fn convert_condition_and(&self, exprs: &[String]) -> Result<String> {
        Ok(text_convert_condition_and(self.config, exprs))
    }

    fn convert_condition_or(&self, exprs: &[String]) -> Result<String> {
        Ok(text_convert_condition_or(self.config, exprs))
    }

    fn convert_condition_not(&self, expr: &str) -> Result<String> {
        Ok(text_convert_condition_not(self.config, expr))
    }

    fn convert_condition_group(
        &self,
        expr: &str,
        outer: TokenType,
        inner: TokenType,
    ) -> Result<String> {
        Ok(text_convert_condition_group(self.config, expr, outer, inner))
    }

    fn escape_and_quote_field(&self, field: &str) -> String {
        text_escape_and_quote_field(self.config, field)
    }

    fn convert_field_str(
        &self,
        field: &str,
        op: IrStrOp,
        pattern: &IrPattern,
        case_insensitive: bool,
        _state: &mut ConversionState,
    ) -> Result<rsigma_convert::state::ConvertResult> {
        text_convert_field_str_ir(self.config, field, op, pattern, case_insensitive)
    }

    // … implement the remaining leaf converters (eq_num, eq_bool, null, …)
    // by calling the matching text_convert_* helpers or writing target-specific SQL/SPL.

    fn finish_query(
        &self,
        _rule: &SigmaRule,
        query: String,
        _state: &ConversionState,
    ) -> Result<String> {
        Ok(query)
    }

    fn finalize_query(
        &self,
        rule: &SigmaRule,
        query: String,
        _index: usize,
        _state: &ConversionState,
        output_format: &str,
    ) -> Result<String> {
        match output_format {
            "default" => Ok(format!("index={} | search {}", self.index, query)),
            "savedsearch" => {
                let name = rule.title.replace(' ', "_");
                Ok(format!(
                    "[{name}]\nsearch = index={} | search {}\n",
                    self.index, query
                ))
            }
            _ => Err(rsigma_convert::ConvertError::RuleConversion(
                format!("unknown output format: {output_format}"))),
        }
    }

    fn finalize_output(&self, queries: Vec<String>, _output_format: &str) -> Result<String> {
        Ok(queries.join("\n"))
    }
}
```

Optional: override `output_file_extension` so the per-rule files `rsigma backend convert` writes when `--output` is a directory get the extension your target loader expects (`"sql"`, `"yml"`, ...). It defaults to `"txt"` and takes the output format so a backend can vary it per format.

Step 4: re-export from `lib.rs` so embedders can use the backend type directly.

```rust
// crates/rsigma-convert/src/lib.rs
pub use backends::splunk::SplunkBackend;
```

## Wire it into the CLI

Open `crates/rsigma-cli/src/commands/convert.rs`. Native backends are registered in `try_native_backend` and listed in `NATIVE_TARGETS`:

```rust
const NATIVE_TARGETS: &[&str] = &["postgres", "lynxdb", "fibratus", "splunk"];

fn try_native_backend(
    target: &str,
    options: &std::collections::HashMap<String, String>,
) -> Option<Box<dyn rsigma_convert::Backend>> {
    match target {
        "postgres" | "postgresql" | "pg" => Some(Box::new(
            rsigma_convert::backends::postgres::PostgresBackend::from_options(options),
        )),
        "lynxdb" => Some(Box::new(
            rsigma_convert::backends::lynxdb::LynxDbBackend::new(),
        )),
        "fibratus" => Some(Box::new(
            rsigma_convert::backends::fibratus::FibratusBackend::from_options(options),
        )),
        "splunk" => Some(Box::new(SplunkBackend::from_options(options))),
        "test" => /* ... */,
        _ => None,
    }
}
```

Update `NATIVE_TARGETS`, the `Available targets:` and install-hint paths that take `NATIVE_TARGETS`, and the `cmd_list_targets` printer in the same file so unknown targets and `rsigma backend targets` both include the new option.

Then run `cargo install --path crates/rsigma-cli --force --features daemon` and:

```bash
rsigma backend targets
# postgres, lynxdb, fibratus, splunk, …

rsigma backend convert -t splunk -O index=security rule.yml
```

## Test it

Add an integration test under `crates/rsigma-convert/tests/`. Prefer a golden-style file mirroring the existing suites:

```rust
use rsigma_convert::{convert_collection, backends::splunk::SplunkBackend};
use rsigma_parser::parse_sigma_yaml;

#[test]
fn splunk_basic_keyword() {
    let yaml = include_str!("fixtures/whoami.yml");
    let collection = parse_sigma_yaml(yaml).unwrap();
    let out = convert_collection(&SplunkBackend::new(), &collection, &[], "default").unwrap();
    assert!(out.queries[0].queries[0].contains(r#"CommandLine="*whoami*""#));
}
```

Cover at least: keyword match, field=value, regex (`re|`), CIDR, IN-list (`OR`-folding), NULL, negation, and at least one correlation rule. The existing `crates/rsigma-convert/tests/golden_postgres.rs`, `golden_lynxdb.rs`, and `golden_fibratus.rs` files are the reference structure.

If your backend produces stable golden output, add expected files under `crates/rsigma-convert/tests/golden/<name>/` and compare in the test; the Postgres, LynxDB, and Fibratus golden suites are the template.

## Document it

Three places to update:

1. **Per-backend reference page** at `docs/content/reference/backends/<name>.md`. Use the existing [PostgreSQL backend reference](../reference/backends/postgres.md) as the template: modifier-mapping table, options table, output-format catalog, examples.
2. **CLI reference for `rsigma backend convert`** at `docs/content/cli/backend/convert.md` if your backend introduces new options.
3. **Backend list page** in `docs/docmd.config.js` navigation under Reference → Backends.

## Checklist

- [ ] Module added under `crates/rsigma-convert/src/backends/<name>/mod.rs`.
- [ ] Re-exported from `crates/rsigma-convert/src/lib.rs`.
- [ ] `Backend` trait implemented (config held on the struct; `text_convert_*` and `convert_rule_via_ir` used for text-query backends).
- [ ] `finish_query` and `finalize_query` implemented.
- [ ] CLI dispatch wired in `try_native_backend` + `NATIVE_TARGETS` in `crates/rsigma-cli/src/commands/convert.rs`.
- [ ] Integration and golden tests in `crates/rsigma-convert/tests/golden_<name>.rs`.
- [ ] Backend reference page under `docs/content/reference/backends/<name>.md`.
- [ ] CHANGELOG entry.

## See also

- [`rsigma-convert` README](https://github.com/timescale/rsigma/blob/main/crates/rsigma-convert/README.md) for the full `Backend` trait surface and the existing pySigma-equivalent class variables.
- [Rule Conversion](../guide/rule-conversion.md) for the user-facing CLI flow.
- [PostgreSQL backend reference](../reference/backends/postgres.md), [LynxDB backend reference](../reference/backends/lynxdb.md), and [Fibratus backend reference](../reference/backends/fibratus.md) for the three shipped reference implementations.
