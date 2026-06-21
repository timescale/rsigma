# Adding a new backend

The `Backend` trait in [`rsigma-convert`](../library/convert.md) is the plug-in surface for SIEM query generation. The shipped implementations are `PostgresBackend`, `LynxDbBackend`, `FibratusBackend`, and the two test backends; this page walks through adding your own (Splunk, Elastic, KQL, ClickHouse, …) and wiring it into the CLI.

A native backend always takes precedence over [sigma-cli delegation](../reference/backends/sigma-cli.md): adding one for a target (for example `splunk`) transparently replaces the delegated path for that target, with no change to how users invoke `rsigma backend convert -t splunk`.

## Decide on the shape

Two flavours of backend, depending on how much pySigma-style boilerplate you want to inherit:

1. **Text-query backend.** Set `text_query_config()` to a `TextQueryConfig` and let the trait's default methods walk the condition AST for you. This is how `PostgresBackend`, `LynxDbBackend`, and `FibratusBackend` are built. Use this if your target language is a flat boolean expression with `field op value` shapes.
2. **Custom backend.** Override `convert_rule` outright. Use this when your target language has fundamentally different structure (a tree-shaped JSON DSL like Elasticsearch query DSL, or a pipeline of stages like Splunk SPL).

Most SIEMs fit shape 1.

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

Step 2: write the `TextQueryConfig` constant. The full schema lives on [docs.rs/rsigma-convert](https://docs.rs/rsigma-convert). `TextQueryConfig` does not have a `Default` impl; the cleanest pattern is to copy `crates/rsigma-convert/src/backends/postgres/mod.rs` (the `POSTGRES_CONFIG` block at the top of the file) or `lynxdb/mod.rs` (the `LYNX_CONFIG` block) as a starting template and edit the operators, quoting, and templates to match your target language. The key fields you almost always need to set:

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

Step 3: implement the trait.

```rust
use rsigma_convert::{Backend, TextQueryConfig};
use rsigma_convert::error::Result;
use rsigma_eval::pipeline::ConversionState;
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

    fn text_query_config(&self) -> Option<&TextQueryConfig> {
        Some(self.config)
    }

    fn finalize_query(
        &self,
        rule: &SigmaRule,
        query: String,
        output_format: &str,
        _state: &ConversionState,
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
}
```

Optional: override `output_file_extension` so the per-rule files `rsigma backend convert` writes when `--output` is a directory get the extension your target loader expects (`"sql"`, `"yml"`, ...). It defaults to `"txt"` and takes the output format so a backend can vary it per format.

Step 4: re-export from `lib.rs` so embedders can use the backend type directly.

```rust
// crates/rsigma-convert/src/lib.rs
pub use backends::splunk::SplunkBackend;
```

## Wire it into the CLI

Open `crates/rsigma-cli/src/commands/convert.rs`. The `get_backend` function is a small match on the `-t/--target` string:

```rust
fn get_backend(target: &str, options: &HashMap<String, String>) -> Box<dyn Backend> {
    match target {
        "postgres" | "postgresql" | "pg" =>
            Box::new(PostgresBackend::from_options(options)),
        "lynxdb" =>
            Box::new(LynxDbBackend::new()),
        "splunk" =>                                      // ← add this
            Box::new(SplunkBackend::from_options(options)),
        "test" => /* ... */,
        _ => /* fall through to unknown-target error */,
    }
}
```

Update the `Available targets:` error message at the bottom of the function and the `cmd_list_targets` printer earlier in the same file so unknown targets and `rsigma backend targets` both include the new option.

Then run `cargo install --path crates/rsigma-cli --force --features daemon` and:

```bash
rsigma backend targets
# postgres, lynxdb, splunk, test

rsigma backend convert -t splunk -O index=security rule.yml
```

## Test it

Add an integration test under `crates/rsigma-convert/tests/`:

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

Cover at least: keyword match, field=value, regex (`re|`), CIDR, IN-list (`OR`-folding), NULL, negation, and at least one correlation rule. The existing `crates/rsigma-convert/tests/postgres.rs` and `lynxdb.rs` files are the reference structure.

If your backend produces stable golden output, add a fixture under `tests/fixtures/dynamic-pipelines/` and a comparison loop in CI; the existing `Golden file comparison for rsigma pipeline resolve` step in `.github/workflows/ci.yml` is the template.

## Document it

Three places to update:

1. **Per-backend reference page** at `docs/reference/backends/<name>.md`. Use the existing [PostgreSQL backend reference](../reference/backends/postgres.md) as the template: modifier-mapping table, options table, output-format catalogue, examples.
2. **CLI reference for `rsigma backend convert`** at `docs/cli/backend/convert.md` if your backend introduces new options.
3. **Backend list page** at `docs/reference/backends/.pages` (if it exists) or the `mkdocs.yml` nav.

## Checklist

- [ ] Module added under `crates/rsigma-convert/src/backends/<name>/mod.rs`.
- [ ] Re-exported from `crates/rsigma-convert/src/lib.rs`.
- [ ] `Backend` trait implemented (or `TextQueryConfig` set).
- [ ] CLI dispatch wired in `crates/rsigma-cli/src/commands/convert.rs`.
- [ ] Integration tests in `crates/rsigma-convert/tests/<name>.rs`.
- [ ] Backend reference page under `docs/reference/backends/<name>.md`.
- [ ] CHANGELOG entry.

## See also

- [`rsigma-convert` README](https://github.com/timescale/rsigma/blob/main/crates/rsigma-convert/README.md) for the full `Backend` trait surface and the existing pySigma-equivalent class variables.
- [Rule Conversion](../guide/rule-conversion.md) for the user-facing CLI flow.
- [PostgreSQL backend reference](../reference/backends/postgres.md), [LynxDB backend reference](../reference/backends/lynxdb.md), and [Fibratus backend reference](../reference/backends/fibratus.md) for the three shipped reference implementations.
