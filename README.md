# rsigma

A Rust toolkit for [Sigma](https://github.com/SigmaHQ/sigma) detection rules - parsing, evaluation, and tooling.

This is a Cargo workspace containing three crates:

| Crate | Description | Status |
|-------|-------------|--------|
| [`rsigma-parser`](crates/rsigma-parser/) | Parse Sigma YAML into a strongly-typed AST | Ready |
| [`rsigma-eval`](crates/rsigma-eval/) | Evaluate compiled rules against events | Planned |
| [`rsigma-cli`](crates/rsigma-cli/) | CLI for parsing, validating, and evaluating rules | Ready |

## rsigma-parser

Parses Sigma YAML into a strongly-typed AST, handling the full Sigma 2.0 specification: detection rules, condition expressions, field modifiers, value wildcards, correlation rules, filter rules, and multi-document collections.

### Features

- **PEG grammar** (pest) for condition expression parsing with correct operator precedence
- **All 30+ field modifiers**: `contains`, `endswith`, `startswith`, `re`, `cidr`, `base64`, `base64offset`, `wide`, `windash`, `all`, `cased`, `exists`, `fieldref`, `expand`, comparison operators (`gt`, `gte`, `lt`, `lte`), regex flags (`i`, `m`, `s`), timestamp parts (`minute`, `hour`, `day`, `week`, `month`, `year`)
- **Condition expressions**: `and`, `or`, `not`, `1 of`, `all of`, `any of`, `N of`, parenthesized groups, wildcard identifier patterns
- **Correlation rules**: `event_count`, `value_count`, `temporal`, `temporal_ordered`, `value_sum`, `value_avg`, `value_percentile`, `value_median` with threshold and extended (boolean) conditions
- **Filter rules**: additional conditions applied to referenced rules
- **Multi-document YAML**: `---` separators, `action: global/reset/repeat`
- **Value types**: strings with wildcards (`*`, `?`), escape sequences (`\`), numbers, booleans, null
- **Timespan parsing**: `1h`, `15s`, `30m`, `7d`, `1w`, `1M`, `1y`

### Compatibility

Tested against the full [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) rule repository:

| Corpus | Rules Parsed | Errors |
|--------|-------------|--------|
| `rules/` | 3,110 | 0 |
| `rules-emerging-threats/` | 436 | 0 |
| `rules-threat-hunting/` | 133 | 0 |
| `rules-compliance/` | 3 | 0 |
| `rules-placeholder/` | 14 | 0 |
| `unsupported/` | 31 | 58 (deprecated pipe syntax) |
| `deprecated/` | 165 | 1 (deprecated pipe syntax) |
| **Total** | **3,892** | **0 real errors** |

The deprecated pipe aggregation syntax (`selection | count(field) by field > N`) is intentionally rejected, matching [pySigma](https://github.com/SigmaHQ/pySigma) behavior. This syntax has been replaced by Sigma correlations.

### Library Usage

```rust
use rsigma_parser::{parse_sigma_yaml, parse_condition, ConditionExpr};

// Parse a Sigma rule from YAML
let yaml = r#"
title: Detect Whoami
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
level: medium
"#;

let collection = parse_sigma_yaml(yaml).unwrap();
let rule = &collection.rules[0];
assert_eq!(rule.title, "Detect Whoami");
assert_eq!(rule.detection.named.len(), 1);

// Parse a condition expression directly
let expr = parse_condition(
    "selection_main and 1 of selection_dword_* and not 1 of filter_*"
).unwrap();
println!("{expr}");
// (selection_main and 1 of selection_dword_* and not 1 of filter_*)
```

## rsigma-eval (planned)

Streaming evaluator for Sigma rules against JSON events. Planned features:

- Streaming rule evaluation against NDJSON events
- Field matching with all Sigma modifiers
- Boolean condition evaluation with short-circuit optimization
- Compiled matchers for zero-allocation hot-path evaluation
- Logsource routing (pre-filter rules by product/category/service)
- Correlation engine (event_count, value_count, temporal windowing)

## rsigma-cli

```bash
# Parse a single rule and print the AST as JSON
rsigma parse path/to/rule.yml

# Validate all rules in a directory (recursive)
rsigma validate path/to/sigma/rules/

# Parse a condition expression
rsigma condition "selection and not 1 of filter_*"

# Parse from stdin
cat rule.yml | rsigma stdin
```

## Architecture

```
                    ┌──────────────────┐
   YAML input ───>  │   serde_yaml     │──> Raw YAML Value
                    └──────────────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │   parser.rs      │──> Typed AST
                    │  (YAML → AST)    │   (SigmaRule, CorrelationRule,
                    └──────────────────┘    FilterRule, SigmaCollection)
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
     ┌────────────┐  ┌────────────┐  ┌────────────┐
     │ sigma.pest │  │  value.rs  │  │   ast.rs   │
     │  (PEG      │  │ (SigmaStr, │  │ (AST types │
     │  grammar)  │  │  wildcards,│  │  modifiers,│
     │     +      │  │  timespan) │  │  enums)    │
     │condition.rs│  └────────────┘  └────────────┘
     │  (Pratt    │
     │  parser)   │
     └────────────┘
```

### Condition Expression Grammar

The condition parser uses a PEG grammar with a Pratt parser for correct operator precedence:

```
Precedence (highest → lowest):
  NOT  (prefix)
  AND  (left-associative)
  OR   (left-associative)
```

Keywords (`and`, `or`, `not`, `all`, `any`, `of`, `them`) use atomic rules with negative lookahead to distinguish from identifiers that contain keyword substrings (e.g., `selection_and_filter` is one identifier, not `selection` `and` `filter`).

## Workspace Structure

```
rsigma/
├── Cargo.toml                  # workspace root
├── LICENSE
├── README.md
└── crates/
    ├── rsigma-parser/          # parsing library
    │   ├── Cargo.toml
    │   └── src/
    │       ├── lib.rs
    │       ├── ast.rs          # AST types
    │       ├── condition.rs    # Condition parser (pest + Pratt)
    │       ├── error.rs        # Error types
    │       ├── parser.rs       # YAML → AST
    │       ├── sigma.pest      # PEG grammar
    │       └── value.rs        # SigmaString, SigmaValue, Timespan
    ├── rsigma-eval/            # evaluator (planned)
    │   ├── Cargo.toml
    │   └── src/
    │       └── lib.rs
    └── rsigma-cli/             # CLI binary
        ├── Cargo.toml
        └── src/
            └── main.rs
```

## Reference

This project is informed by:

- [pySigma](https://github.com/SigmaHQ/pySigma) — the reference Python implementation
- [Sigma Specification V2.0.0](https://github.com/SigmaHQ/sigma-specification) — the formal specification
- [sigma-rust](https://github.com/jopohl/sigma-rust) — Pratt parsing approach for conditions
- [sigmars](https://github.com/crowdalert/sigmars) — correlation rule support, pest grammar patterns

## License

MIT
