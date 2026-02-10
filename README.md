# rsigma

A Rust toolkit for [Sigma](https://github.com/SigmaHQ/sigma) detection rules — parsing, evaluation, and tooling.

This is a Cargo workspace containing three crates:

| Crate | Description |
|-------|-------------|
| [`rsigma-parser`](crates/rsigma-parser/) | Parse Sigma YAML into a strongly-typed AST | 
| [`rsigma-eval`](crates/rsigma-eval/) | Compile and evaluate rules against JSON events |
| [`rsigma-cli`](crates/rsigma-cli/) | CLI for parsing, validating, and evaluating rules |

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

## rsigma-eval

Compiles Sigma rules into optimized in-memory matchers and evaluates them against JSON events using a **compile-then-evaluate** model. Rules are compiled once; each event is matched with zero allocation on the hot path.

### Features

- **Compiled matchers** for all Sigma value-matching modifiers: `contains`, `startswith`, `endswith`, `re`, `cidr`, `base64offset`, `wide`, `windash`, `fieldref`, `exists`, numeric comparisons (`gt`, `gte`, `lt`, `lte`), wildcard patterns, null, and boolean equality
- **Condition tree evaluation** with short-circuit logic, supporting `and`, `or`, `not`, identifiers, and quantified selectors (`1 of selection_*`, `all of them`)
- **Logsource routing** — pre-filter rules by `product`, `category`, and `service` so only relevant rules are tested
- **Modifier combinations** — handles stacked modifiers like `|contains|all`, `|base64offset|contains`, `|re|i|m|s`
- **Event wrapper** with dot-notation field access (`process.name`), flat-key precedence, and keyword search across all string values
- **Rich match output** — `MatchResult` includes rule title, ID, level, tags, matched selection names, and matched field/value pairs

### Library Usage

```rust
use rsigma_parser::parse_sigma_yaml;
use rsigma_eval::{Engine, Event};
use serde_json::json;

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
let mut engine = Engine::new();
engine.add_collection(&collection).unwrap();

let event_val = json!({"CommandLine": "cmd /c whoami"});
let event = Event::from_value(&event_val);
let matches = engine.evaluate(&event);
assert_eq!(matches.len(), 1);
assert_eq!(matches[0].rule_title, "Detect Whoami");
```

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

# Evaluate a single event against rules
rsigma eval --rules path/to/rules/ --event '{"CommandLine": "whoami"}'

# Evaluate NDJSON events from stdin
cat events.ndjson | rsigma eval --rules path/to/rules/
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
              │
              ▼
     ┌──────────────────────────────────────────┐
     │              rsigma-eval                 │
     │                                          │
     │  compiler.rs ──> CompiledRule            │
     │    (AST → compiled matchers)             │
     │                                          │
     │  matcher.rs ──> CompiledMatcher          │
     │    (Exact, Contains, Regex, Cidr, ...)   │
     │                                          │
     │  engine.rs ──> Engine                    │
     │    (logsource routing, batch evaluation) │
     │                                          │
     │  event.rs ──> Event                      │
     │    (field access, keyword search)        │
     └──────────────────────────────────────────┘
              │
              ▼
     ┌──────────────────┐
     │  MatchResult     │──> rule title, id, level, tags,
     │                  │    matched selections, field matches
     └──────────────────┘
```

## Reference

This project is informed by:

- [pySigma](https://github.com/SigmaHQ/pySigma) — the reference Python implementation
- [Sigma Specification V2.0.0](https://github.com/SigmaHQ/sigma-specification) — the formal specification
- [sigma-rust](https://github.com/jopohl/sigma-rust) — Pratt parsing approach for conditions
- [sigmars](https://github.com/crowdalert/sigmars) — correlation rule support, pest grammar patterns

## License

MIT
