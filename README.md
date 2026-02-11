# rsigma

A Rust toolkit for [Sigma](https://github.com/SigmaHQ/sigma) detection rules — parsing, evaluation, correlation, and tooling.

## Crates

| Crate | Description |
|-------|-------------|
| [`rsigma-parser`](crates/rsigma-parser/) | Parse Sigma YAML into a strongly-typed AST | 
| [`rsigma-eval`](crates/rsigma-eval/) | Compile and evaluate rules against JSON events |
| [`rsigma-cli`](crates/rsigma-cli/) | CLI for parsing, validating, and evaluating rules |

## rsigma-parser

Parses Sigma YAML into a strongly-typed AST covering the full Sigma 2.0 specification.

### Features

- **PEG grammar** (pest) for condition expressions with correct operator precedence
- **All field modifiers**: `contains`, `endswith`, `startswith`, `re`, `cidr`, `base64`, `base64offset`, `wide`/`utf16le`, `utf16be`, `utf16`, `windash`, `all`, `cased`, `exists`, `fieldref`, `expand`, `neq`, comparison operators (`gt`, `gte`, `lt`, `lte`), regex flags (`i`, `m`, `s`), timestamp parts (`minute`, `hour`, `day`, `week`, `month`, `year`)
- **Condition expressions**: `and`, `or`, `not`, `1 of`, `all of`, `any of`, `N of`, parenthesized groups, wildcard patterns — `them` excludes `_`-prefixed identifiers per spec
- **Correlation rules**: `event_count`, `value_count`, `temporal`, `temporal_ordered`, `value_sum`, `value_avg`, `value_percentile`, `value_median` with threshold conditions (including range predicates like `gt: 10, lte: 100`), extended boolean conditions, field aliases, and chaining
- **Filter rules**: injected as `AND NOT` conditions on referenced rules with logsource compatibility checks
- **Multi-document YAML**: `---` separators, `action: global/reset/repeat`
- **Value types**: strings with wildcards (`*`, `?`), escape sequences, numbers, booleans, null
- **Timespan parsing**: `1h`, `15s`, `30m`, `7d`, `1w`, `1M`, `1y`

### Compatibility

Tested against the [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) rule repository:

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

The deprecated pipe aggregation syntax (`selection | count(field) by field > N`) is intentionally rejected, matching [pySigma](https://github.com/SigmaHQ/pySigma) behavior.

### Usage

```rust
use rsigma_parser::{parse_sigma_yaml, parse_condition};

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
assert_eq!(collection.rules[0].title, "Detect Whoami");
```

## rsigma-eval

Compiles Sigma rules into optimized in-memory matchers and evaluates them against JSON events. Rules are compiled once; evaluation is zero-allocation on the hot path.

### Features

- **Detection engine**: compiled matchers for all modifier combinations, logsource routing, condition tree evaluation with short-circuit logic
- **Correlation engine**: stateful processing with sliding time windows, group-by aggregation, field aliasing, correlation chaining, and all 8 correlation types
- **Processing pipelines**: pySigma-compatible field mapping, logsource transformation, value replacement, placeholder expansion, conditional application, and multi-pipeline chaining — 26 transformation types, 3 condition levels
- **Filter application**: runtime injection of filter rules as `AND NOT` conditions
- **Special modifiers**: `|expand` (runtime placeholder expansion), `|neq` (not-equal), `|utf16be`/`|utf16` encoding, timestamp part extraction (`|hour`, `|day`, etc.)
- **Event wrapper**: dot-notation field access, flat-key precedence, keyword search across all string values
- **Rich output**: `MatchResult` / `CorrelationResult` with rule metadata, matched selections, field/value pairs, and aggregated values

### Usage

```rust
use rsigma_parser::parse_sigma_yaml;
use rsigma_eval::{Engine, Event};
use serde_json::json;

let collection = parse_sigma_yaml(yaml).unwrap();
let mut engine = Engine::new();
engine.add_collection(&collection).unwrap();

let event = Event::from_value(&json!({"CommandLine": "cmd /c whoami"}));
let matches = engine.evaluate(&event);
assert_eq!(matches[0].rule_title, "Detect Whoami");
```

With a processing pipeline:

```rust
use rsigma_eval::{Engine, Event, parse_pipeline};

let pipeline = parse_pipeline(r#"
name: ECS Mapping
transformations:
  - type: field_name_mapping
    mapping:
      CommandLine: process.command_line
    rule_conditions:
      - type: logsource
        product: windows
"#).unwrap();

let mut engine = Engine::new_with_pipeline(pipeline);
engine.add_collection(&collection).unwrap();

// Rule now expects ECS field names
let event = Event::from_value(&json!({"process.command_line": "whoami"}));
let matches = engine.evaluate(&event);
```

For correlations:

```rust
use rsigma_eval::{CorrelationEngine, CorrelationConfig};

let mut engine = CorrelationEngine::new(CorrelationConfig::default());
engine.add_collection(&collection).unwrap();
let result = engine.process_event_at(&event, timestamp_secs);
// result.detections + result.correlations
```

## rsigma-cli

```bash
# Parse a single rule
rsigma parse rule.yml

# Validate all rules in a directory
rsigma validate path/to/sigma/rules/ -v

# Evaluate events against rules
rsigma eval -r path/to/rules/ -e '{"CommandLine": "whoami"}'

# Evaluate with a processing pipeline
rsigma eval -r rules/ -p pipelines/ecs.yml -e '{"process.command_line": "whoami"}'

# Multiple pipelines (applied in priority order)
rsigma eval -r rules/ -p sysmon.yml -p custom.yml -e '...'

# Validate with pipeline
rsigma validate rules/ -p pipelines/ecs.yml -v

# Stream NDJSON events
cat events.ndjson | rsigma eval -r path/to/rules/
```

## Benchmarks

Criterion.rs benchmarks with synthetic rules and events (Apple M-series, single-threaded):

### Parsing

| Scenario | Time |
|----------|------|
| 1 rule | 12 µs |
| 100 rules | 1.2 ms |
| 1,000 rules | 12 ms |
| Complex condition (8 selections, nested booleans) | 24 µs |

### Detection Evaluation

| Scenario | Time | Throughput |
|----------|------|------------|
| Compile 1,000 rules | 676 µs | — |
| Compile 5,000 rules | 3.5 ms | — |
| 1 event vs 100 rules | 5 µs | — |
| 1 event vs 1,000 rules | 67 µs | — |
| 1 event vs 5,000 rules | 371 µs | — |
| 100K events vs 100 rules | 493 ms | **203K events/sec** |
| Wildcard-heavy (1,000 rules, 100 events) | 6.9 ms | — |
| Regex-heavy (1,000 rules, 100 events) | 8.1 ms | — |

### Correlation Engine

| Scenario | Time | Throughput |
|----------|------|------------|
| 1K events, 20 event_count correlations | 737 µs | **1.36M events/sec** |
| 1K events, 10 temporal correlations | 415 µs | **2.41M events/sec** |
| 100K events, 50 detection + 10 correlation rules | 223 ms | **449K events/sec** |
| 50K unique group keys (state pressure) | 39 ms | **1.26M events/sec** |

Run benchmarks:

```bash
cargo bench                          # all benchmarks
cargo bench --bench parse            # parser only
cargo bench --bench eval             # detection only
cargo bench --bench correlation      # correlations only
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
            ┌────────────────┼──────────────┐
            ▼                ▼              ▼
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
     │  pipeline/ ──> Pipeline (YAML parsing,   │
     │    conditions, transformations, state)   │
     │    ↓ transforms SigmaRule AST            │
     │                                          │
     │  compiler.rs ──> CompiledRule            │
     │  matcher.rs  ──> CompiledMatcher         │
     │  engine.rs   ──> Engine (stateless)      │
     │                                          │
     │  correlation.rs ──> CompiledCorrelation  │
     │  correlation_engine.rs ──> (stateful)    │
     │    sliding windows, group-by, chaining   │
     └──────────────────────────────────────────┘
              │
              ▼
     ┌────────────────────┐
     │  MatchResult       │──> rule title, id, level, tags,
     │  CorrelationResult │   matched selections, aggregated values
     └────────────────────┘
```

## Reference

- [pySigma](https://github.com/SigmaHQ/pySigma) — reference Python implementation
- [Sigma Specification V2.0.0](https://github.com/SigmaHQ/sigma-specification) — formal specification
- [sigma-rust](https://github.com/jopohl/sigma-rust) — Pratt parsing approach
- [sigmars](https://github.com/crowdalert/sigmars) — correlation support patterns

## License

MIT
