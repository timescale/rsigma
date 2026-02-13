# RSigma

A Rust implementation of the [Sigma](https://github.com/SigmaHQ/sigma) detection standard — parser, evaluation engine, and CLI. rsigma parses Sigma YAML rules into a strongly-typed AST, compiles them into optimized matchers, and evaluates them directly against JSON log events in real time. Unlike a pure parser or transpiler, rsigma acts as a **backend**: it runs detection and correlation logic in-process, supports processing pipelines for field mapping and backend-specific configuration, and streams results from NDJSON input — no external SIEM required.

## Crates

| Crate | Description |
|-------|-------------|
| [`rsigma-parser`](crates/rsigma-parser/) | Parse Sigma YAML into a strongly-typed AST | 
| [`rsigma-eval`](crates/rsigma-eval/) | Compile and evaluate rules against JSON events |
| [`rsigma-cli`](crates/rsigma-cli/) | CLI for parsing, validating, and evaluating rules |
| [`rsigma-lsp`](crates/rsigma-lsp/) | Language Server Protocol (LSP) server for IDE support |

## rsigma-parser

Parses Sigma YAML into a strongly-typed AST covering the full Sigma 2.0 specification.

### Features

- **Linter**: 44 built-in rules derived from the Sigma v2.1.0 specification — validates metadata fields (title, id, status, level, date, tags), detection logic, correlation rules, and filter rules. Operates on raw YAML values to catch issues the parser silently ignores.
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
- **Alert suppression**: per-correlation or global suppression windows to prevent alert floods during sustained activity
- **Action-on-fire**: configurable post-fire behavior — `alert` (keep state, re-fire) or `reset` (clear window, require fresh threshold)
- **Generate flag**: Sigma-standard `generate` support — suppress detection output for correlation-only rules via `--no-detections`
- **Processing pipelines**: pySigma-compatible field mapping, logsource transformation, value replacement, placeholder expansion, conditional application, and multi-pipeline chaining — 26 transformation types, 3 condition levels
- **Custom attributes**: `SetCustomAttribute` pipeline transformation stores key-value pairs on rules (mirrors pySigma's `SigmaRule.custom_attributes`). The `rsigma.*` namespace configures engine behavior from pipelines — the same pattern used by backends like [pySigma-backend-loki](https://github.com/grafana/pySigma-backend-loki)
- **Filter application**: runtime injection of filter rules as `AND NOT` conditions
- **Special modifiers**: `|expand` (runtime placeholder expansion), `|neq` (not-equal), `|utf16be`/`|utf16` encoding, timestamp part extraction (`|hour`, `|day`, etc.)
- **Event wrapper**: dot-notation field access, flat-key precedence, keyword search across all string values
- **Rich output**: `MatchResult` with optional embedded event JSON / `CorrelationResult` with rule metadata, matched selections, field/value pairs, and aggregated values

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
use rsigma_eval::{CorrelationEngine, CorrelationConfig, CorrelationAction};

let config = CorrelationConfig {
    suppress: Some(300),                         // 5-minute suppression window
    action_on_match: CorrelationAction::Reset,   // clear state after firing
    emit_detections: false,                      // only emit correlation alerts
    ..Default::default()
};

let mut engine = CorrelationEngine::new(config);
engine.set_include_event(true);                  // embed event JSON in all match results
engine.add_collection(&collection).unwrap();
let result = engine.process_event_at(&event, timestamp_secs);
// result.detections + result.correlations
```

### Custom Attributes (`rsigma.*`)

Pipeline transformations can configure engine behavior via `SetCustomAttribute`, following the same pattern as pySigma backends:

| Attribute | Effect | CLI equivalent |
|-----------|--------|----------------|
| `rsigma.timestamp_field` | Prepends a field name to the timestamp extraction priority list | `--timestamp-field` |
| `rsigma.suppress` | Sets the default suppression window (e.g. `5m`) | `--suppress` |
| `rsigma.action` | Sets the post-fire action (`alert` or `reset`) | `--action` |
| `rsigma.include_event` | Embeds the full event JSON in detection output (per-rule) | `--include-event` |

CLI flags and the library API (`engine.set_include_event(true)`) always take precedence over pipeline attributes. Example pipeline:

```yaml
transformations:
  - type: set_custom_attribute
    attribute: rsigma.timestamp_field
    value: time
  - type: set_custom_attribute
    attribute: rsigma.suppress
    value: 5m
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

# Unwrap nested event payloads with jq syntax
rsigma eval -r rules/ --jq '.event' -e '{"ts":"...","event":{"CommandLine":"whoami"}}'

# Or use JSONPath (RFC 9535)
rsigma eval -r rules/ --jsonpath '$.event' -e '{"ts":"...","event":{"CommandLine":"whoami"}}'

# Stream wrapped NDJSON — jq can yield multiple events per line
hel run | rsigma eval -r rules/ -p ecs.yml --jq '.event'

# Array-wrapped events: .records[] yields one event per array element
rsigma eval -r rules/ --jq '.records[]' -e '{"records":[{"CommandLine":"whoami"},{"CommandLine":"id"}]}'

# Include matched event JSON in detection output
rsigma eval -r rules/ --include-event -e '{"CommandLine": "whoami"}'

# Alert suppression — suppress duplicate correlation alerts within a window
rsigma eval -r rules/ --suppress 5m -e @events.ndjson

# Action on fire — reset correlation state after alert (default: alert)
rsigma eval -r rules/ --suppress 5m --action reset -e @events.ndjson

# Suppress detection output (only show correlation alerts)
rsigma eval -r rules/ --no-detections -e @events.ndjson

# Specify the event timestamp field for correlation windowing
rsigma eval -r rules/ --timestamp-field time -e @events.ndjson

# Lint rules against the Sigma specification
rsigma lint path/to/rules/

# Lint with verbose output (show passing files)
rsigma lint path/to/rules/ -v

# Lint with optional JSON schema validation (downloads and caches official schema)
rsigma lint path/to/rules/ --schema default

# Lint with a local JSON schema file
rsigma lint rule.yml --schema my-schema.json

# Force colored output (auto-detected by default, respects NO_COLOR)
rsigma lint path/to/rules/ --color always

# Validate with pipeline
rsigma validate rules/ -p pipelines/ecs.yml -v

# Stream NDJSON events
cat events.ndjson | rsigma eval -r path/to/rules/
```

## rsigma-lsp

A Language Server Protocol (LSP) server that brings real-time Sigma rule development support to any editor — VSCode, Neovim, Helix, Zed, Emacs, and more. Built on the same parser, linter, and compiler as the CLI.

### Features

- **Diagnostics**: real-time validation from three layers — 44 lint rules (Sigma spec v2.1.0), parser errors (YAML and condition expressions), and compiler errors (unknown selections, invalid modifier combos)
- **Completions**: context-aware suggestions for field modifiers (`|contains`, `|base64`, etc.), status/level enums, logsource category/product/service values, MITRE ATT&CK tags, condition keywords, and selection names from the current rule
- **Hover**: documentation for all 23 field modifiers and MITRE ATT&CK tactics/techniques with links
- **Document symbols**: navigable outline of rule structure (title, logsource, detection selections, condition)

### Installation

```bash
# Build and install the LSP binary
cargo install --path crates/rsigma-lsp
```

### Editor Setup

**Neovim** (native LSP):

```lua
vim.api.nvim_create_autocmd('FileType', {
  pattern = 'yaml',
  callback = function()
    vim.lsp.start({
      name = 'rsigma-lsp',
      cmd = { 'rsigma-lsp' },
    })
  end,
})
```

**VSCode**: A thin extension wrapper is provided in [`editors/vscode/`](editors/vscode/). To use it:

```bash
cd editors/vscode
npm install
npx vsce package
# Install the .vsix file via: code --install-extension rsigma-*.vsix
```

The extension launches `rsigma-lsp` from your `$PATH` by default. Override via the `rsigma.serverPath` setting.

**Helix** (`~/.config/helix/languages.toml`):

```toml
[language-server.rsigma-lsp]
command = "rsigma-lsp"

[[language]]
name = "yaml"
language-servers = ["yaml-language-server", "rsigma-lsp"]
```

## Benchmarks

Criterion.rs benchmarks with synthetic rules and events (Apple M-series, single-threaded):

### Parsing

| Scenario | Time |
|----------|------|
| 1 rule | 11.7 µs |
| 100 rules | 1.1 ms |
| 1,000 rules | 11.1 ms |
| Complex condition (8 selections, nested booleans) | 23.2 µs |

### Detection Evaluation

| Scenario | Time | Throughput |
|----------|------|------------|
| Compile 1,000 rules | 669 µs | — |
| Compile 5,000 rules | 3.4 ms | — |
| 1 event vs 100 rules | 4.8 µs | — |
| 1 event vs 1,000 rules | 65 µs | — |
| 1 event vs 5,000 rules | 336 µs | — |
| 100K events vs 100 rules | 458 ms | **218K events/sec** |
| Wildcard-heavy (1,000 rules, 100 events) | 5.9 ms | — |
| Regex-heavy (1,000 rules, 100 events) | 7.3 ms | — |

### Correlation Engine

| Scenario | Time | Throughput |
|----------|------|------------|
| 1K events, 20 event_count correlations | 727 µs | **1.37M events/sec** |
| 1K events, 10 temporal correlations | 411 µs | **2.43M events/sec** |
| 100K events, 50 detection + 10 correlation rules | 217 ms | **462K events/sec** |
| 50K unique group keys (state pressure) | 35.8 ms | **1.40M events/sec** |

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
     ┌─────┴──────────────────────────────────────────────┐
     │                                                     │
     ▼                                                     ▼
     ┌──────────────────────────────────────────┐   ┌────────────────────┐
     │              rsigma-eval                 │   │    rsigma-lsp      │
     │                                          │   │                    │
     │  pipeline/ ──> Pipeline (YAML parsing,   │   │  LSP server over   │
     │    conditions, transformations, state)   │   │  stdio (tower-lsp) │
     │    ↓ transforms SigmaRule AST            │   │                    │
     │                                          │   │  • diagnostics     │
     │  compiler.rs ──> CompiledRule            │   │    (lint + parse   │
     │  matcher.rs  ──> CompiledMatcher         │   │     + compile)     │
     │  engine.rs   ──> Engine (stateless)      │   │  • completions     │
     │                                          │   │  • hover           │
     │  correlation.rs ──> CompiledCorrelation  │   │  • document        │
     │  correlation_engine.rs ──> (stateful)    │   │    symbols         │
     │    sliding windows, group-by, chaining,  │   │                    │
     │    alert suppression, action-on-fire     │   │  Editors:          │
     │                                          │   │  VSCode, Neovim,   │
     │  rsigma.* custom attributes ─────────>   │   │  Helix, Zed, ...  │
     │    engine config from pipelines          │   └────────────────────┘
     └──────────────────────────────────────────┘
              │
              ▼
     ┌────────────────────┐
     │  MatchResult       │──> rule title, id, level, tags,
     │  CorrelationResult │   matched selections, aggregated
     └────────────────────┘   values, optional event JSON
```

## Reference

- [pySigma](https://github.com/SigmaHQ/pySigma) — reference Python implementation
- [Sigma Specification V2.0.0](https://github.com/SigmaHQ/sigma-specification) — formal specification
- [sigma-rust](https://github.com/jopohl/sigma-rust) — Pratt parsing approach
- [sigmars](https://github.com/crowdalert/sigmars) — correlation support patterns

## License

MIT
