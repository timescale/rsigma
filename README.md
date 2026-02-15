# RSigma

A complete Rust toolkit for the [Sigma](https://github.com/SigmaHQ/sigma) detection standard — parser, evaluation engine, linter, CLI, and LSP. rsigma parses Sigma YAML rules into a strongly-typed AST, compiles them into optimized matchers, and evaluates them directly against JSON log events in real time. It runs detection and stateful correlation logic in-process with memory-efficient compressed event storage, supports pySigma-compatible processing pipelines for field mapping and backend configuration, and streams results from NDJSON input — no external SIEM required. A built-in linter validates rules against 64 checks derived from the Sigma v2.1.0 specification with four severity levels and a full suppression system, and an LSP server provides real-time diagnostics, completions, and hover documentation in any editor.

| Crate | Description |
|-------|-------------|
| [`rsigma-parser`](crates/rsigma-parser/) | Parse Sigma YAML into a strongly-typed AST |
| [`rsigma-eval`](crates/rsigma-eval/) | Compile and evaluate rules against JSON events |
| [`rsigma-cli`](crates/rsigma-cli/) | CLI for parsing, validating, linting, and evaluating rules |
| [`rsigma-lsp`](crates/rsigma-lsp/) | Language Server Protocol (LSP) server for IDE support |

## Installation

```bash
# Build all crates
cargo build --release

# Install the CLI
cargo install --path crates/rsigma-cli

# Install the LSP server
cargo install --path crates/rsigma-lsp
```

## Quick Start

Evaluate events against Sigma rules from the command line:

```bash
# Single event
rsigma eval -r path/to/rules/ -e '{"CommandLine": "cmd /c whoami"}'

# Stream NDJSON from stdin
cat events.ndjson | rsigma eval -r path/to/rules/

# With a processing pipeline for field mapping
rsigma eval -r rules/ -p pipelines/ecs.yml -e '{"process.command_line": "whoami"}'
```

Or use the library directly:

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

let event = Event::from_value(&json!({"CommandLine": "cmd /c whoami"}));
let matches = engine.evaluate(&event);
assert_eq!(matches[0].rule_title, "Detect Whoami");
```

---

## rsigma-parser

Parses Sigma YAML into a strongly-typed AST covering the full Sigma 2.0 specification.

### Parsing

- **Multi-document YAML**: `---` separators, `action: global/reset/repeat` for rule templates
- **Condition expressions**: PEG grammar (pest) with Pratt parsing and correct operator precedence (`NOT` > `AND` > `OR`). Supports `and`, `or`, `not`, `1 of`, `all of`, `any of`, `N of`, parenthesized groups, wildcard patterns — `them` excludes `_`-prefixed identifiers per spec
- **Value types**: strings with wildcards (`*`, `?`), escape sequences (`\*`, `\?`, `\\`), integers, floats, booleans, null
- **Timespan parsing**: `15s`, `30m`, `1h`, `7d`, `1w`, `1M`, `1y`
- **Logsource**: `category`, `product`, `service`, `definition`, custom fields

### Field Modifiers (27)

| Category | Modifiers |
|----------|-----------|
| String matching | `contains`, `startswith`, `endswith` |
| Value linking | `all` |
| Encoding | `base64`, `base64offset`, `wide` / `utf16le`, `utf16be`, `utf16`, `windash` |
| Pattern | `re`, `cidr` |
| Case | `cased` |
| Existence | `exists` |
| Placeholder | `expand` |
| Field reference | `fieldref` |
| Numeric comparison | `gt`, `gte`, `lt`, `lte`, `neq` |
| Regex flags | `i` (ignore case), `m` (multiline), `s` (dotall) |
| Timestamp parts | `minute`, `hour`, `day`, `week`, `month`, `year` |

### Correlation Rules (8 types)

| Type | Description |
|------|-------------|
| `event_count` | Count matching events per group key |
| `value_count` | Count distinct field values per group key |
| `temporal` | Require multiple rules to fire in the same window |
| `temporal_ordered` | Same as temporal, but rules must fire in order |
| `value_sum` | Sum a numeric field across events |
| `value_avg` | Average a numeric field across events |
| `value_percentile` | Compute a percentile of a numeric field |
| `value_median` | Compute the median of a numeric field |

Supports threshold conditions with range predicates (e.g. `gt: 10, lte: 100`), extended boolean conditions for temporal types (e.g. `rule_a and rule_b`), field aliases for cross-rule group-by fields, and correlation chaining.

### Filter Rules

Filter rules inject `AND NOT` conditions into referenced detection rules — enables centralized exclusion management without modifying original rule files. References by rule ID or title, with optional logsource compatibility checks.

### Linter (64 rules)

64 built-in lint rules derived from the Sigma v2.1.0 specification, organized by scope:

| Scope | Count | Examples |
|-------|-------|---------|
| Infrastructure | 4 | YAML parse errors, non-mapping documents, schema violations |
| Shared metadata | 16 | Missing/empty title, missing description/author (Info), invalid UUID, invalid status/level/dates, non-lowercase keys |
| Detection rules | 17 | Missing logsource/detection/condition, invalid tags, unknown condition references |
| Correlation rules | 13 | Missing type/rules/timespan, invalid operators, non-numeric condition values |
| Filter rules | 8 | Missing filter section, filters with level/status, missing logsource |
| Detection logic | 6 | Null in value lists, single-value `\|all`, `\|all`+`\|re` conflict, wildcard-only values |

Four severity levels: **Error** (spec violation), **Warning** (best-practice issue), **Info** (soft suggestion), **Hint** (stylistic). Info/Hint findings don't cause lint failure.

Operates on raw YAML values to catch issues the parser silently ignores. Optionally validates against the official Sigma JSON schema (downloaded and cached for 7 days, with offline fallback to stale cache).

**Rule suppression** — three-tier system to disable or override lint rules:

- **CLI**: `--disable rule1,rule2` suppresses specific rules globally
- **Config file**: `.rsigma-lint.yml` with `disabled_rules` and `severity_overrides`, auto-discovered by walking ancestor directories
- **Inline comments**: `# rsigma-disable`, `# rsigma-disable rule1, rule2`, `# rsigma-disable-next-line`

```yaml
# .rsigma-lint.yml
disabled_rules:
  - missing_description
  - missing_author
severity_overrides:
  title_too_long: info
```

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

### Parser Usage

```rust
use rsigma_parser::{parse_sigma_yaml, parse_condition};

let collection = parse_sigma_yaml(yaml).unwrap();
assert_eq!(collection.rules[0].title, "Detect Whoami");

// Parse a condition expression directly
let expr = parse_condition("selection1 and not filter").unwrap();
```

---

## rsigma-eval

Compiles Sigma rules into optimized in-memory matchers and evaluates them against JSON events. Rules are compiled once; evaluation is zero-allocation on the hot path.

### Detection Engine

- **Compiled matchers**: optimized matching for all 27 modifier combinations — exact, contains, startswith, endswith, regex, CIDR, numeric comparison, base64 offset (3 alignment variants), windash expansion (5 replacement characters), field references, placeholder expansion, timestamp part extraction
- **Logsource routing**: optional pre-filtering by `category`/`product`/`service` to reduce the number of rules evaluated per event
- **Condition tree evaluation**: short-circuit boolean logic, selector patterns with quantifiers (`1 of selection_*`, `all of them`)
- **Filter application**: runtime injection of filter rules as `AND NOT` conditions on referenced rules

### Event Model

The `Event` wrapper provides flexible field access over `serde_json::Value`:

- **Dot-notation**: `actor.user.name` traverses nested objects
- **Flat-key precedence**: `"actor.user.name"` as a literal key takes priority over nested traversal
- **Array traversal**: arrays are searched with OR semantics (any element matching satisfies the check)
- **Keyword detection**: `matches_keyword` searches all string values across all fields (max nesting depth: 64)

### Correlation Engine

Stateful processing with sliding time windows, group-by aggregation, and all 8 correlation types.

**Core features:**
- **Group-by partitioning**: composite keys with field aliasing across referenced rules
- **Correlation chaining**: correlation results propagate to higher-level correlations (max depth: 10)
- **Extended temporal conditions**: boolean expressions over rule references (e.g. `rule_a and rule_b and not rule_c`)
- **Cycle detection**: DFS-based validation of the correlation reference graph at load time

**Alert management:**
- **Suppression**: per-correlation or global suppression windows to prevent alert floods. After a `(correlation, group_key)` fires, suppress re-alerts for the configured duration
- **Action-on-fire**: `alert` (keep state, re-fire on next match) or `reset` (clear window state, require fresh threshold)
- **Generate flag**: Sigma-standard `generate` support — suppress detection output for correlation-only rules

**Event inclusion** (`correlation_event_mode`):
- **Full mode**: contributing events stored as individually deflate-compressed blobs (3-5x memory savings on typical JSON)
- **Refs mode**: lightweight references (timestamp + optional event ID) at ~40 bytes per event
- **Configurable cap**: `max_correlation_events` (default: 10) bounds memory per `(correlation, group_key)` window
- **Zero cost when disabled**: buffers are not allocated unless mode is `Full` or `Refs`
- **Per-correlation override**: set `rsigma.correlation_event_mode` via `custom_attributes` in YAML

**Memory management:**
- **Max state entries**: configurable hard cap (default: 100,000) across all correlations and group keys
- **Time-based eviction**: entries outside their correlation window are evicted automatically
- **Hard-cap eviction**: when over the limit, the stalest 10% of entries are dropped to avoid evicting on every event
- **Stale alert cleanup**: expired suppression entries are garbage-collected

**Timestamp extraction:**
- **Field priority list**: configurable ordered list of fields to try (default: `@timestamp`, `timestamp`, `EventTime`, `TimeCreated`, `eventTime`)
- **Format support**: RFC 3339, `%Y-%m-%dT%H:%M:%S`, `%Y-%m-%d %H:%M:%S`, epoch seconds, epoch milliseconds (auto-detected if > 10^12)
- **Fallback policy**: `WallClock` (use `Utc::now()`, good for real-time streaming) or `Skip` (skip event from correlation, recommended for batch/replay)

### Processing Pipelines

pySigma-compatible pipeline system for field mapping, logsource transformation, and backend-specific configuration. Supports multi-pipeline chaining with priority ordering.

#### Transformations (26 types)

| Type | Description |
|------|-------------|
| `field_name_mapping` | Rename fields via a mapping dict |
| `field_name_prefix_mapping` | Rename fields matching a prefix |
| `field_name_prefix` | Add a prefix to all field names |
| `field_name_suffix` | Add a suffix to all field names |
| `field_name_transform` | Case transformation: lower, upper, title, snake_case |
| `drop_detection_item` | Remove matching detection items |
| `add_condition` | Inject additional detection conditions (with optional negation) |
| `change_logsource` | Modify logsource category/product/service |
| `replace_string` | Regex-based string replacement in values (`skip_special` preserves wildcards) |
| `map_string` | Map string values to replacements (supports one-to-many) |
| `set_value` | Replace detection item values |
| `convert_type` | Convert values to str, int, float, or bool |
| `value_placeholders` | Expand `%placeholder%` in values |
| `wildcard_placeholders` | Expand placeholders to wildcards |
| `query_expression_placeholders` | Backend query placeholders (no-op in eval) |
| `set_state` | Store key-value pairs in pipeline state |
| `rule_failure` | Raise an error for matching rules |
| `detection_item_failure` | Raise an error for matching detection items |
| `hashes_fields` | Transform hash field names |
| `add_field` | Add a new detection item with a fixed value |
| `remove_field` | Remove a field from detection items |
| `set_field` | Rename the field of a detection item |
| `set_custom_attribute` | Set key-value attributes on rules |
| `case_transformation` | Transform case of field values: lower, upper, snake_case |
| `nest` | Apply a group of transformations conditionally |
| `regex` | Regex transformation (no-op in eval) |

#### Conditions (3 levels)

| Level | Types |
|-------|-------|
| **Rule conditions** | `logsource`, `contains_detection_item`, `processing_item_applied`, `processing_state`, `is_sigma_rule`, `is_sigma_correlation_rule`, `rule_attribute`, `tag` |
| **Detection item conditions** | `match_string`, `is_null`, `processing_item_applied`, `processing_state` |
| **Field name conditions** | `include_fields`, `exclude_fields`, `processing_item_applied`, `processing_state` |

#### Finalizers (3 types)

| Type | Description |
|------|-------------|
| `concat` | Concatenate output with separator, prefix, suffix |
| `json` | Serialize output as JSON with optional indentation |
| `template` | Apply a string template to output |

### Custom Attributes (`rsigma.*`)

Pipeline transformations can configure engine behavior via `SetCustomAttribute`, following the same pattern as pySigma backends (e.g. [pySigma-backend-loki](https://github.com/grafana/pySigma-backend-loki)):

| Attribute | Effect | CLI equivalent |
|-----------|--------|----------------|
| `rsigma.timestamp_field` | Prepends a field name to the timestamp extraction priority list | `--timestamp-field` |
| `rsigma.suppress` | Sets the default suppression window (e.g. `5m`) | `--suppress` |
| `rsigma.action` | Sets the post-fire action (`alert` or `reset`) | `--action` |
| `rsigma.include_event` | Embeds the full event JSON in detection output (per-rule) | `--include-event` |

CLI flags and the library API always take precedence over pipeline attributes.

```yaml
# Example pipeline with custom attributes
transformations:
  - type: set_custom_attribute
    attribute: rsigma.timestamp_field
    value: time
  - type: set_custom_attribute
    attribute: rsigma.suppress
    value: 5m
```

### Eval Usage

**Detection only:**

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

**With correlations:**

```rust
use rsigma_eval::{CorrelationEngine, CorrelationConfig, CorrelationAction};

let config = CorrelationConfig {
    suppress: Some(300),                         // 5-minute suppression window
    action_on_match: CorrelationAction::Reset,   // clear state after firing
    emit_detections: false,                      // only emit correlation alerts
    correlation_event_mode: CorrelationEventMode::Full, // include full events (or Refs for lightweight)
    max_correlation_events: 20,                        // keep last 20 events per window
    ..Default::default()
};

let mut engine = CorrelationEngine::new(config);
engine.set_include_event(true);                  // embed event JSON in all match results
engine.add_collection(&collection).unwrap();
let result = engine.process_event_at(&event, timestamp_secs);
// result.detections: Vec<MatchResult>
// result.correlations: Vec<CorrelationResult>
// result.correlations[0].events: Option<Vec<serde_json::Value>>     (Full mode)
// result.correlations[0].event_refs: Option<Vec<EventRef>>          (Refs mode)
```

---

## rsigma-cli

### `parse` — Parse a single rule

```bash
rsigma parse rule.yml            # print AST as JSON
rsigma parse rule.yml --pretty   # pretty-print (default)
```

### `validate` — Validate rules in a directory

```bash
rsigma validate path/to/rules/ -v              # verbose output
rsigma validate rules/ -p pipelines/ecs.yml    # validate with pipeline
```

### `lint` — Lint rules against the Sigma specification

```bash
rsigma lint path/to/rules/                     # lint all rules
rsigma lint path/to/rules/ -v                  # verbose (show passing files + info-only)
rsigma lint path/to/rules/ --schema default    # + JSON schema validation (downloads + caches)
rsigma lint rule.yml --schema my-schema.json   # local JSON schema
rsigma lint path/to/rules/ --color always      # force color (respects NO_COLOR)
rsigma lint rules/ --disable missing_description,missing_author  # suppress specific rules
rsigma lint rules/ --config my-lint.yml        # explicit config file
```

### `eval` — Evaluate events against rules

**Basic evaluation:**

```bash
# Single event
rsigma eval -r path/to/rules/ -e '{"CommandLine": "whoami"}'

# Stream NDJSON from stdin
cat events.ndjson | rsigma eval -r path/to/rules/

# With processing pipeline(s) — applied in priority order
rsigma eval -r rules/ -p sysmon.yml -p custom.yml -e '...'
```

**Event extraction (jq / JSONPath):**

```bash
# Unwrap nested payloads with jq syntax
rsigma eval -r rules/ --jq '.event' -e '{"ts":"...","event":{"CommandLine":"whoami"}}'

# JSONPath (RFC 9535)
rsigma eval -r rules/ --jsonpath '$.event' -e '{"ts":"...","event":{"CommandLine":"whoami"}}'

# Array unwrapping — yields one event per element
rsigma eval -r rules/ --jq '.records[]' -e '{"records":[{"CommandLine":"whoami"},{"CommandLine":"id"}]}'

# Stream with extraction
hel run | rsigma eval -r rules/ -p ecs.yml --jq '.event'
```

**Detection output:**

```bash
# Include the full matched event JSON in detection output
rsigma eval -r rules/ --include-event -e '{"CommandLine": "whoami"}'
```

**Correlation options:**

```bash
# Suppression — deduplicate correlation alerts within a time window
rsigma eval -r rules/ --suppress 5m -e @events.ndjson

# Action on fire — reset state after alert (default: alert)
rsigma eval -r rules/ --suppress 5m --action reset -e @events.ndjson

# Include full contributing events in correlation output (compressed in memory)
rsigma eval -r rules/ --correlation-event-mode full -e @events.ndjson

# Include lightweight event references (timestamp + ID) instead
rsigma eval -r rules/ --correlation-event-mode refs -e @events.ndjson

# Cap stored events per correlation window (default: 10)
rsigma eval -r rules/ --correlation-event-mode full --max-correlation-events 20 -e @events.ndjson

# Suppress detection output (only show correlation alerts)
rsigma eval -r rules/ --no-detections -e @events.ndjson

# Custom timestamp field for correlation windowing
rsigma eval -r rules/ --timestamp-field time -e @events.ndjson
```

### `condition` — Parse a condition expression

```bash
rsigma condition 'selection and not filter'
```

### `stdin` — Parse YAML from stdin

```bash
cat rule.yml | rsigma stdin
```

---

## rsigma-lsp

A Language Server Protocol (LSP) server that brings real-time Sigma rule development support to any editor — VSCode, Neovim, Helix, Zed, Emacs, and more. Built on the same parser, linter, and compiler as the CLI.

### Features

- **Diagnostics**: real-time validation from three layers — 64 lint rules (Sigma spec v2.1.0) with four severity levels (Error/Warning/Info/Hint), parser errors (YAML and condition expressions), and compiler errors (unknown selections, invalid modifier combos). Loads `.rsigma-lint.yml` config and respects inline `# rsigma-disable` comments. Debounced at 150ms for responsive editing
- **Completions**: context-aware suggestions for field modifiers (`|contains`, `|base64`, etc.), top-level keys, status/level enums, logsource category/product/service values, detection keys, MITRE ATT&CK tags, condition keywords, and selection names from the current rule. Triggers on `|`, `:`, ` `, and newline
- **Hover**: documentation for all 27 field modifiers and MITRE ATT&CK tactics/techniques with links
- **Document symbols**: navigable outline of rule structure (title, logsource, correlation, detection with child selections)

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

**VSCode / Cursor**: A thin extension wrapper is provided in [`editors/vscode/`](editors/vscode/). To use it:

```bash
cd editors/vscode
npm install
npm run package              # builds with esbuild + creates .vsix
code --install-extension rsigma-0.1.0.vsix    # VSCode
cursor --install-extension rsigma-0.1.0.vsix  # Cursor
```

The extension launches `rsigma-lsp` from your `$PATH` by default. Override via the `rsigma.serverPath` setting.

**Helix** (`~/.config/helix/languages.toml`):

```toml
[language-server.rsigma-lsp]
command = "rsigma-lsp"

[[language]]
ame = "yaml"
language-servers = ["yaml-language-server", "rsigma-lsp"]
```

---

## Benchmarks

Criterion.rs benchmarks with synthetic rules and events (Apple M-series, single-threaded):

### Parsing

| Scenario | Time |
|----------|------|
| 1 rule | 11.7 us |
| 100 rules | 1.1 ms |
| 1,000 rules | 11.1 ms |
| Complex condition (8 selections, nested booleans) | 23.2 us |

### Detection Evaluation

| Scenario | Time | Throughput |
|----------|------|------------|
| Compile 1,000 rules | 669 us | -- |
| Compile 5,000 rules | 3.4 ms | -- |
| 1 event vs 100 rules | 4.8 us | -- |
| 1 event vs 1,000 rules | 65 us | -- |
| 1 event vs 5,000 rules | 336 us | -- |
| 100K events vs 100 rules | 458 ms | **218K events/sec** |
| Wildcard-heavy (1,000 rules, 100 events) | 5.9 ms | -- |
| Regex-heavy (1,000 rules, 100 events) | 7.3 ms | -- |

### Correlation Engine

| Scenario | Time | Throughput |
|----------|------|------------|
| 1K events, 20 event_count correlations | 727 us | **1.37M events/sec** |
| 1K events, 10 temporal correlations | 411 us | **2.43M events/sec** |
| 100K events, 50 detection + 10 correlation rules | 217 ms | **462K events/sec** |
| 50K unique group keys (state pressure) | 35.8 ms | **1.40M events/sec** |

```bash
cargo bench                          # all benchmarks
cargo bench --bench parse            # parser only
cargo bench --bench eval             # detection only
cargo bench --bench correlation      # correlations only
```

---

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
     ┌─────┴───────────────────────────────────────────────┐
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
    │    + EventBuffer (deflate-compressed)    │   │    symbols         │
    │  correlation_engine.rs ──> (stateful)    │   │                    │
    │    sliding windows, group-by, chaining,  │   │  Editors:          │
    │    alert suppression, action-on-fire,    │   │  VSCode, Neovim,   │
    │    memory management, event inclusion    │   │  Helix, Zed, ...   │
    │                                          │   └────────────────────┘
    │  rsigma.* custom attributes ─────────>   │
    │    engine config from pipelines          │
    └──────────────────────────────────────────┘
              │
              ▼
     ┌────────────────────┐
     │  MatchResult       │──> rule title, id, level, tags,
     │  CorrelationResult │   matched selections, field matches,
     └────────────────────┘   aggregated values, optional events
```

## Reference

- [pySigma](https://github.com/SigmaHQ/pySigma) — reference Python implementation
- [Sigma Specification V2.0.0](https://github.com/SigmaHQ/sigma-specification) — formal specification
- [sigma-rust](https://github.com/jopohl/sigma-rust) — Pratt parsing approach
- [sigmars](https://github.com/crowdalert/sigmars) — correlation support patterns

## License

MIT
