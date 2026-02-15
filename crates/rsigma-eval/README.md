# rsigma-eval

[![CI](https://github.com/timescale/rsigma/actions/workflows/ci.yml/badge.svg)](https://github.com/timescale/rsigma/actions/workflows/ci.yml)

`rsigma-eval` is an evaluator for [Sigma](https://github.com/SigmaHQ/sigma) detection rules. It compiles Sigma rules into optimized in-memory matchers and evaluates them against JSON events. Rules are compiled once; evaluation is zero-allocation on the hot path.

This library is part of [rsigma].

## Public API

### Engine

| Method | Description |
|--------|-------------|
| `Engine::new()` | Create an empty engine |
| `Engine::new_with_pipeline(pipeline)` | Create engine with an initial pipeline |
| `set_include_event(include: bool)` | Global override: include full event JSON in all match results |
| `add_pipeline(pipeline)` | Add a pipeline (sorted by `priority` after add) |
| `add_rule(rule: &SigmaRule)` | Apply pipelines and compile a rule |
| `add_collection(collection: &SigmaCollection)` | Add all rules, then apply all filters |
| `add_collection_with_pipelines(collection, pipelines)` | Temporarily replace pipelines, add collection, restore |
| `add_compiled_rule(rule: CompiledRule)` | Add a pre-compiled rule directly |
| `apply_filter(filter: &FilterRule)` | Inject filter as `AND NOT` into referenced rules |
| `evaluate(event: &Event)` | Evaluate all rules against an event |
| `evaluate_with_logsource(event, logsource)` | Evaluate with logsource-based pre-filtering |
| `rule_count()` | Number of loaded rules |
| `rules()` | Access the compiled rules slice |

### Correlation Engine

| Method | Description |
|--------|-------------|
| `CorrelationEngine::new(config)` | Create with a `CorrelationConfig` |
| `set_include_event(include: bool)` | Global override for event inclusion |
| `add_collection(collection)` | Add rules and correlations |
| `add_rule(rule: &SigmaRule)` | Add a single detection rule |
| `add_correlation(corr: &CorrelationRule)` | Add a single correlation rule |
| `process_event(event: &Event)` | Evaluate + update correlation state (wall-clock time) |
| `process_event_at(event, timestamp_secs)` | Evaluate + update state with explicit timestamp |
| `evict_expired(now)` | Manually evict expired state entries |
| `state_count()` | Number of active correlation state entries |
| `event_buffer_count()` | Total events stored across all buffers |
| `event_buffer_bytes()` | Total bytes of compressed event data |

### Compilation

| Function | Description |
|----------|-------------|
| `compile_rule(rule: &SigmaRule)` | Compile a parsed rule into a `CompiledRule` |
| `compile_detection(detection: &Detection)` | Compile a detection tree |
| `evaluate_rule(rule: &CompiledRule, event: &Event)` | Evaluate one compiled rule |
| `eval_condition(expr, detections, event, matched)` | Evaluate a condition expression tree |

### Pipeline

| Function | Description |
|----------|-------------|
| `parse_pipeline(yaml: &str)` | Parse a pipeline from a YAML string |
| `parse_pipeline_file(path: &Path)` | Parse a pipeline from a YAML file |
| `apply_pipelines(pipelines, rule)` | Apply all pipelines to a rule in priority order |
| `merge_pipelines(pipelines)` | Merge multiple pipelines into one (sorted by priority) |

## Detection Engine

- **Compiled matchers**: optimized matching for all 30 modifier combinations — exact, contains, startswith, endswith, regex, CIDR, numeric comparison, base64 offset (3 alignment variants), windash expansion (5 replacement characters), field references, placeholder expansion, timestamp part extraction
- **Logsource routing**: optional pre-filtering by `category`/`product`/`service` to reduce the number of rules evaluated per event
- **Condition tree evaluation**: short-circuit boolean logic, selector patterns with quantifiers (`1 of selection_*`, `all of them`)
- **Filter application**: runtime injection of filter rules as `AND NOT` conditions on referenced rules

### Compilation Pipeline

1. **Rule compilation** (`compile_rule`): For each named detection, call `compile_detection`. Reads `rsigma.include_event` from `custom_attributes`.
2. **Detection compilation** (`compile_detection`):
   - `AllOf` → compile each item, reject empty.
   - `AnyOf` → recursively compile each sub-detection, reject empty.
   - `Keywords` → compile each value as case-insensitive contains, combine with `AnyOf`.
3. **Value compilation** (`compile_value`): Handles modifiers in this order: `|expand` → timestamp part → `|fieldref` → `|re` → `|cidr` → numeric comparison → `|neq` → string modifiers. String modifiers: `|wide`/`|utf16le` → `|utf16be` → `|utf16` → `|base64` → `|base64offset` → `|windash` → string match.

### Compiled Matcher Types

| Matcher | Modifier | Notes |
|---------|----------|-------|
| `Exact` | (default) | Case-insensitive by default; `\|cased` makes it sensitive |
| `Contains` | `\|contains` | Substring match |
| `StartsWith` | `\|startswith` | Prefix match |
| `EndsWith` | `\|endswith` | Suffix match |
| `Regex` | `\|re` | `\|i` adds `(?i)`, `\|m` adds multiline, `\|s` adds dotall |
| `Cidr` | `\|cidr` | IP network matching via `IpNet` |
| `NumericEq/Gt/Gte/Lt/Lte` | `\|gt`, `\|gte`, etc. | f64 comparison |
| `Exists` | `\|exists` | Accepts `true`/`yes`/`false`/`no` as values |
| `FieldRef` | `\|fieldref` | Compares against another field's value |
| `Null` | — | Matches null or missing values |
| `BoolEq` | — | Boolean equality |
| `Expand` | `\|expand` | Placeholder template expansion |
| `TimestampPart` | `\|minute`, `\|hour`, `\|day`, `\|week`, `\|month`, `\|year` | Extract timestamp component, match inner value |
| `Not` | `\|neq` | Wraps inner matcher with negation |
| `AnyOf` / `AllOf` | — | Multiple values combined (OR / AND with `\|all`) |

### Value Coercion

- **Arrays**: string matchers use OR semantics (`any element matches`).
- **Numbers**: coerced to string for string matchers.
- **Booleans**: `"true"`, `"1"`, `"yes"` → true; `"false"`, `"0"`, `"no"` → false.

### Filter Rule Behavior

- Filters match by `rule.id` or `rule.title` (from `filter.rules`).
- If the filter has a `logsource`, the rule must be compatible (symmetric check).
- Empty `filter.rules` applies the filter to all rules.
- Filter detections are added as `__filter_{name}`; the condition is wrapped as `original AND NOT filter`.

### Selector Pattern Matching

- `*` — matches any detection name.
- `selection_*` — prefix match.
- `*_filter` — suffix match.
- `exact` — exact match.
- `them` — matches all names except those starting with `_`.

## Event Model

The `Event` wrapper provides flexible field access over `serde_json::Value`:

- **Flat-key precedence**: `"actor.user.name"` as a literal top-level key takes priority over nested traversal.
- **Dot-notation**: if no flat key matches and the path contains `.`, split and traverse nested objects.
- **Array traversal**: arrays are searched with OR semantics (first matching element wins).
- **Keyword detection**: `matches_keyword` searches all string values across all fields recursively.
- **Max nesting depth**: recursive traversal stops at depth **64** (`MAX_NESTING_DEPTH`).

## Correlation Engine

Stateful processing with sliding time windows, group-by aggregation, and all 8 correlation types.

### CorrelationConfig

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `timestamp_fields` | `Vec<String>` | `["@timestamp", "timestamp", "EventTime", "TimeCreated", "eventTime"]` | Field names to try for timestamp extraction, in priority order |
| `timestamp_fallback` | `TimestampFallback` | `WallClock` | `WallClock` (use `Utc::now()`) or `Skip` (skip event from correlation) |
| `max_state_entries` | `usize` | `100,000` | Hard cap across all correlations and group keys |
| `suppress` | `Option<u64>` | `None` | Default suppression window in seconds |
| `action_on_match` | `CorrelationAction` | `Alert` | `Alert` (keep state) or `Reset` (clear window state) |
| `emit_detections` | `bool` | `true` | Whether to emit detection-level matches for correlation-only rules |
| `correlation_event_mode` | `CorrelationEventMode` | `None` | `None`, `Full` (deflate-compressed), or `Refs` (timestamp + ID) |
| `max_correlation_events` | `usize` | `10` | Max events stored per `(correlation, group_key)` window |

### Core Features

- **Group-by partitioning**: composite keys with field aliasing across referenced rules
- **Correlation chaining**: correlation results propagate to higher-level correlations (max depth: **10**, `MAX_CHAIN_DEPTH`)
- **Extended temporal conditions**: boolean expressions over rule references (e.g. `rule_a and rule_b and not rule_c`)
- **Cycle detection**: DFS-based validation of the correlation reference graph at load time

### Alert Management

- **Suppression**: per-correlation or global suppression windows to prevent alert floods. After a `(correlation, group_key)` fires, suppress re-alerts for the configured duration
- **Action-on-fire**: `Alert` (keep state, re-fire on next match) or `Reset` (clear window state, require fresh threshold)
- **Generate flag**: Sigma-standard `generate` support — suppress detection output for correlation-only rules

### Event Inclusion

- **Full mode**: contributing events stored as individually deflate-compressed blobs (compression level 1, 3-5x memory savings on typical JSON)
- **Refs mode**: lightweight references (timestamp + optional event ID) at ~40 bytes per event
- **Event ID extraction** (Refs mode): tries fields in order: `id`, `_id`, `event_id`, `EventRecordID`, `event.id`
- **Configurable cap**: `max_correlation_events` bounds memory per window
- **Zero cost when disabled**: buffers are not allocated unless mode is `Full` or `Refs`
- **Per-correlation override**: set `rsigma.correlation_event_mode` via `custom_attributes` in YAML

### Memory Management

- **Max state entries**: configurable hard cap (default: 100,000) across all correlations and group keys
- **Time-based eviction**: entries outside their correlation window are evicted automatically
- **Hard-cap eviction**: when over the limit, entries are evicted until 90% of the cap is reached (the stalest 10% are dropped in bulk to avoid evicting on every event)
- **Stale alert cleanup**: expired suppression entries are garbage-collected

### Timestamp Extraction

- **Field priority list**: configurable ordered list of fields to try (default: `@timestamp`, `timestamp`, `EventTime`, `TimeCreated`, `eventTime`)
- **Format support**: RFC 3339, `%Y-%m-%dT%H:%M:%S`, `%Y-%m-%dT%H:%M:%S%.f`, `%Y-%m-%d %H:%M:%S`, epoch seconds, epoch milliseconds (auto-detected if value > 10^12)
- **Fallback policy**: `WallClock` (use `Utc::now()`, good for real-time streaming) or `Skip` (skip event from correlation, recommended for batch/replay)

### Value Percentile

`value_percentile` uses linear interpolation (C=1 method). The condition threshold represents the percentile rank (0-100), clamped to that range.

## Output Types

### MatchResult

| Field | Type | Description |
|-------|------|-------------|
| `rule_title` | `String` | Rule title |
| `rule_id` | `Option<String>` | Rule UUID |
| `level` | `Option<Level>` | Severity level |
| `tags` | `Vec<String>` | Tags |
| `matched_selections` | `Vec<String>` | Detection names that matched |
| `matched_fields` | `Vec<FieldMatch>` | Field/value pairs that contributed to the match |
| `event` | `Option<Value>` | Full event JSON when `include_event` is enabled |

### FieldMatch

| Field | Type |
|-------|------|
| `field` | `String` |
| `value` | `serde_json::Value` |

### CorrelationResult

| Field | Type | Description |
|-------|------|-------------|
| `rule_title` | `String` | Correlation rule title |
| `rule_id` | `Option<String>` | Rule UUID |
| `level` | `Option<Level>` | Severity level |
| `tags` | `Vec<String>` | Tags |
| `correlation_type` | `CorrelationType` | e.g. `event_count`, `temporal` |
| `group_key` | `Vec<(String, String)>` | Group-by field/value pairs |
| `aggregated_value` | `f64` | Computed aggregate (count, sum, avg, percentile, median) |
| `timespan_secs` | `u64` | Correlation window duration |
| `events` | `Option<Vec<Value>>` | Contributing events (Full mode) |
| `event_refs` | `Option<Vec<EventRef>>` | Event references (Refs mode) |

### EventRef

| Field | Type |
|-------|------|
| `timestamp` | `i64` |
| `id` | `Option<String>` |

## Processing Pipelines

pySigma-compatible pipeline system for field mapping, logsource transformation, and backend-specific configuration. Supports multi-pipeline chaining with priority ordering.

### Pipeline Chaining

- **Priority**: `Pipeline.priority` (default `0`); lower runs first.
- **Sorting**: pipelines are sorted by `priority` on add.
- **State isolation**: each pipeline gets its own `PipelineState`; state is not shared across pipelines.

### Transformation Item Fields

Each transformation item in a pipeline can have:

| Field | Description |
|-------|-------------|
| `id` | Identifier for `processing_item_applied` conditions |
| `rule_conditions` | All must match (AND logic) for the transformation to apply |
| `rule_cond_expression` | Logical expression over rule condition IDs (alternative to `rule_conditions`) |
| `detection_item_conditions` | Conditions on individual detection items |
| `field_name_conditions` | Conditions on field names |
| `field_name_cond_not` | Negate field name conditions |

### Transformations (26 types)

| Type | Fields | Description |
|------|--------|-------------|
| `field_name_mapping` | `mapping: {k: v}` | Rename fields via a mapping dict |
| `field_name_prefix_mapping` | `mapping: {prefix: replacement}` | Rename fields matching a prefix |
| `field_name_prefix` | `prefix` | Add a prefix to all field names |
| `field_name_suffix` | `suffix` | Add a suffix to all field names |
| `field_name_transform` | `transform_func`, `mapping` | Case transformation (see below) |
| `drop_detection_item` | — | Remove matching detection items |
| `add_condition` | `conditions: {k: v}`, `negated` (default: `false`) | Inject additional detection conditions |
| `change_logsource` | `category`, `product`, `service` | Modify logsource fields |
| `replace_string` | `regex`, `replacement`, `skip_special` (default: `false`) | Regex-based string replacement (`skip_special` preserves wildcards) |
| `map_string` | `mapping: {k: v \| [v1, v2]}` | Map string values to replacements (supports one-to-many) |
| `set_value` | `value` | Replace detection item values |
| `convert_type` | `target_type` (`str`/`int`/`float`/`bool`, default: `str`) | Convert values between types |
| `value_placeholders` | — | Expand `%placeholder%` in values |
| `wildcard_placeholders` | — | Expand placeholders to wildcards |
| `query_expression_placeholders` | `expression` (default: `""`) | Backend query placeholders (no-op in eval) |
| `set_state` | `key`, `value` | Store key-value pairs in pipeline state |
| `rule_failure` | `message` (default: `"rule failure"`) | Raise an error for matching rules |
| `detection_item_failure` | `message` (default: `"detection item failure"`) | Raise an error for matching detection items |
| `hashes_fields` | `valid_hash_algos`, `field_prefix` (default: `"File"`), `drop_algo_prefix` (default: `false`) | Transform hash field names |
| `add_field` | `field` | Add a new detection item with a fixed value |
| `remove_field` | `field` | Remove a field from detection items |
| `set_field` | `fields: [...]` | Rename the field of a detection item |
| `set_custom_attribute` | `attribute`, `value` | Set key-value attributes on rules |
| `case_transformation` | `case_type` / `case` (`lower`/`upper`/`snake_case`) | Transform case of field values |
| `nest` | `items` or `transformations` | Apply a group of transformations conditionally |
| `regex` | — | Regex transformation (no-op in eval) |

**Aliases**: `case` is accepted as an alias for `case_transformation`.

#### `field_name_transform` Functions

| Value | Behavior |
|-------|----------|
| `lower` / `lowercase` | `to_lowercase` |
| `upper` / `uppercase` | `to_uppercase` |
| `title` | Capitalize each word, join with `_` (e.g. `hello_world` → `Hello_World`) |
| `snake_case` | camelCase → snake_case |

### Conditions (3 levels)

#### Rule Conditions

| Type | Fields |
|------|--------|
| `logsource` | `category`, `product`, `service` |
| `contains_detection_item` | `field`, `value` (optional) |
| `processing_item_applied` | `processing_item_id` |
| `processing_state` | `key`, `val` |
| `is_sigma_rule` | — |
| `is_sigma_correlation_rule` | — |
| `rule_attribute` | `attribute` (`level`/`status`/`author`/`title`/`id`/`date`/`description`), `value` |
| `tag` | `tag` |

#### Detection Item Conditions

| Type | Fields |
|------|--------|
| `match_string` | `pattern` (default: `".*"`), `negate` (default: `false`) |
| `is_null` | `negate` |
| `processing_item_applied` | `processing_item_id` |
| `processing_state` | `key`, `val` |

#### Field Name Conditions

| Type | Fields |
|------|--------|
| `include_fields` | `fields`, `match_type` (`plain` or `regex`, default: `plain`) |
| `exclude_fields` | `fields`, `match_type` |
| `processing_item_applied` | `processing_item_id` |
| `processing_state` | `key`, `val` |

### Finalizers (3 types)

| Type | Fields | Defaults |
|------|--------|----------|
| `concat` | `separator`, `prefix`, `suffix` | `" "`, `""`, `""` |
| `json` | `indent` | — |
| `template` | `template` | `""` |

Finalizers are stored in the pipeline but not executed in eval mode.

## Custom Attributes (`rsigma.*`)

Pipeline transformations can configure engine behavior via `SetCustomAttribute`, following the same pattern as pySigma backends (e.g. [pySigma-backend-loki](https://github.com/grafana/pySigma-backend-loki)):

| Attribute | Effect | CLI equivalent | Scope |
|-----------|--------|----------------|-------|
| `rsigma.timestamp_field` | Prepends a field name to the timestamp extraction priority list | `--timestamp-field` | Engine |
| `rsigma.suppress` | Sets the suppression window (e.g. `5m`) | `--suppress` | Engine + per-correlation |
| `rsigma.action` | Sets the post-fire action (`alert` or `reset`) | `--action` | Engine + per-correlation |
| `rsigma.include_event` | Embeds the full event JSON in detection output | `--include-event` | Per-rule |
| `rsigma.correlation_event_mode` | Sets event inclusion mode (`full` or `refs`) | `--correlation-event-mode` | Per-correlation |
| `rsigma.max_correlation_events` | Caps stored events per correlation window (integer) | `--max-correlation-events` | Per-correlation |

CLI flags and the library API always take precedence over pipeline attributes. Engine-level attributes (`timestamp_field`, `suppress`, `action`) are only applied when the CLI did not already set the corresponding flag. Per-correlation attributes override engine defaults for individual correlation rules.

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

## Constants and Limits

| Constant | Value | Purpose |
|----------|-------|---------|
| `MAX_NESTING_DEPTH` | 64 | Recursive JSON traversal depth for keyword search |
| `MAX_WINDASH_DASHES` | 8 | Maximum dash characters expanded by windash (5^8 variants) |
| `WINDASH_CHARS` | 5 | `-`, `/`, `–` (en-dash), `—` (em-dash), `―` (horizontal bar) |
| `MAX_CHAIN_DEPTH` | 10 | Maximum correlation chaining depth |
| `max_state_entries` | 100,000 | Default hard cap for correlation state |
| Eviction target | 90% | Hard-cap eviction drops the stalest 10% |
| `max_correlation_events` | 10 | Default per-window event cap |
| Epoch threshold | 10^12 | Numeric timestamps above this are treated as milliseconds |

## Error Types

| Error | When |
|-------|------|
| `InvalidRegex` | Regex compilation failure |
| `InvalidCidr` | CIDR parse failure |
| `Base64` | Base64 encoding error |
| `UnknownDetection` | Condition references missing detection |
| `InvalidModifiers` | Invalid modifier combo, empty AllOf/AnyOf, windash overflow, pipeline failure |
| `IncompatibleValue` | Wrong type for modifier (e.g. null for string) |
| `ExpectedNumeric` | Numeric modifier with non-numeric value |
| `Parser` | Parser error (from rsigma-parser) |
| `CorrelationError` | Correlation compile/runtime error |
| `TimestampParse` | Timestamp parse failure |
| `UnknownRuleRef` | Correlation references unknown rule |
| `CorrelationCycle` | Cycle in correlation references |

## Usage

**Detection only:**

```rust
use rsigma_parser::parse_sigma_yaml;
use rsigma_eval::{Engine, Event, parse_pipeline};
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
use rsigma_eval::{CorrelationEngine, CorrelationConfig, CorrelationAction, CorrelationEventMode};

let config = CorrelationConfig {
    suppress: Some(300),                         // 5-minute suppression window
    action_on_match: CorrelationAction::Reset,   // clear state after firing
    emit_detections: false,                      // only emit correlation alerts
    correlation_event_mode: CorrelationEventMode::Full, // include full events
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

## Benchmarks

Criterion.rs benchmarks with synthetic rules and events (Apple M-series, single-threaded):

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
cargo bench --bench eval
cargo bench --bench correlation
```

## License

MIT License.

[rsigma]: https://github.com/timescale/rsigma
