# rsigma-eval

[![CI](https://github.com/timescale/rsigma/actions/workflows/ci.yml/badge.svg)](https://github.com/timescale/rsigma/actions/workflows/ci.yml)

`rsigma-eval` is an evaluator for [Sigma](https://github.com/SigmaHQ/sigma) detection rules. It compiles Sigma rules into optimized in-memory matchers and evaluates them against JSON events. Rules are compiled once; evaluation is zero-allocation on the hot path.

This library is part of [rsigma].

## Detection Engine

- **Compiled matchers**: optimized matching for all 27 modifier combinations — exact, contains, startswith, endswith, regex, CIDR, numeric comparison, base64 offset (3 alignment variants), windash expansion (5 replacement characters), field references, placeholder expansion, timestamp part extraction
- **Logsource routing**: optional pre-filtering by `category`/`product`/`service` to reduce the number of rules evaluated per event
- **Condition tree evaluation**: short-circuit boolean logic, selector patterns with quantifiers (`1 of selection_*`, `all of them`)
- **Filter application**: runtime injection of filter rules as `AND NOT` conditions on referenced rules

## Event Model

The `Event` wrapper provides flexible field access over `serde_json::Value`:

- **Dot-notation**: `actor.user.name` traverses nested objects
- **Flat-khttps://github.com/timescale/rsigmae"` as a literal key takes priority over nested traversal
- **Array traversal**: arrays are searched with OR semantics (any element matching satisfies the check)
- **Keyword detection**: `matches_keyword` searches all string values across all fields (max nesting depth: 64)

## Correlation Engine

Stateful processing with sliding time windows, group-by aggregation, and all 8 correlation types.

### Core features

- **Group-by partitioning**: composite keys with field aliasing across referenced rules
- **Correlation chaining**: correlation results propagate to higher-level correlations (max depth: 10)
- **Extended temporal conditions**: boolean expressions over rule references (e.g. `rule_a and rule_b and not rule_c`)
- **Cycle detection**: DFS-based validation of the correlation reference graph at load time

### Alert management

- **Suppression**: per-correlation or global suppression windows to prevent alert floods. After a `(correlation, group_key)` fires, suppress re-alerts for the configured duration
- **Action-on-fire**: `alert` (keep state, re-fire on next match) or `reset` (clear window state, require fresh threshold)
- **Generate flag**: Sigma-standard `generate` support — suppress detection output for correlation-only rules

### Event inclusion (`correlation_event_mode`)

- **Full mode**: contributing events stored as individually deflate-compressed blobs (3-5x memory savings on typical JSON)
- **Refs mode**: lightweight references (timestamp + optional event ID) at ~40 bytes per event
- **Configurable cap**: `max_correlation_events` (default: 10) bounds memory per `(correlation, group_key)` window
- **Zero cost when disabled**: buffers are not allocated unless mode is `Full` or `Refs`
- **Per-correlation override**: set `rsigma.correlation_event_mode` via `custom_attributes` in YAML

### Memory management

- **Max state entries**: configurable hard cap (default: 100,000) across all correlations and group keys
- **Time-based eviction**: entries outside their correlation window are evicted automatically
- **Hard-cap eviction**: when over the limit, the stalest 10% of entries are dropped to avoid evicting on every event
- **Stale alert cleanup**: expired suppression entries are garbage-collected

### Timestamp extraction

- **Field priority list**: configurable ordered list of fields to try (default: `@timestamp`, `timestamp`, `EventTime`, `TimeCreated`, `eventTime`)
- **Format support**: RFC 3339, `%Y-%m-%dT%H:%M:%S`, `%Y-%m-%d %H:%M:%S`, epoch seconds, epoch milliseconds (auto-detected if > 10^12)
- **Fallback policy**: `WallClock` (use `Utc::now()`, good for real-time streaming) or `Skip` (skip event from correlation, recommended for batch/replay)

## Processing Pipelines

pySigma-compatible pipeline system for field mapping, logsource transformation, and backend-specific configuration. Supports multi-pipeline chaining with priority ordering.

### Transformations (26 types)

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

### Conditions (3 levels)

| Level | Types |
|-------|-------|
| **Rule conditions** | `logsource`, `contains_detection_item`, `processing_item_applied`, `processing_state`, `is_sigma_rule`, `is_sigma_correlation_rule`, `rule_attribute`, `tag` |
| **Detection item conditions** | `match_string`, `is_null`, `processing_item_applied`, `processing_state` |
| **Field name conditions** | `include_fields`, `exclude_fields`, `processing_item_applied`, `processing_state` |

### Finalizers (3 types)

| Type | Description |
|------|-------------|
| `concat` | Concatenate output with separator, prefix, suffix |
| `json` | Serialize output as JSON with optional indentation |
| `template` | Apply a string template to output |

## Custom Attributes (`rsigma.*`)

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

[rsigma]: https://github.com/mostafa/rsigma
