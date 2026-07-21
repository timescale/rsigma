# `rsigma-eval`

The detection and correlation engine. Compiles parsed Sigma rules into a matcher tree (via the [`rsigma-ir`](ir.md) HIR), evaluates events against them, runs correlation windows, and applies processing pipelines.

- [docs.rs/rsigma-eval](https://docs.rs/rsigma-eval)
- [README](https://github.com/timescale/rsigma/blob/main/crates/rsigma-eval/README.md)
- [crates.io/crates/rsigma-eval](https://crates.io/crates/rsigma-eval)

## When to use

- Run rules against events in an in-process embedding (no daemon, no I/O).
- Build a custom front-end on top of the engine (different input format, different sink shape).
- Reuse the matcher optimizer, pipeline machinery, or correlation engine in another tool.

For streaming I/O (stdin / HTTP / NATS / OTLP), source resolution, and hot-reload, layer [`rsigma-runtime`](runtime.md) on top.

## Install

```toml
[dependencies]
rsigma-parser = "{{ rsigma.version }}"
rsigma-eval = "{{ rsigma.version }}"
serde_json = "1"   # only if you use the JsonEvent shim
```

| Feature | Default | Effect |
|---------|---------|--------|
| `parallel` | off (rsigma-cli turns it on) | `rayon`-based parallel batch evaluation via `Engine::evaluate_batch_parallel`. |
| `daachorse-index` | off | Cross-rule Aho-Corasick pre-filter. See [Performance Tuning](../guide/performance-tuning.md#cross-rule-aho-corasick-pre-filter). |

## Public surface

| Type | Purpose |
|------|---------|
| `Engine` | Stateless detection engine. Holds compiled rules and (optionally) the pre-filter indexes. |
| `CorrelationEngine` | Stateful engine that wraps `Engine` and adds the sliding-window correlation state. Use this when any rule in the collection is a correlation rule. |
| `CorrelationConfig` | Limits on correlation state (`max_state_entries`, `max_event_buffer`). Default `100_000` and `10_000`. |
| `Pipeline` | Parsed processing pipeline. Applied to rules at `add_collection` time, in priority order. |
| `pipeline::parse_pipeline(&str) -> Result<Pipeline>` | Parse a pipeline YAML string. |
| `LogSourceExtractor` | Derives an event's `LogSource` from configurable fields plus optional static defaults, for conflict-based logsource pruning. Pass to `Engine::set_logsource_extractor`. |
| `Event` trait + `JsonEvent`, `KvEvent`, `MapEvent`, `PlainEvent` | The event shapes the engine consumes. |
| `EvaluationResult` | One detection match or correlation firing. Composes a `RuleHeader` (rule metadata, custom attributes, optional enrichments) and a `ResultBody::Detection(DetectionBody)` / `ResultBody::Correlation(CorrelationBody)` payload. Serializes to one flat JSON object per result. |
| `RuleHeader`, `DetectionBody`, `CorrelationBody` | The three composable structs behind `EvaluationResult`. `RuleHeader` carries the fields shared between kinds (`rule_title`, `rule_id`, `level`, `tags`, `custom_attributes`, and an optional `enrichments` map); the body variants carry the kind-specific fields. |
| `ResultBody` | `#[serde(untagged)]` enum that picks the kind-specific payload. Use `EvaluationResult::as_detection() / as_correlation()` accessors or pattern match on `result.body` to read its fields. |
| `ProcessResult` | Alias for `Vec<EvaluationResult>`. The `CorrelationEngine::process_event` return: every result for an event, detections first then correlations, in evaluation order. |
| `ProcessResultExt` | Extension trait on `[EvaluationResult]` exposing `detections()` / `correlations()` iterators and `detection_count()` / `correlation_count()`. Bring this into scope when you want kind-filtered iteration without pattern matching. |
| `CompiledMatcher`, `CompiledRule` | Internal matcher tree types; consume via the AST conversion or build them yourself for an alternative front-end. |

The full enum of modifiers, the matcher-optimizer constants, the `rsigma.*` custom-attribute table, and the bloom/cross-rule prefilters live in [the crate README](https://github.com/timescale/rsigma/blob/main/crates/rsigma-eval/README.md).

## Minimum example: detection only

```rust
use rsigma_eval::{Engine, JsonEvent};
use rsigma_parser::parse_sigma_yaml;
use serde_json::json;

let yaml = r#"
title: Whoami
id: 8b1d8c97-5b3a-4d77-9b48-7c5f7c8b1a2a
logsource: { product: windows, category: process_creation }
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
level: medium
"#;

let collection = parse_sigma_yaml(yaml)?;
let mut engine = Engine::new();
engine.add_collection(&collection)?;

let event = json!({ "CommandLine": "cmd /c whoami" });
let matches = engine.evaluate(&JsonEvent::borrow(&event));

assert_eq!(matches.len(), 1);
assert_eq!(matches[0].header.rule_title, "Whoami");
```

## With a pipeline

`Pipeline` applies before compilation. The CLI's `-p` flag wires this up; in code:

```rust
use rsigma_eval::Engine;
use rsigma_eval::pipeline::parse_pipeline;
use rsigma_parser::parse_sigma_yaml;

let pipeline = parse_pipeline(r#"
name: ecs_windows
priority: 20
transformations:
  - id: ecs_fields
    type: field_name_mapping
    mapping:
      CommandLine: process.command_line
    rule_conditions:
      - type: logsource
        product: windows
"#)?;

let collection = parse_sigma_yaml(rule_yaml)?;

let mut engine = Engine::new();
engine.add_pipeline(pipeline);   // priority sorted; multiple allowed
engine.add_collection(&collection)?;
```

After this, the rule sees ECS field names; an event with `process.command_line` matches.

## Correlation

For stateful detections, use `CorrelationEngine` instead of the bare `Engine`. It owns both the rule set and the sliding-window state:

```rust
use rsigma_eval::{CorrelationConfig, CorrelationEngine, JsonEvent, ProcessResultExt};
use rsigma_parser::parse_sigma_yaml;

let collection = parse_sigma_yaml(yaml)?;

let mut correlator = CorrelationEngine::new(CorrelationConfig::default());
correlator.add_collection(&collection)?;

for raw in events {
    let evt = JsonEvent::borrow(&raw);
    let result = correlator.process_event(&evt);
    for m in result.detections() { /* detection match */ }
    for c in result.correlations() { /* correlation firing */ }
}
```

`process_with_detections(event, Vec<EvaluationResult>)` is the lower-overhead variant for hot loops (pre-compute detections in parallel, feed sequentially to correlation). `CorrelationConfig` enforces `max_state_entries` (default 100,000) and the 10-deep correlation-chain limit; see [Security Hardening](../reference/security.md#input-size-and-depth-caps).

## Custom attributes

Pipeline transformations can write `rsigma.*` attributes that the engine consumes (`include_event`, `correlation_event_mode`, `max_correlation_events`, …). Full table in [Custom Attributes](../reference/custom-attributes.md).

## Performance knobs

| Method | Effect |
|--------|--------|
| `Engine::set_bloom_prefilter(bool)` | Toggle the per-field bloom trigram filter over positive substring needles. Pays off only when most events do not match any pattern. |
| `Engine::set_bloom_max_bytes(usize)` | Per-engine bloom budget. Default 1 MiB. |
| `Engine::set_cross_rule_ac(bool)` | Toggle the cross-rule Aho-Corasick pre-filter. Requires the `daachorse-index` feature. Pays off only on very large pure-substring rule sets. |
| `Engine::set_logsource_extractor(Option<LogSourceExtractor>)` | Opt into conflict-based logsource pruning: skip rules whose `product`/`service`/`category` (and custom dimensions) conflict with the event's. Off by default, fail-open. Pays off on large mixed-product rule sets. |
| `Engine::evaluate_pruned(&event, &LogSource)` | Evaluate with a caller-resolved event logsource for conflict-based pruning, bypassing the engine's own extractor. Used by `SchemaRouter` to feed a per-event logsource resolved from explicit fields plus the recognized schema's implied logsource. |
| `Engine::evaluate_batch(&[events])` (with `parallel`) | Batch evaluation. With the `parallel` feature, rayon parallelizes across events internally. |
| `Engine::save_hir()` / `load_hir(&[u8])` | Serialize the engine's lowered rules to a versioned HIR cache blob and rebuild from one, a restart cache that skips parse, pipeline, and lowering. Captures rules added via the parsed-rule paths in post-pipeline, pre-filter form; re-apply filters after `load_hir`. Backed by [`rsigma-ir`](ir.md)'s `cache`. |

Schema classification and routing live alongside the engine: `SchemaClassifier::classify` and `classify_with_ambiguity` recognize an event's schema from declarative `SchemaSignature` predicates, `explain` reports why, and `validate_schema_config` statically checks a config. `SchemaRouter` builds one engine per pipeline-set, routes each event to its schema's engine (deriving the event's logsource from the schema for pruning), feeds one shared correlation store, and reports a per-schema pruning summary via `schema_pruning_summary`. See the [Schema Signatures reference](../reference/schema-signatures.md) and the [Schema Routing](../guide/schema-routing.md) guide.

`Engine::add_rule` and `add_compiled_rule` are amortized O(1) per call (v0.12.0+), so a control-plane that ingests rules one at a time no longer pays an O(N) cost on every push. The bulk loaders (`add_rules`, `extend_compiled_rules`, `add_collection`) rebuild indexes exactly once per batch. If you enable `set_cross_rule_ac(true)`, prefer the bulk loaders since the daachorse automaton has no incremental update.

Decision matrix in [Performance Tuning](../guide/performance-tuning.md). Verified Criterion numbers in [Benchmarks](../benchmarks.md).

## Error handling

`EvalError` from `thiserror`. Variants include `Parser` (re-exports the parser errors), `InvalidRegex`, `InvalidCidr`, `InvalidModifiers`, `UnknownRuleRef` (correlation references a rule that wasn't added), `CorrelationCycle`, and `Base64`. Each carries enough context to point operators at the offending rule.

## See also

- [Architecture](../reference/architecture.md) for how `Engine` and `CorrelationEngine` fit into the broader runtime.
- [Performance Tuning](../guide/performance-tuning.md) for the bloom and cross-rule AC knobs.
- [`rsigma-runtime`](runtime.md) for the streaming-runtime layer that wraps this crate.
- [Custom Attributes](../reference/custom-attributes.md) for the `rsigma.*` namespace this crate consumes.
- [`rsigma-eval` README](https://github.com/timescale/rsigma/blob/main/crates/rsigma-eval/README.md) for the full API surface.
- [docs.rs/rsigma-eval](https://docs.rs/rsigma-eval).
