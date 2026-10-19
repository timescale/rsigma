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
| `parallel` | off (rsigma-cli turns it on) | `rayon`-based parallel batch evaluation inside `Engine::evaluate_batch`. |
| `daachorse-index` | off | Cross-rule Aho-Corasick pre-filter. See [Performance Tuning](../guide/performance-tuning.md#cross-rule-aho-corasick-pre-filter). |

## Public surface

| Type | Purpose |
|------|---------|
| `Engine` | Stateless detection engine. Holds compiled rules and (optionally) the pre-filter indexes. |
| `CorrelationEngine` | Stateful engine that wraps `Engine` and adds the sliding-window correlation state. Use this when any rule in the collection is a correlation rule. |
| `CorrelationConfig` | Correlation engine settings: state limits (`max_state_entries`, default `100_000`; `max_group_entries`, default unbounded), timestamp extraction, suppression, post-fire action, event inclusion (`correlation_event_mode`, `max_correlation_events`, default `10`), and output. `emit_detections` defaults to `false`, so a rule referenced only by correlations without `generate: true` produces no standalone result; set it to `true` to emit every detection and correlation match. {{ added "0.24.0" }} |
| `Pipeline` | Parsed processing pipeline. Applied to rules at `add_collection` time, in priority order. |
| `ConditionSet<T>` | One pipeline condition scope: identifier-keyed conditions, `and`/`or` linking, optional negation, and an optional expression. `TransformationItem` has one set each for rule, detection-item, and field-name conditions. {{ added "0.24.0" }} |
| `pipeline::parse_pipeline(&str) -> Result<Pipeline>` | Parse a pipeline YAML string. |
| `pipeline::sources::scan_source_templates(&str)` | Find every `${source.<id>}` and `${source.<id>.<path>}` template in a string, with its id, path, and byte offset. It is the single reference grammar shared by pipeline parsing and `rsigma-runtime`'s expansion. `is_valid_source_id` checks the id character set (ASCII letters, digits, `_`, `-`) that source declarations must use. {{ added "0.25.0" }} |
| `TransformedRule` + `transform_rule` / `transform_collection` | Apply pipelines and hand back the rewritten rule, the transformation ids that fired, and the merged `PipelineState`, without compiling or loading. `Engine::transform_rule` / `Engine::transform_collection` do the same over an engine's configured pipelines. |
| `apply_filters(&SigmaCollection) -> Vec<SigmaRule>` | Merge each filter into the detection rules it targets, as pySigma does when a collection loads, and return the rules for pipelines to transform. Filters target rules the same way `Engine::apply_filter` does. Conversion uses it. {{ added "0.24.0" }} |
| `LogSourceExtractor` | Derives an event's `LogSource` from configurable fields plus optional static defaults, for conflict-based logsource pruning. Pass to `Engine::set_logsource_extractor`. |
| `ExtractLogSource<E: Event>` | Trait behind logsource pruning, with one method, `extract(&self, &E) -> LogSource`. `LogSourceExtractor` implements it for every event type. Implement it for your own event type to prune by logsource carried outside the matchable fields, such as metadata beside the payload. See [Custom logsource extractors](#custom-logsource-extractors). {{ added "0.25.0" }} |
| `Event` trait + `JsonEvent`, `KvEvent`, `MapEvent`, `PlainEvent` | The event shapes the engine consumes. `JsonEvent::into_value` unwraps the JSON value, cloning only when the event borrows it. {{ added "0.25.0" }} |
| `EvaluationResult` | One detection match or correlation firing. Composes a `RuleHeader` (rule metadata, custom attributes, optional enrichments) and a `ResultBody::Detection(DetectionBody)` / `ResultBody::Correlation(CorrelationBody)` payload. Serializes to one flat JSON object per result. |
| `RuleHeader`, `DetectionBody`, `CorrelationBody` | The three composable structs behind `EvaluationResult`. `RuleHeader` carries the fields shared between kinds (`rule_title`, `rule_id`, `level`, `tags`, `custom_attributes`, and an optional `enrichments` map); the body variants carry the kind-specific fields. |
| `ResultBody` | `#[serde(untagged)]` enum that picks the kind-specific payload. Use `EvaluationResult::as_detection() / as_correlation()` accessors or pattern match on `result.body` to read its fields. |
| `ProcessResult` | Alias for `Vec<EvaluationResult>`. The `CorrelationEngine::process_event` return: every result for an event, detections first then correlations, in evaluation order. |
| `ProcessResultExt` | Extension trait on `[EvaluationResult]` exposing `detections()` / `correlations()` iterators and `detection_count()` / `correlation_count()`. Bring this into scope when you want kind-filtered iteration without pattern matching. |
| `CompiledMatcher`, `CompiledRule` | Internal matcher tree types; consume via the AST conversion or build them yourself for an alternative front-end. |
| `draft_rule`, `DraftConfig`, `DraftReport` | Profile positive exemplars against an optional baseline and emit a verified detection-rule draft. |
| `rule_draft::correlation::{draft_correlation, GroupedExemplar, TimedEvent, CorrelationDraftConfig, CorrelationDraftReport}` | Infer recurring slots, entity, order, and window from grouped timed exemplars, then emit and verify a multi-document temporal correlation. |
| `explain_rule`, `RuleExplanation`, `ConditionTrace`, `DetectionTrace`, `ArrayMemberTrace`, `ArrayEmptyReason`, `ItemTrace`, `MatchReason` | Non-short-circuiting recording evaluator behind `engine explain`. `DetectionTrace::ArrayMatch` records per-member traces; `Conditional` covers extended array bodies. |

The full enum of modifiers, the matcher-optimizer constants, the `rsigma.*` custom-attribute table, and the bloom/cross-rule prefilters live in [the crate README](https://github.com/timescale/rsigma/blob/main/crates/rsigma-eval/README.md).

`Transformation::SetState.value` is a `serde_json::Value`, preserving numeric and boolean pipeline state for typed `processing_state` comparisons. Code that previously constructed it with a `String` should use `serde_json::Value::String`. {{ added "0.24.0" }}

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

## Reading the rule a pipeline produced

`add_collection` discards the rewritten Sigma AST and keeps only the compiled rules, so a caller that needs to act on what a pipeline decided asks for the rewrite explicitly. The common case is a collector that subscribes to log channels: rather than hardcoding a second copy of the pipeline's category-to-channel mapping, read the `logsource` the pipeline rewrote.

```rust
use rsigma_eval::{Engine, transform_collection};
use rsigma_eval::pipeline::parse_pipeline;
use rsigma_parser::parse_sigma_yaml;

let pipelines = vec![parse_pipeline(&pipeline_yaml)?];
let collection = parse_sigma_yaml(&rule_yaml)?;

let mut channels = std::collections::BTreeSet::new();
for transformed in transform_collection(&pipelines, &collection)? {
    if let Some(service) = &transformed.rule.logsource.service {
        channels.insert(service.clone());
    }
    // `transformed.applied_items` lists the ids of the transformations that
    // fired, so you can tell "nothing matched" from "matched and rewrote".
}

// The originals are unchanged, so load them normally.
let mut engine = Engine::new();
for pipeline in pipelines {
    engine.add_pipeline(pipeline);
}
engine.add_collection(&collection)?;
```

`TransformedRule` also carries `state`, the merged `PipelineState`, which is where `set_state` and `query_expression_placeholders` values land.

Both functions clone and re-run the pipelines, the same work `add_collection` does, so they belong on the load or reload path and not on the per-event path. If only the logsource matters, `Engine::rules()` after loading is cheaper: each `CompiledRule` retains its post-pipeline `logsource`.

They also apply pipelines in slice order rather than by `priority`, matching `apply_pipelines`. Pass the slice through `merge_pipelines` when chaining several, or use `Engine::transform_collection`, which uses the engine's already-sorted pipelines.

## Rule tuning

`tune_rule(rule, false_positives, true_positives, config)` accepts one parsed, optionally pipeline-transformed `SigmaRule` plus JSON event values. It verifies that every label fires before filtering, profiles reusable value forms from the FP set, rejects candidates that match a TP, emits a standard filter rule, and verifies the final artifact through `Engine::add_collection`.

`TuneConfig` bounds minimum and maximum field count, OR-list cardinality, inferred token length, cluster support, and cluster count. `TuneReport` contains the paste-ready YAML, ranked field rationale, emitted selections, FP coverage, warnings, and closed before/after counts. `TuneError::NoCleanSeparator` is returned instead of an unsafe filter when the corpora cannot be separated.

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

`process_with_detections(event, Vec<EvaluationResult>, timestamp_secs)` is the lower-overhead variant for hot loops (pre-compute detections in parallel, feed sequentially to correlation). `CorrelationConfig` enforces `max_state_entries` (default 100,000) and the 10-deep correlation-chain limit; see [Security Hardening](../reference/security.md#input-size-and-depth-caps). A correlation whose `rules:` list other correlations (for example a `temporal` of two `event_count` rules) emits the parent result when the chain condition is met, the same way a temporal of detections does. The referenced child correlations update the parent's state but are output only when a referencing correlation has `generate: true` or `emit_detections` is on. {{ added "0.24.0" }}

An `EvaluationResult` carries the rule `id` but not its `name`, so `process_with_detections` and `correlate_detections` match a detection from a rule without an `id` to its rule by title. When two such rules share a title, neither feeds the correlations that reference it by `name`. Give those rules unique titles, or use `process_event`, `process_event_at`, or `process_batch`, which evaluate detections themselves and keep each compiled rule's `id` and `name`. {{ added "0.24.0" }}

`rule_draft::correlation::draft_correlation` accepts positive and negative `GroupedExemplar` collections, an optional flat baseline, and `CorrelationDraftConfig`. Each `TimedEvent` carries exactly one RFC3339 timestamp or Sigma offset plus a JSON event. The result contains paste-ready YAML, inferred grouping/order/window evidence, per-slot support, gap distributions, warnings, and the isolated verification matrix. Caller-supplied ids keep the library deterministic; command-line callers generate UUIDs.

## Custom attributes

Pipeline transformations can write `rsigma.*` attributes that the engine consumes (`include_event`, `correlation_event_mode`, `max_correlation_events`, …). Full table in [Custom Attributes](../reference/custom-attributes.md).

## Performance knobs

| Method | Effect |
|--------|--------|
| `Engine::set_bloom_prefilter(bool)` | Toggle the per-field bloom trigram filter over positive substring needles. Pays off only when most events do not match any pattern. |
| `Engine::set_bloom_max_bytes(usize)` | Per-engine bloom budget. Default 1 MiB. |
| `Engine::set_cross_rule_ac(bool)` | Toggle the cross-rule Aho-Corasick pre-filter. Requires the `daachorse-index` feature. Pays off only on very large pure-substring rule sets. |
| `Engine::set_logsource_extractor(Option<LogSourceExtractor>)` | Opt into conflict-based logsource pruning: skip rules whose `product`/`service`/`category` (and custom dimensions) conflict with the event's. Off by default, fail-open. Pays off on large mixed-product rule sets. |
| `Engine::with_logsource_extractor(extractor)` | Create an empty engine that prunes with a custom `ExtractLogSource` implementation. {{ added "0.25.0" }} |
| `Engine::evaluate_pruned(&event, &LogSource)` | Evaluate with a caller-resolved event logsource for conflict-based pruning, bypassing the engine's own extractor. Used by `SchemaRouter` to feed a per-event logsource resolved from explicit fields plus the recognized schema's implied logsource. |
| `Engine::evaluate_batch(&[events])` (with `parallel`) | Batch evaluation. With the `parallel` feature, rayon parallelizes across events internally. |
| `Engine::set_retain_hir(bool)` | Keep each loaded rule's HIR so `save_hir` can write it. Off by default, since nothing on the evaluation path reads it; enable it before loading rules. {{ added "0.25.0" }} |
| `Engine::save_hir()` / `load_hir(&[u8])` | Serialize the engine's lowered rules to a versioned HIR cache blob and rebuild from one, a restart cache that skips parse, pipeline, and lowering. Captures rules added via the parsed-rule paths in post-pipeline, pre-filter form; re-apply filters after `load_hir`. `save_hir` returns `EvalError::HirCache` unless `set_retain_hir(true)` was on for every such rule. Backed by [`rsigma-ir`](ir.md)'s `cache`. |

Schema classification and routing live alongside the engine: `SchemaClassifier::classify` and `classify_with_ambiguity` recognize an event's schema from declarative `SchemaSignature` predicates, `explain` reports why, and `validate_schema_config` statically checks a config. `SchemaRouter` builds one engine per pipeline-set, routes each event to its schema's engine (deriving the event's logsource from the schema for pruning), feeds one shared correlation store, and reports a per-schema pruning summary via `schema_pruning_summary`. See the [Schema Signatures reference](../reference/schema-signatures.md) and the [Schema Routing](../guide/schema-routing.md) guide.

`Engine::add_rule` and `add_compiled_rule` are amortized O(1) per call (v0.12.0+), so a control-plane that ingests rules one at a time no longer pays an O(N) cost on every push. The bulk loaders (`add_rules`, `extend_compiled_rules`, `add_collection`) rebuild indexes exactly once per batch. If you enable `set_cross_rule_ac(true)`, prefer the bulk loaders since the daachorse automaton has no incremental update.

Decision matrix in [Performance Tuning](../guide/performance-tuning.md). Verified Criterion numbers in [Benchmarks](../benchmarks.md).

### Custom logsource extractors

{{ added "0.25.0" }}

`LogSourceExtractor` reads the event's logsource from its fields. When your event type carries the logsource somewhere else, such as metadata from a transport envelope, implement `ExtractLogSource` for that type. `Engine`, `CorrelationEngine`, and `SchemaRouter` are generic over the extractor type, which defaults to `LogSourceExtractor`, so existing code keeps compiling. The extractor runs once per event with static dispatch.

```rust
use rsigma_eval::{CorrelationConfig, CorrelationEngine, Engine, ExtractLogSource};
use rsigma_parser::LogSource;

struct MetadataExtractor;

impl ExtractLogSource<MyEvent> for MetadataExtractor {
    fn extract(&self, event: &MyEvent) -> LogSource {
        LogSource {
            product: event.metadata.product.clone(),
            ..LogSource::default()
        }
    }
}

let engine = Engine::with_logsource_extractor(MetadataExtractor);
let correlation =
    CorrelationEngine::with_logsource_extractor(CorrelationConfig::default(), MetadataExtractor);
```

Leave a dimension `None` when the extractor cannot determine it. An unset dimension is a wildcard, so pruning stays fail-open. Build a router with `SchemaRouter::build_with_logsource_extractor`, which takes the same arguments as `SchemaRouter::build` except the extractor. The recognized schema's implied logsource still fills any dimension the extractor leaves unset.

Prefer an extractor over computing the logsource yourself and calling `evaluate_pruned`. `process_event`, `process_event_at`, and `process_batch` keep each compiled rule's `id` and `name`. When detections are precomputed and fed to `process_with_detections` or `correlate_detections`, a detection from a rule without an `id` is matched to its rule by title, as described above.

## Error handling

`EvalError` from `thiserror`. Variants include `Parser` (re-exports the parser errors), `InvalidRegex`, `InvalidCidr`, `IncompatibleValue` (a value the modifier cannot use, such as a `cidr` with host bits set), `InvalidModifiers`, `UnknownRuleRef` (correlation references a rule that wasn't added), `CorrelationCycle`, and `Base64`. Each carries enough context to point operators at the offending rule.

Processing pipelines that fail to parse or validate, or that fail while being applied to a rule (including a deliberate `rule_failure` or `detection_item_failure`), return `EvalError::Pipeline`. The enum is `#[non_exhaustive]`, so a `match` on it needs a wildcard arm. {{ added "0.25.0" }}

## See also

- [Architecture](../reference/architecture.md) for how `Engine` and `CorrelationEngine` fit into the broader runtime.
- [Performance Tuning](../guide/performance-tuning.md) for the bloom and cross-rule AC knobs.
- [`rsigma-runtime`](runtime.md) for the streaming-runtime layer that wraps this crate.
- [Custom Attributes](../reference/custom-attributes.md) for the `rsigma.*` namespace this crate consumes.
- [`rsigma-eval` README](https://github.com/timescale/rsigma/blob/main/crates/rsigma-eval/README.md) for the full API surface.
- [docs.rs/rsigma-eval](https://docs.rs/rsigma-eval).
