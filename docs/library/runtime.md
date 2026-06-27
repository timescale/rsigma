# `rsigma-runtime`

The streaming runtime. Wraps `rsigma-eval` in an async pipeline with input adapters, sinks, hot-reload, dynamic source resolution, and pluggable metrics.

- [docs.rs/rsigma-runtime](https://docs.rs/rsigma-runtime)
- [README](https://github.com/timescale/rsigma/blob/main/crates/rsigma-runtime/README.md)
- [crates.io/crates/rsigma-runtime](https://crates.io/crates/rsigma-runtime)

## When to use

- Embed the daemon shape into a larger Rust program (alternate front-end, sidecar, custom orchestrator).
- Reuse the input parsers (JSON, syslog, logfmt, CEF, EVTX) or the dynamic-source resolver outside the daemon.
- Build a custom event sink that the engine writes to.

For a one-shot evaluation against in-memory events, you do not need this crate; use [`rsigma-eval`](eval.md) directly. For the supported daemon binary, `cargo install rsigma --features daemon`.

## Install

```toml
[dependencies]
rsigma-parser = "{{ rsigma.version }}"
rsigma-eval = "{{ rsigma.version }}"
rsigma-runtime = "{{ rsigma.version }}"
tokio = { version = "1", features = ["full"] }
```

| Feature | Effect |
|---------|--------|
| `nats` | NATS JetStream as an event source, sink, and dynamic-pipeline source. |
| `otlp` | OTLP/HTTP and OTLP/gRPC log decoding (`opentelemetry-proto`, `prost`). |
| `logfmt` | logfmt input parser. |
| `cef` | CEF input parser. |
| `evtx` | `.evtx` (Windows Event Log) file reader. |
| `daachorse-index` | Pass-through to `rsigma-eval/daachorse-index` for the cross-rule AC pre-filter. |

## Public surface

| Type | Purpose |
|------|---------|
| `RuntimeEngine` | Wraps an `Engine` or `CorrelationEngine` plus the on-disk rule path, pipelines, and the dynamic source resolver. Supports hot-reload via `load_rules`. |
| `LogProcessor` | An `ArcSwap<Mutex<RuntimeEngine>>` with batch processing methods (`process_batch_lines`, `process_batch_with_format`) and a `reload_rules` helper. The daemon glues this to its bounded mpsc plumbing. |
| `EventSource` trait, `Sink` trait | The plug-in surfaces for inputs and outputs. Built-in: `StdinSource`, `StdoutSink`, `FileSink`, and `NatsSource`/`NatsSink` under the `nats` feature. |
| `spawn_source(source) -> mpsc::Receiver<RawEvent>` | Convenience helper that runs an `EventSource` on its own task. |
| `EventFilter` trait | Optional jq/JSONPath pre-extraction applied to each input line. |
| `MetricsHook` trait + `NoopMetrics` | The plug-in surface that the daemon uses to wire `prometheus` counters. Reimplement to ship metrics elsewhere (Datadog, OpenTelemetry, custom registry). |
| `input::parse_line(...)` | Format-aware line parser. Auto-detects JSON, syslog, plain text; honours format hints. |
| `EvtxFileReader` (feature `evtx`) | Streaming `.evtx` reader. |
| `SourceResolver` trait + `DefaultSourceResolver` | Dynamic-pipeline source resolution: HTTP, command, file, NATS. |
| `SourceCache` | TTL-aware cache for resolved source values. Optional SQLite backing for cross-restart persistence. |
| `TemplateExpander`, `RefreshScheduler`, `RefreshTrigger` | Substitutes `${source.X}` references in pipeline `vars:` and runs the refresh policies. |
| `Enricher` trait + `EnrichmentPipeline` | Post-evaluation enrichment surface. Drives the four primitives (`TemplateEnricher`, `LookupEnricher`, `HttpEnricher`, `CommandEnricher`) and any bespoke types registered via `register_builtin`. |
| `EnricherKind`, `OnError`, `Scope`, `EnrichError`, `EnrichErrorKind` | Configuration types: declared kind, error policy, scope filter, and the typed error returned by `Enricher::enrich`. |
| `HttpResponseCache` (re-exported from `enrichment::http_cache`) | `(method, url, body_hash)`-keyed in-memory response cache with TTL and lazy eviction. Each `HttpEnricher` instance owns its own. |
| `register_builtin(name, factory) -> Result<(), String>` | Process-global, append-only registry hook. External crates use it to ship a bespoke Rust-coded enricher type addressable via `type: <name>` in the daemon's enrichers config. Reserved names (`template` / `lookup` / `http` / `command`) and duplicate registrations are rejected. |
| `enrichment::config::{load_enrichers_file, build_enrichers, build_enrichers_full, EnrichersFile}` | YAML loader for an enrichers config, shared by the daemon and the MCP server. Validates template namespaces, scopes, and bespoke `type:` values. |
| `alert_pipeline::{AlertPipeline, DedupStore, Selector, AlertPipelineFile, load_alert_pipeline_file, parse_alert_pipeline_config, build_alert_pipeline}` | Post-engine alert-processing layer. Deduplicates results by a configurable fingerprint with an `active -> resolved` lifecycle. `AlertPipeline` is the validated, swappable config; `DedupStore` is the sink-task-owned active-alert state. |
| `dispositions::{Disposition, DispositionStore, DispositionConfig, DispositionSnapshot, Verdict, Numerator, parse_dispositions, triage_feed}` | Triage feedback loop. `parse_dispositions` parses a POST body or source payload (object, array, or NDJSON); `Disposition::from_raw` validates one record; `DispositionStore` keeps rolling per-rule verdict counts and computes the false-positive ratio; `triage_feed` renders the `rule scorecard --triage` JSON shape. |
| `lookup_builtin(name)` | Read-only registry probe used by the daemon config loader. |
| `io::webhook::{WebhooksFile, WebhookConfig, WebhookSink, build_webhooks, load_webhooks_file}` | YAML loader and template-driven HTTP output sink. Validates `kind`, template namespaces, and retry/rate-limit bounds; the daemon drives it as a lossy (`on_full=drop`) leaf on the async delivery layer. |

The full pipeline architecture, source resolution flow, and dynamic-pipeline contract are in [the crate README](https://github.com/timescale/rsigma/blob/main/crates/rsigma-runtime/README.md) and the [Architecture reference](../reference/architecture.md).

## Minimum example: in-process batch evaluation

```rust
use rsigma_runtime::{LogProcessor, NoopMetrics, RuntimeEngine};
use rsigma_eval::CorrelationConfig;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut engine = RuntimeEngine::new(
        "rules/".into(),         // rules_path
        Vec::new(),              // pipelines
        CorrelationConfig::default(),
        false,                   // include_event
    );
    engine.load_rules().map_err(|e| e.to_string())?;

    let processor = LogProcessor::new(engine, Arc::new(NoopMetrics));

    let lines = vec![
        r#"{"CommandLine":"cmd /c whoami"}"#.to_string(),
        r#"{"CommandLine":"powershell -enc ..."}"#.to_string(),
    ];

    let outcomes = processor.process_batch_lines(&lines, None);
    for r in outcomes {
        for m in r.matches { println!("matched: {}", m.rule_title.unwrap_or_default()); }
    }
    Ok(())
}
```

For a streaming daemon shape, wire an `EventSource` (`StdinSource`, `NatsSource`, …) through `spawn_source` into your own loop, batch the channel into `Vec<String>`, and feed it to `process_batch_lines`. The daemon code in `rsigma-cli/src/daemon/server.rs` is the reference implementation.

## Hot-reload

`LogProcessor` holds the live `RuntimeEngine` in an `ArcSwap<Mutex<…>>`. `processor.reload_rules()` rebuilds it from disk and atomically swaps it in; in-flight batches finish against the old engine, the next batch sees the new one. Wire a file watcher (`notify`), a `SIGHUP` handler, or an HTTP endpoint to call it:

```rust
use rsigma_runtime::LogProcessor;
use std::sync::Arc;

let processor = Arc::new(processor);
let p = processor.clone();

tokio::spawn(async move {
    // On reload trigger:
    match p.reload_rules() {
        Ok(stats) => println!("reloaded {} rules", stats.rules_loaded),
        Err(e) => eprintln!("reload failed: {e}"),
    }
});
```

The daemon's `notify` + SIGHUP + `POST /api/v1/reload` wiring lives in `rsigma-cli`; `LogProcessor` just exposes the primitive.

## Post-evaluation enrichment

`EnrichmentPipeline` runs after the engine has produced a `ProcessResult` and before the sink serializes it. Each enricher implements the `Enricher` trait, declares a `kind: detection | correlation` at construction, and writes into `RuleHeader::enrichments` under a configured `inject_field`. The pipeline filters per-result by declared kind against the body variant, applies the optional `Scope` filter, wraps the call in a per-enricher timeout, and applies the configured `OnError` policy on failure.

```rust
use rsigma_runtime::{
    EnricherKind, EnrichmentPipeline, OnError, Scope, TemplateEnricher,
};
use std::time::Duration;

let runbook = TemplateEnricher::new(
    "runbook_det".to_string(),
    EnricherKind::Detection,
    "runbook_url".to_string(),
    "https://wiki.internal/runbooks/${detection.rule.id}".to_string(),
    Duration::from_secs(5),
    OnError::Skip,
    Scope::default(),
);

let pipeline = EnrichmentPipeline::new(
    vec![Box::new(runbook)],
    16, // max_concurrent_enrichments
);

// `results` is the engine's `Vec<EvaluationResult>`.
// pipeline.run(&mut results).await;
```

Wire a `MetricsHook` via `EnrichmentPipeline::with_metrics` to surface `rsigma_enrichment_total` / `rsigma_enrichment_duration_seconds` / `rsigma_enrichment_queue_depth` (and the HTTP cache counters) into your own metrics backend. The daemon's Prometheus-backed `Metrics` struct implements the hook.

For YAML-driven configuration, use the `enrichment::config` loader: `load_enrichers_file(path)` parses an enrichers config file into an `EnrichersFile`, and `build_enrichers(file)` / `build_enrichers_full(file, source_cache, metrics)` turn it into an `EnrichmentPipeline` (validating template namespaces and bespoke types). The daemon and the MCP server's `evaluate_events` tool share this loader.

For the operator-facing schema, the four primitives, and the recipe catalog, see [Enrichers](../guide/enrichers.md).

## Custom metrics

Implement `MetricsHook` to ship metrics into your own registry. `NoopMetrics` is a no-op implementation suitable for tests and embedders that do not care. The daemon's own `prometheus`-backed implementation lives in `rsigma-cli/src/daemon/metrics.rs` and is a good template. The hook methods mirror the [27 Prometheus metrics](../reference/metrics.md) the daemon exposes.

```rust
use rsigma_runtime::{LogProcessor, MetricsHook};
use std::sync::Arc;

struct MyMetrics { /* fields */ }

impl MetricsHook for MyMetrics {
    // Implement the methods you care about. See the trait definition on docs.rs
    // for the full surface.
}

let processor = LogProcessor::new(engine, Arc::new(MyMetrics { /* ... */ }));
```

## Dynamic source resolution

The `SourceResolver` + `TemplateExpander` pair is exposed so you can drive it standalone, for example to validate a pipeline's sources from a CI step or to refresh source values from a custom event loop:

```rust
use rsigma_runtime::{DefaultSourceResolver, SourceResolver};

let resolver = DefaultSourceResolver::new();
let value = resolver.resolve(&pipeline.sources[0]).await?;
```

The full spec (source types, data formats, extract languages, refresh policies) lives in [Dynamic Pipeline Sources](../reference/dynamic-sources.md). `RefreshScheduler` runs the periodic refresh policies; `TemplateExpander` substitutes `${source.X}` references into the pipeline.

## Error handling

`RuntimeError` from `thiserror` wraps `EvalError`, `SigmaParserError`, `io::Error`, and `SourceError`. Per-event errors (failed input parse, sink write) are surfaced through the result types instead of aborting; the daemon's optional DLQ collects them.

## See also

- [Streaming Detection](../guide/streaming-detection.md) for the operator-facing daemon walkthrough.
- [Architecture](../reference/architecture.md) for the runtime data flow.
- [Dynamic Pipeline Sources](../reference/dynamic-sources.md) for the source spec.
- [`rsigma-runtime` README](https://github.com/timescale/rsigma/blob/main/crates/rsigma-runtime/README.md).
- [docs.rs/rsigma-runtime](https://docs.rs/rsigma-runtime).
