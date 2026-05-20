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
