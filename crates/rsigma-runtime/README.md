# rsigma-runtime

Streaming runtime for [rsigma](https://github.com/timescale/rsigma) — input format adapters, batch log processing, hot-reload, and pluggable metrics.

## Features

- **Input adapters**: JSON/NDJSON, syslog (RFC 3164/5424), logfmt, CEF, plain text, and auto-detect. Each adapter parses raw log lines into typed events implementing the `rsigma_eval::Event` trait.
- **`LogProcessor`**: batch evaluation pipeline with atomic engine swap via `ArcSwap`, `MetricsHook` for pluggable metrics, and `EventFilter` for JSON payload extraction.
- **`RuntimeEngine`**: wraps `Engine` and `CorrelationEngine` with rule loading, reload, and correlation state management.
- **I/O**: `EventSource` trait (stdin, HTTP, NATS) and `Sink` enum (stdout, file, NATS) with fan-out support.

## Usage

```rust
use std::sync::Arc;
use rsigma_eval::CorrelationConfig;
use rsigma_runtime::{InputFormat, LogProcessor, NoopMetrics, RuntimeEngine};

let mut engine = RuntimeEngine::new(
    "rules/".into(),
    vec![],
    CorrelationConfig::default(),
    false,
);
engine.load_rules().unwrap();

let processor = LogProcessor::new(engine, Arc::new(NoopMetrics));

let batch = vec![r#"{"CommandLine": "cmd /c whoami"}"#.to_string()];
let results = processor.process_batch_with_format(
    &batch,
    &InputFormat::Json,
    None,
);
```

See the [examples](examples/) directory for complete working programs.

## Feature flags

| Flag | Description |
|------|-------------|
| `logfmt` | Enable logfmt input adapter |
| `cef` | Enable CEF (ArcSight) input adapter |
| `evtx` | Enable EVTX (Windows Event Log) input adapter |
| `nats` | Enable NATS JetStream source and sink |

## License

MIT
