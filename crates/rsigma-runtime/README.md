# rsigma-runtime

Streaming runtime for [rsigma](https://github.com/timescale/rsigma) — input format adapters, batch log processing, hot-reload, dynamic source resolution, and pluggable metrics.

## Features

- **Input adapters**: JSON/NDJSON, syslog (RFC 3164/5424), logfmt, CEF, EVTX (Windows Event Log), plain text, and auto-detect. Line-oriented adapters parse raw log lines into typed events implementing the `rsigma_eval::Event` trait. The EVTX adapter reads binary `.evtx` files directly via `EvtxFileReader` and yields `serde_json::Value` records.
- **`LogProcessor`**: batch evaluation pipeline with atomic engine swap via `ArcSwap`, `MetricsHook` for pluggable metrics, and `EventFilter` for JSON payload extraction.
- **`RuntimeEngine`**: wraps `Engine` and `CorrelationEngine` with rule loading, reload, and correlation state management.
- **Dynamic source resolution**: `SourceResolver` trait with `DefaultSourceResolver` implementation fetching data from files, commands, HTTP APIs, and NATS subjects. Includes template expansion, extraction (jq/JSONPath/CEL), caching with TTL, and scheduled refresh.
- **`DaemonSourceRegistry`**: unified registry of every dynamic source the daemon resolves, loaded from external `--source` files with collision-error semantics. (Pipeline-embedded `sources:` blocks are also merged in for backward compatibility but are deprecated and removed in v1.0.) Used by the daemon to manage all dynamic sources from a single point.
- **I/O**: `EventSource` trait (stdin, HTTP, NATS) and `Sink` enum (stdout, file, NATS, OTLP, webhook) with fan-out support and a shared async delivery layer (per-sink queues, bounded retry/backoff, DLQ routing).
- **Field observability**: re-exports `FieldObserver` / `FieldObservation` / `FieldObservationEntry` / `FieldCoverage` from `rsigma-eval` (the canonical home, since they only need the `Event` trait) so downstream consumers can keep importing from `rsigma_runtime`. Attach via `LogProcessor::set_field_observer(Some(observer))`; inspect via `snapshot()` / `reset()`; join against a `RuleFieldSet` via `FieldObservation::coverage()`.
- **Live event tap**: the `tap` module (`TapRegistry`, `TapStage`, `TapPayload`, `TapSessionHandle`) captures raw lines and decoded events into bounded per-session channels off the engine hot path. Attach via `LogProcessor::set_event_tap(Some(registry))`; the hot path does one `ArcSwap` load per batch when no session is active. Delivery is non-blocking (`try_send`), so a slow consumer drops events (counted) rather than ever applying backpressure to detection. Redaction and HTTP streaming live in the CLI.
- **Post-evaluation enrichment**: the `Enricher` trait and `EnrichmentPipeline` (four primitives: `template`, `lookup`, `http`, `command`, plus bespoke types via `register_builtin`), with a YAML loader in `enrichment::config` (`load_enrichers_file`, `build_enrichers`, `build_enrichers_full`) shared by the daemon and the MCP server.
- **Triage feedback loop**: the `dispositions` module (`parse_dispositions`, `Disposition`, `DispositionStore`, `triage_feed`) ingests analyst verdicts off the result stream and maintains a rolling per-rule false-positive ratio with redelivery idempotency and a versioned snapshot for persistence.
- **Risk-based alerting**: the `risk` module (`RiskLayer`, `RiskState`, `RiskIncidentResult`, `parse_risk_config`, `build_risk_layer`) annotates each firing with a risk score and risk objects (entities) via the shared field selector, accumulates per-entity risk over a sliding window, and emits a `RiskIncidentResult` on a score or ATT&CK-tactic-count threshold, with caps, a per-entity cooldown, and a versioned snapshot for persistence.
- **OTLP**: `LogRecord`-to-JSON conversion for OpenTelemetry log ingestion (feature-gated under `otlp`). Resource and log attributes are flattened for direct Sigma rule matching.

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

## Dynamic Source Resolution

The `sources` module provides the infrastructure for resolving external data at pipeline load time. This allows pipeline values to be populated from live data rather than hardcoded.

### Core types

```rust
use rsigma_runtime::{DefaultSourceResolver, SourceResolver, SourceCache, ResolvedValue, SourceError};

// Create a resolver with in-memory cache
let resolver = DefaultSourceResolver::new();

// Or with SQLite-backed persistence and TTL
use std::time::Duration;
let cache = SourceCache::with_sqlite_and_ttl(
    std::path::Path::new("/tmp/rsigma-cache.db"),
    Some(Duration::from_secs(3600)),
).unwrap();
let resolver = DefaultSourceResolver::with_cache(cache);
```

### Resolution flow

1. **Fetch**: the source type (file, command, HTTP, NATS) determines how raw data is obtained.
2. **Parse**: raw bytes are parsed according to the declared `DataFormat` (JSON, YAML, lines, CSV).
3. **Extract**: an optional expression (jq, JSONPath, or CEL) selects a subset of the parsed data.
4. **Cache**: successful results are stored for `use_cached` error policy fallback.
5. **Template expansion**: `TemplateExpander` substitutes `${source.<id>}` references with resolved values.

### Resolving all sources

```rust
use rsigma_runtime::sources::resolve_all;

// sources: &[DynamicSource] from the parsed pipeline
let resolved_map = resolve_all(&resolver, &pipeline.sources).await?;
// resolved_map: HashMap<String, serde_json::Value>

// Or with PipelineState tracking:
use rsigma_runtime::sources::resolve_all_with_state;
let resolved_map = resolve_all_with_state(&resolver, &pipeline.sources, Some(&mut state)).await?;
```

### Extraction languages

The `extract` module supports three languages for selecting data from resolved sources:

| Language | Use case | Example |
|----------|----------|---------|
| jq | Complex transformations, array iteration, filtering | `.indicators[].ip` |
| JSONPath | Simple path queries into nested JSON | `$.data.items[*].value` |
| CEL | Typed expressions with filtering and aggregation | `data.filter(x, x.score > 7)` |

### Refresh scheduling

The `refresh` module manages automatic re-resolution:

- **Interval**: periodic timer fires resolution on a configurable cadence.
- **Watch**: file system notifications (via `notify`) trigger re-resolution when a file source changes.
- **Push**: NATS messages on the source subject trigger immediate updates.
- **OnDemand**: resolution only happens when triggered via API, SIGHUP, or NATS control subject (`rsigma.control.resolve`).

### Include expansion

The `include` module splices transformation blocks from resolved sources into the pipeline:

```rust
use rsigma_runtime::sources::include::expand_includes;

// Modifies pipeline.transformations in place, replacing Include directives
// with the resolved transformation blocks.
expand_includes(&mut pipeline, &resolved_map, allow_remote_include)?;
```

Recursive includes are rejected (max depth 1) to prevent cycles.

### Template expansion

The `template` module replaces `${source.<id>}` and `${source.<id>.<path>}` references in pipeline vars:

```rust
use rsigma_runtime::sources::TemplateExpander;

// Returns a new pipeline with vars expanded using resolved source data.
let expanded_pipeline = TemplateExpander::expand(&pipeline, &resolved_map);
```

## Feature flags

| Flag | Description |
|------|-------------|
| `logfmt` | Enable logfmt input adapter |
| `cef` | Enable CEF (ArcSight) input adapter |
| `evtx` | Enable EVTX (Windows Event Log) input adapter. Provides `EvtxFileReader` for reading `.evtx` files and iterating records as `serde_json::Value` |
| `nats` | Enable NATS JetStream source and sink, NATS dynamic sources, and NATS control subject |
| `otlp` | Enable OTLP log ingestion types and `LogRecord`-to-JSON conversion |
| `daachorse-index` | Forward to `rsigma-eval/daachorse-index`. Enables `RuntimeEngine::set_cross_rule_ac` and the cross-rule Aho-Corasick pre-filter for large substring-heavy rule sets |

## License

MIT
