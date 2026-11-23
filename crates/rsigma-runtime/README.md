# rsigma-runtime

Streaming runtime for [rsigma](https://github.com/timescale/rsigma), input format adapters, batch log processing, hot-reload, dynamic source resolution, and pluggable metrics.

## Features

- **Input adapters**: JSON/NDJSON, syslog (RFC 3164/5424), logfmt, CEF, EVTX (Windows Event Log), plain text, and auto-detect. Line-oriented adapters parse raw log lines into typed events implementing the `rsigma_eval::Event` trait. The EVTX adapter reads binary `.evtx` files directly via `EvtxFileReader` and yields `serde_json::Value` records.
- **`LogProcessor`**: ordered batch evaluation pipeline with parallel input parsing, atomic engine swap via `ArcSwap`, `MetricsHook` for pluggable metrics, and `EventFilter` for JSON payload extraction (it takes the parsed line by value, so payloads move out without a clone). `process_batch_with_format_detailed` returns a `BatchProcessOutcome` whose `parse_error_indices` lets adapters route malformed lines without parsing them twice. Batches too cheap to be worth waking the Rayon pool are parsed and evaluated on the calling thread; `init_detection_pool` sizes the pool and `detection_threads` reports its size. `process_batch_with_format_detailed_for_tenants` takes a parallel tenant slice and stamps each result; `set_tenant_allowlist` bounds the tenant metric labels.
- **`RuntimeEngine`**: wraps `Engine` and `CorrelationEngine` with rule loading, reload, and correlation state management. `set_include_event` (also on `LogProcessor`) turns event retention on or off on a running engine, and rule reloads keep the value.
- **Dynamic source resolution**: `SourceResolver` trait with `DefaultSourceResolver` implementation fetching data from files, commands, HTTP APIs, and NATS subjects, plus `type: watchlist` sets pushed by the caller. With `stix-source`, `type: taxii` polls a TAXII 2.1 collection and `format: stix` reads a bundle. Includes template expansion, extraction (jq/JSONPath/CEL), caching with TTL, and scheduled refresh. `SourceFetch::CacheFirst` rebuilds rules from cached values.
- **`DaemonSourceRegistry`**: unified registry of every dynamic source the daemon resolves, loaded from external `--source` files with collision-error semantics. (Pipeline files can no longer declare `sources:` inline; that form was removed in v0.19.0.) Used by the daemon to manage all dynamic sources from a single point.
- **I/O**: `EventSource` trait (stdin, HTTP, NATS, Unix domain socket) and `Sink` enum (stdout, file, NATS, OTLP, webhook, Unix domain socket) with fan-out support and a shared async delivery layer (per-sink queues, one batched first attempt per drained batch, bounded retry/backoff, DLQ routing). Each line-oriented sink carries a `SinkFormat` (`Ndjson` by default, `Ocsf` for OCSF Detection Finding output). The `unix://` source and sink are gated behind the `uds` feature and `#[cfg(unix)]`.
- **OCSF findings**: the `ocsf` module serializes detections, correlations, incidents, and risk incidents as OCSF Detection Finding (class 2004) JSON, selected per sink with `?format=ocsf`. Incidents can instead be emitted as Incident Findings (class 2005, `ocsf_incident_class=2005`) whose `finding_info_list[]` references the Detection Findings they group. Output only: everything without a faithful OCSF home rides under `unmapped`, and nothing here deserializes OCSF.
- **Field observability**: re-exports `FieldObserver` / `FieldObservation` / `FieldObservationEntry` / `FieldCoverage` from `rsigma-eval` (the canonical home, since they only need the `Event` trait) so downstream consumers can keep importing from `rsigma_runtime`. Attach via `LogProcessor::set_field_observer(Some(observer))`; inspect via `snapshot()` / `reset()`; join against a `RuleFieldSet` via `FieldObservation::coverage()`.
- **Live event tap**: the `tap` module (`TapRegistry`, `TapStage`, `TapPayload`, `TapSessionHandle`) captures raw lines and decoded events into bounded per-session channels off the engine hot path. Attach via `LogProcessor::set_event_tap(Some(registry))`; the hot path does one `ArcSwap` load per batch when no session is active. Delivery is non-blocking (`try_send`), so a slow consumer drops events (counted) rather than ever applying backpressure to detection. Redaction and HTTP streaming live in the CLI.
- **Post-evaluation enrichment**: the `Enricher` trait and `EnrichmentPipeline` (seven primitives: `template`, `lookup`, `http`, `command`, `stix` when `stix-enrich` is enabled, `mmdb` when `mmdb-enrich` is enabled, and `dns` when `dns-enrich` is enabled, plus bespoke types via `register_builtin`), with a YAML loader in `enrichment::config` (`load_enrichers_file`, `parse_enrichers_config`, `build_enrichers`, `build_enrichers_full`, `EnricherResources`) shared by the daemon and the MCP server. Built-in entries reject keys that are unknown or do not apply to their type, and bespoke types receive extra keys through `EnricherConfig::extra`. Webhook and risk configs reject unknown keys too. Built-in enricher templates read `${detection.fields.<name>}` from the retained event when the rule did not match on `<name>`; `EnrichmentPipeline::needs_event` says whether a pipeline reads the event (only `build_enrichers` and `build_enrichers_full` compute it; a pipeline from `EnrichmentPipeline::new` reports `false`), so a caller passes it to `set_include_event` and removes the event after enrichment with `strip_auto_retained_event`, which keeps events that rules asked for and correlation payloads. A lookup that finds no data for its key returns `EnrichErrorKind::Miss` (`EnrichErrorKind` is `#[non_exhaustive]`), which the pipeline handles with `Enricher::on_miss` (defaulting to `on_error`, set on the built-in types with `with_on_miss`), logs at debug, and counts as `status="miss"`; other failures log at most one warning per enricher every 10 seconds with a `suppressed` count. `HttpEnricher::with_default` injects a default for a `null` result, and `HttpEnricher::with_miss_status` turns listed statuses into cached misses. `EnrichersConfigError::InvalidValue` rejects a `miss_status` entry outside `300..=599` and `on_miss` combined with `default`. With the `mmdb-mmap` feature, an `mmdb` entry with `mmap: true` (`EnricherConfig::mmap`) memory-maps its database instead of reading it into memory, and the file must then be replaced by renaming a new file over it.
- **Triage feedback loop**: the `dispositions` module (`parse_dispositions`, `Disposition`, `DispositionStore`, `triage_feed`) ingests analyst verdicts off the result stream and maintains a rolling per-rule false-positive ratio with redelivery idempotency and a versioned snapshot for persistence.
- **Verdict-driven capture**: the `capture` module (`CaptureRing`, `CaptureConfig`, `CaptureRingSink`) retains admitted `group_by` detection events under event, incident, and global byte ceilings plus a TTL. The `capture_spool` module is the versioned bundle format (`parse_manifest`, `parse_provenance`, `parse_corpus_events`) consumed by `rule tune --from-dispositions`. The ring is not persisted.
- **Alert pipeline**: the `alert_pipeline` module is a post-engine stage that silences, inhibits, and deduplicates results before grouping survivors into incidents, modeled on Alertmanager. It shares the field-selector namespace and scope filter with the risk layer, emits `IncidentResult`s via `Sink::send_incident`, and keeps a versioned snapshot (active alerts, open incidents, dynamic silences, inhibition sources) for persistence. `Silence::build_api` builds an API silence under the pipeline's `SilenceLimits` (`AlertPipeline::silence_limits`, from `max_silence_duration` and `allow_broad_silences`). Restoring a snapshot trims it to the pipeline's caps, and `AlertPipeline::enforce_caps` applies the same trim to state carried into a reloaded pipeline.
- **Risk-based alerting**: the `risk` module (`RiskLayer`, `RiskState`, `RiskIncidentResult`, `parse_risk_config`, `build_risk_layer`) annotates each firing with a risk score and risk objects (entities) via the shared field selector, accumulates per-entity risk over a sliding window, and emits a `RiskIncidentResult` on a score or ATT&CK-tactic-count threshold, with caps, a per-entity cooldown, and a versioned snapshot for persistence. It runs after enrichment and before the alert pipeline.
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

`load_rules` skips rule documents that fail to parse and counts them in `EngineStats::parse_errors`. It returns an error, keeping the previous engine, when every rule fails to parse, or on any parse error after `set_strict_rules(true)`.

See the [examples](examples/) directory for complete working programs.

## Named rulesets

`RuntimeEngine::with_rulesets` loads several named rulesets with per-ruleset pipelines and state, using `RuleSource`, `RulesetBinding`, and `PipelineRef`. `watch_paths(source, pipeline_paths)` returns the directories the hot-reload watcher should follow in both modes: rule sources, overlays, ruleset pipelines, and the `-p` pipeline files. `RuntimeEngine::take_ruleset_skipped` drains the skipped-event counts since the last call, and `load_rules` resolves dynamic pipeline sources in ruleset mode as it does in path mode. `LogProcessor` reports per-ruleset matches and skipped events through the metrics hook.

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

1. **Fetch**: the source type (file, command, HTTP, NATS, watchlist, and with `stix-source`, TAXII) determines how raw data is obtained. A watchlist reads `WatchlistRegistry` and returns the unexpired values. Without a registry it returns `[]`. A pipeline reference lowers that watchlist's cap to the placeholder limit, and `apply_reference_limits` applies the same cap from the pipelines that loaded. `restore` reports rows left above the cap. A TAXII source polls indicators and keeps an in-memory `added_after` cursor. One poll reads a budget derived from `max_indicators` and `page_size`, and the next refresh continues when that poll stops with an added-date. The retained set drops expired and revoked bodies and keeps indicators past the cap while it is under twice `max_indicators`. Call `prepare_taxii` before the first resolve so credentials are read and the egress filter is installed.
2. **Parse**: raw bytes are parsed according to the declared `DataFormat` (JSON, YAML, lines, CSV, and with `stix-source`, STIX). `format: stix` builds the observable arrays and the `indicators` map. Array values escape `\`, `*`, and `?`. The `indicators` keys stay raw. `extract` does not apply to that format.
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
| `uds` | Enable the Unix domain socket event source and sink (`unix://` input/output). Unix targets only |
| `otlp` | Enable OTLP log ingestion types and `LogRecord`-to-JSON conversion |
| `daachorse-index` | Forward to `rsigma-eval/daachorse-index`. Enables `RuntimeEngine::set_cross_rule_ac` and the cross-rule Aho-Corasick pre-filter for large substring-heavy rule sets |
| `stix-source` | `type: taxii` polling and `format: stix` bundle builds. Pulls in `rstix` with the `taxii` and `pattern` features. `prepare_taxii` reads credential environment variables and installs the egress address filter. `with_stix_clock` fixes the lifecycle clock. |

## License

MIT
