---
description: "rsigma-runtime Rust crate: an async streaming pipeline around rsigma-eval with input adapters, sinks, hot-reload, dynamic sources, and metrics."
---

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
tokio = { version = "1", features = ["rt-multi-thread", "sync", "macros", "io-util", "io-std", "process", "fs"] }
```

| Feature | Effect |
|---------|--------|
| `nats` | NATS JetStream as an event source, sink, and dynamic source. |
| `otlp` | OTLP/HTTP and OTLP/gRPC log decoding (`opentelemetry-proto`, `prost`). |
| `logfmt` | logfmt input parser. |
| `cef` | CEF input parser. |
| `evtx` | `.evtx` (Windows Event Log) file reader. |
| `uds` | Unix-domain socket source and sink (Unix only). |
| `daachorse-index` | Pass-through to `rsigma-eval/daachorse-index` for the cross-rule AC pre-filter. |

## Public surface

| Type | Purpose |
|------|---------|
| `RuntimeEngine` | Wraps an `Engine` or `CorrelationEngine` plus the on-disk rule path, pipelines, and the dynamic source resolver. Supports hot-reload via `load_rules`. `with_rulesets` loads several named rulesets with per-ruleset pipelines and state; `rule_source`, `set_ruleset_classifier`, `ruleset_classifier`, `ruleset_stats`, and `take_ruleset_skipped` (which drains the skipped-event counts since the last call) serve that mode. {{ added "0.28.0" }} |
| `RuleSource`, `RulesetBinding`, `PipelineRef`, `load_pipelines`, `watch_paths` | The rule source for path mode or named-ruleset mode, the per-ruleset spec and pipeline references, loading a binding's pipelines, and the hot-reload watch paths. `watch_paths(source, pipeline_paths)` covers rule sources, overlays, ruleset pipelines, and the `-p` pipeline files, and watches a bare file name through the working directory. {{ added "0.28.0" }} |
| `LogProcessor` | An ordered batch processor that parses formatted inputs in parallel before locking its live `RuntimeEngine`. `process_batch_with_format_detailed` returns `BatchProcessOutcome`, including input indices that failed parsing for single-parse DLQ routing. The daemon glues this to its bounded mpsc plumbing. `ruleset_stats` reports per-ruleset rule and skip counts. `process_batch_with_format_detailed_for_tenants` takes a parallel tenant slice and stamps each result. `set_tenant_allowlist` bounds the tenant metric labels. {{ added "0.28.0" }} |
| `RuntimeEngine::set_include_event`, `LogProcessor::set_include_event`, `LogProcessor::include_event` | Turn engine-wide event retention on or off on a running engine, on every engine variant, without a rule reload. Rule reloads keep the value, including one set while rules are loading. `LogProcessor::set_include_event` waits for in-flight batches so each batch sees one value. {{ added "0.28.0" }} |
| `init_detection_pool`, `detection_threads` | Build the global Rayon pool that parses and evaluates batches with a given thread count, before any batch runs, and report its size. Without `init_detection_pool` the pool honors `RAYON_NUM_THREADS`. {{ added "0.28.0" }} |
| `WithTenant` | Wraps an `EventSource` and stamps every event with one tenant. {{ added "0.28.0" }} |
| `RulesetBinding.tenants`, `RulesetUnit.tenants`, `RulesetStats.tenants` | Bind a named ruleset to tenants. Empty means every tenant. {{ added "0.28.0" }} |
| `Scope::with_tenants` | Restrict an enricher, webhook, or alert-pipeline scope to listed tenants. {{ added "0.28.0" }} |
| `EventSource` trait, `Sink` trait | The plug-in surfaces for inputs and outputs. Built-in: `StdinSource`, `StdoutSink`, `FileSink`, and `NatsSource`/`NatsSink` under the `nats` feature. |
| `Dispatcher`, `DeliverySink`, `DeliveryConfig`, `DeliveryContext` | The async delivery layer the daemon drives its sinks through: one bounded queue and worker per sink, retries with capped exponential backoff, and DLQ routing. `DeliverySink::deliver_batch` makes the first attempt for a drained batch and returns one outcome per attempted result. Its `backlog` flag is set when more results were already queued behind the batch, so a sink can tell when the worker is the slower side. The default ignores the flag, delivers one result at a time, and stops at the first failure; the worker retries each failed result on its own, in order, and gives each result past the last outcome its own attempt. {{ added "0.28.0" }} |
| `spawn_source(source) -> mpsc::Receiver<RawEvent>` | Convenience helper that runs an `EventSource` on its own task. |
| `EventFilter` | Type alias for `dyn Fn(Value) -> Vec<Value>`: optional jq/JSONPath-style pre-extraction applied to each input line. The filter takes the parsed line by value, so it can move payloads out instead of cloning them. {{ added "0.25.0" }} |
| `MetricsHook` trait + `NoopMetrics` | The plug-in surface that the daemon uses to wire `prometheus` counters. Reimplement to ship metrics elsewhere (Datadog, OpenTelemetry, custom registry). `register_ruleset`, `on_ruleset_match`, `on_ruleset_events_skipped`, and `on_ruleset_rules_loaded` report named rulesets and default to no-ops. `on_tenant_rejected`, `on_tenant_quota_eviction`, and `on_tenant_match` report tenancy and default to no-ops. {{ added "0.28.0" }} `on_sink_otlp_rejected_records` counts log records an OTLP collector rejected and defaults to a no-op. {{ added "0.28.0" }} |
| `input::parse_line(...)` | Format-aware line parser. Auto-detects JSON, syslog, plain text; honors format hints. |
| `EvtxFileReader` (feature `evtx`) | Streaming `.evtx` reader. |
| `SourceResolver` trait + `DefaultSourceResolver` | Dynamic source resolution for pipelines and lookup enrichers: HTTP, command, file, NATS, watchlist, and, with `stix-source`, TAXII and `format: stix`. |
| `SourceCache` | TTL-aware cache for resolved source values. Optional SQLite backing for cross-restart persistence. |
| `TemplateExpander`, `RefreshScheduler`, `RefreshTrigger` | Substitutes `${source.X}` references in pipeline `vars:` and runs the refresh policies. |
| `Enricher` trait + `EnrichmentPipeline` | Post-evaluation enrichment surface. Drives the seven primitives (`TemplateEnricher`, `LookupEnricher`, `HttpEnricher`, `CommandEnricher`, `StixEnricher` with `stix-enrich`, `MmdbEnricher` with `mmdb-enrich`, and `DnsEnricher` with `dns-enrich`) and any bespoke types registered via `register_builtin`. |
| `MmdbEnricher`, `MmdbDatabase`, `MmdbFields`, `MmdbLookupError` (feature `mmdb-enrich`) | MMDB lookup enricher. `MmdbDatabase` opens an operator-supplied MMDB file or builds one from bytes, `MmdbFields` parses a dotted-path field map where numeric segments are array indexes, and `MmdbEnricher` injects the decoded record or the configured default. The `MetricsHook` methods `on_enrichment_mmdb_hit`, `on_enrichment_mmdb_miss`, `on_enrichment_mmdb_reload`, `set_enrichment_mmdb_build_epoch`, `register_mmdb_enricher`, and `register_mmdb_database` report lookups and database refreshes. With the `mmdb-mmap` feature, a config entry with `mmap: true` (`EnricherConfig::mmap`) memory-maps its database instead of reading it into memory; entries that share a database must agree on it. {{ added "0.28.0" }} |
| `DnsEnricher`, `DnsRecordType`, `DnsResolverConfig`, `SUPPORTED_DNS_RECORD_TYPES` (feature `dns-enrich`) | DNS lookup enricher. `DnsRecordType` parses the `record_type` value and exposes `query_name` and `format_answers` for the name and answer normalization, `DnsResolverConfig` holds the nameservers, timeout, and cache bounds, and `DnsEnricher` injects the formatted answers or the configured default. The `MetricsHook` methods `on_enrichment_dns_cache_hit`, `on_enrichment_dns_cache_miss`, `on_enrichment_dns_query`, and `register_dns_enricher` report cache use and upstream query results. {{ added "0.28.0" }} |
| `EnricherKind`, `OnError`, `Scope`, `EnrichError`, `EnrichErrorKind` | Configuration types: declared kind, error policy, scope filter, and the typed error returned by `Enricher::enrich`. |
| `EnrichErrorKind::Miss`, `Enricher::on_miss` | `EnrichErrorKind` is `#[non_exhaustive]`; `Miss(String)` means the lookup ran and found no data for its key, and displays with a `no match:` prefix. The `lookup`, `stix`, `mmdb`, and `dns` no-data outcomes and an `http` status listed in `miss_status` return it when no default is configured. The pipeline applies `Enricher::on_miss` to a `Miss` and `Enricher::on_error` to every other error; `on_miss` defaults to `on_error`. `LookupEnricher`, `HttpEnricher`, `StixEnricher`, `MmdbEnricher`, and `DnsEnricher` take theirs from `with_on_miss`. {{ added "0.28.0" }} |
| `HttpEnricher::with_default`, `HttpEnricher::with_miss_status` | `with_default` sets the value injected when the response, after the optional extract, is `null`, or when its status is listed in `miss_status`. `with_miss_status(Vec<u16>)` lists the statuses that are misses: the body is not read, and those responses are cached for the response cache's TTL. {{ added "0.28.0" }} |
| `EgressPolicy`, `EgressDenial`, `EgressFilteredResolver`, `set_default_egress_policy`, `default_egress_policy` | Outbound HTTP deny list (link-local, cloud metadata, loopback, private) shared by HTTP sources, HTTP enrichers, and webhooks. `EgressPolicy::permit_ip` checks one address, `EgressPolicy::check_url` checks a URL whose host is an IP literal (which skips DNS), and `EgressFilteredResolver` filters resolved hostnames. Clients from `build_default_http_client` apply all three and re-check every redirect hop; a client wrapped with `HttpEnricherClient::from_reqwest` applies only what its own `reqwest::Client` configures. `check_url` {{ added "0.27.0" }} |
| `HttpResponseCache` (re-exported from `enrichment::http_cache`) | `(method, url, body_hash, headers_hash)`-keyed in-memory response cache with TTL and lazy eviction. Each `HttpEnricher` instance owns its own. |
| `enrichment::{render_template, render_template_json, render_template_url}` | Render a `${detection.*}`, `${correlation.*}`, or `${ENV_VAR}` template against an `EvaluationResult`. `render_template` substitutes verbatim, `render_template_json` JSON-string-escapes every value, and `render_template_url` percent-encodes result values as single URL components while leaving `${ENV_VAR}` values verbatim. Use the variant that matches where the rendered text lands. `render_template_url` {{ added "0.25.0" }} These resolve `${detection.fields.<name>}` from matched fields only; the built-in enrichers also read unmatched names from the retained event. {{ added "0.28.0" }} |
| `EnrichmentPipeline::needs_event`, `EnricherConfig::rendered_fields`, `strip_auto_retained_event` | `needs_event` reports whether a loaded enricher renders `${detection.fields.*}`, `${detection.event.*}`, or `${detection.event}`, computed by `build_enrichers` and `build_enrichers_full` from `rendered_fields`, the string fields each enricher type renders. A pipeline built with `EnrichmentPipeline::new` always reports `false`. `strip_auto_retained_event` clears a detection's event unless the rule set `rsigma.include_event: "true"`, and never touches correlation payloads. See [Post-evaluation enrichment](#post-evaluation-enrichment). {{ added "0.28.0" }} |
| `env_references(text) -> Vec<String>` | Names of every `${ENV_VAR}` reference in a template, in order of first appearance and without duplicates. Rendering expands these from the process environment, so use it to reject templates that come from an untrusted party; the MCP server does this for `evaluate_events`. {{ added "0.27.0" }} |
| `register_builtin(name, factory) -> Result<(), String>` | Process-global, append-only registry hook. External crates use it to ship a bespoke Rust-coded enricher type addressable via `type: <name>` in the daemon's enrichers config. Reserved names (`template`, `lookup`, `http`, `command`, `stix`, `mmdb`, `dns`) and duplicate registrations are rejected. |
| `enrichment::config::{load_enrichers_file, build_enrichers, build_enrichers_full, EnricherResources, EnrichersFile}` | YAML loader for an enrichers config, shared by the daemon and the MCP server. Validates template namespaces, scopes, and bespoke `type:` values. |
| `parse_enrichers_config(text) -> Result<EnrichersFile, EnrichersConfigError>` | Parse and validate an enrichers config without opening files, building clients, or resolving sources. It runs the same key, template, scope, and extract checks as `build_enrichers`, and `load_enrichers_file` calls it. A built-in entry with an unknown key fails with `EnrichersConfigError::UnknownField`, and one with a key from another type fails with `InapplicableField`. `EnricherConfig::extra` holds the keys the built-in schema does not know, which bespoke factories receive. `EnricherConfig` and `EnrichersConfigError` are `#[non_exhaustive]`, and `EnricherConfig::output` is an `Option`. {{ added "0.28.0" }} `EnricherConfig` gains `miss_status` and `on_miss`, `EnricherConfig::default` is `Some(Value::Null)` for an explicit `default: null`, and `EnrichersConfigError::InvalidValue` reports a `miss_status` entry outside `300..=599` or `on_miss` combined with `default`. {{ added "0.28.0" }} |
| `alert_pipeline::{AlertPipeline, DedupStore, Selector, AlertPipelineFile, load_alert_pipeline_file, parse_alert_pipeline_config, build_alert_pipeline}` | Post-engine alert-processing layer. Deduplicates results by a configurable fingerprint with an `active -> resolved` lifecycle. `AlertPipeline` is the validated, swappable config; `DedupStore` is the sink-task-owned active-alert state. `AlertPipeline::restore` trims restored state to the pipeline's caps, and `AlertPipeline::enforce_caps` applies the same trim when a reloaded pipeline replaces another, returning a `CapTrim` with the eviction counts. {{ added "0.25.0" }} |
| `alert_pipeline::{Silence, SilenceLimits, SilenceError, DEFAULT_MAX_SILENCE_DURATION}` | `Silence::build_api(spec, &limits, now)` builds an API-origin silence and refuses one without `ends_at`, ending more than `limits.max_duration` after `now`, or with no `=` matcher on a non-empty value on `rule`, `match.<field>`, or `correlation.group_key.<field>` unless `limits.allow_broad` is set. `SilenceLimits` is `#[non_exhaustive]`; start from `SilenceLimits::default()`. `AlertPipeline::silence_limits` returns the limits from `max_silence_duration` and `allow_broad_silences`. `SilenceError` is `#[non_exhaustive]` and gains `Unbounded`, `TooLong`, and `TooBroad`. {{ added "0.27.0" }} |
| `dispositions::{Disposition, DispositionStore, DispositionConfig, DispositionSnapshot, Verdict, Numerator, parse_dispositions, triage_feed}` | Triage feedback loop. `parse_dispositions` parses a POST body or source payload (object, array, or NDJSON); `Disposition::from_raw` validates one record; `DispositionStore` keeps rolling per-rule verdict counts and computes the false-positive ratio; `triage_feed` renders the `rule scorecard --triage` JSON shape. |
| `capture::{CaptureRing, CaptureConfig, CaptureRingSink, AdmittedEvent, CapturedEvent, event_digest}` | Byte-bounded in-memory ring of admitted `group_by` detection events. Used by the daemon capture hook after inhibition/silencing and before dedup. |
| `capture_spool::{BundleManifest, parse_manifest, parse_provenance, parse_corpus_events, bundle_id, disposition_identity}` | Versioned disposition-bundle documents. Readers reject unknown major versions and malformed NDJSON with bounded input sizes. |
| `risk::{RiskLayer, RiskState, RiskIncidentResult, RiskEntityView, RiskStateSnapshot, RiskFile, load_risk_file, parse_risk_config, build_risk_layer}` | Risk-based alerting layer. `RiskLayer` is the validated, swappable config; `RiskLayer::process` annotates each firing with a risk score and risk objects, accumulates per-entity risk in the sink-task-owned `RiskState`, and emits a `RiskIncidentResult` on a score or ATT&CK-tactic-count threshold. `RiskState::views` backs `GET /api/v1/risk`; `snapshot`/`restore` persist the accumulator. |
| `lookup_builtin(name)` | Read-only registry probe used by the daemon config loader. |
| `ocsf::{detection_finding, incident_finding, risk_incident_finding, FindingSource, SystemSource, OCSF_VERSION}` | Output-only OCSF Detection Finding (class 2004) serializer for the three emitted shapes. Each entry point has a `*_with` variant taking a [`FindingSource`] so the minted `metadata.uid` and the serialization clock can be injected in tests. Selected on a sink with `?format=ocsf`; see [OCSF Findings](../guide/ocsf-findings.md) for the full mapping. |
| `ocsf::{incident_finding_2005, risk_incident_finding_2005, incident_finding_in_class, risk_incident_finding_in_class, OcsfOptions, OcsfVersion, OcsfIncidentClass}` | OCSF Incident Finding (class 2005) serializers for the two incident shapes. Each has `*_opts` and `*_with_opts` (an injected [`FindingSource`]); there is no `*_with`, because a class-2005 finding needs an assignee group. All four, and the `*_in_class` functions, return `Result` and reject a blank group or options that name none. `finding_info_list[]` references the Detection Finding uid of each retained contributor whose uid is known, carried on `FindingLinks` and never serialized on the incident. `OcsfOptions` carries the schema `version`, the `incident_class`, and the group; the `*_in_class` functions pick class 2004 or 2005 from it. {{ added "0.28.0" }} |
| `SinkFormat` | The non-exhaustive wire format a line-oriented or OTLP sink serializes into (`Ndjson`, the default, or `Ocsf`). Set with `StdoutSink::with_format` and its siblings; `Sink::format` reports it, and returns `Some` for OTLP sinks too. |
| `IncidentEnvelope`, `FormattedIncidentEnvelope` | `IncidentEnvelope` retains the native NDJSON line and NATS subject as its source-compatible public shape. `FormattedIncidentEnvelope` wraps it with alternate per-format lines for mixed-format delivery, and `with_ocsf_line` adds one OCSF line per `OcsfOptions` so sinks with different OCSF versions or incident classes each get their own. {{ added "0.28.0" }} |
| `OtlpSink`, `OtlpProtocol`, `OtlpClientTls`, `DEFAULT_OTLP_TIMEOUT` (feature `otlp`) | OTLP log-record exporter over gRPC or HTTP protobuf, with optional gzip and client TLS. Every export attempt is bounded by `DEFAULT_OTLP_TIMEOUT` (10 seconds); `OtlpSink::with_timeout` overrides it, and an expired attempt surfaces as a retryable `RuntimeError::Io` with `ErrorKind::TimedOut`. {{ added "0.25.0" }} `OtlpSink::with_format(SinkFormat::Ocsf)` (with `with_ocsf_options`) exports each result's OCSF Detection Finding as the log-record body and keeps the native attributes. {{ added "0.28.0" }} `OtlpSink::with_metrics` reports the log records a collector rejects in a partial success through `MetricsHook::on_sink_otlp_rejected_records`. {{ added "0.28.0" }} |
| `io::webhook::{WebhooksFile, WebhookConfig, WebhookSink, build_webhooks, load_webhooks_file}` | YAML loader and template-driven HTTP output sink. Validates `kind`, template namespaces, and retry/rate-limit bounds; the daemon drives it as a lossy (`on_full=drop`) leaf on the async delivery layer. |

The full pipeline architecture, source resolution flow, and dynamic-pipeline contract are in [the crate README](https://github.com/timescale/rsigma/blob/main/crates/rsigma-runtime/README.md) and the [Architecture reference](../reference/architecture.md).

## Minimum example: in-process batch evaluation

```rust
use rsigma_runtime::{LogProcessor, NoopMetrics, RuntimeEngine};
use rsigma_eval::{CorrelationConfig, ProcessResultExt};
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

    let identity = |v: &serde_json::Value| vec![v.clone()];
    let outcomes = processor.process_batch_lines(&lines, &identity);
    for result in outcomes {
        for m in result.detections() {
            println!("matched: {}", m.header.rule_title);
        }
    }
    Ok(())
}
```

For a streaming daemon shape, wire an `EventSource` (`StdinSource`, `NatsSource`, …) through `spawn_source` into your own loop, batch the channel into `Vec<String>`, and feed it to `process_batch_lines`. The daemon code in `rsigma-cli/src/daemon/server.rs` is the reference implementation. `StdinSource::read_status` returns a `StdinReadStatus` that reports whether the stdin reader stopped on a read error instead of end of input, so a batch runner can tell a clean end of input from a failed read. {{ added "0.28.0" }}

Sinks work on both multi-threaded and current-thread Tokio runtimes; on a current-thread runtime the stdout and file sinks write inline. `load_rules` is synchronous, so it can only resolve dynamic sources referenced by pipelines on a multi-threaded runtime and returns an error on a current-thread one, leaving the previous engine in place. {{ added "0.25.0" }}

`load_rules` logs rule documents that fail to parse, leaves them out, and reports how many in `EngineStats::parse_errors`. It returns an error, leaving the previous engine in place, when every rule fails to parse, or on any parse error after `set_strict_rules(true)`. Hot-reload carries the strict setting forward. {{ added "0.26.0" }}

## Hot-reload

`LogProcessor` holds the live `RuntimeEngine` in an `ArcSwap`. `processor.reload_rules()` rebuilds it from disk and atomically swaps it in; in-flight batches finish against the old engine, the next batch sees the new one. Wire a file watcher (`notify`), a `SIGHUP` handler, or an HTTP endpoint to call it:

```rust
use rsigma_runtime::LogProcessor;
use std::sync::Arc;

let processor = Arc::new(processor);
let p = processor.clone();

tokio::spawn(async move {
    // On reload trigger:
    match p.reload_rules() {
        Ok(stats) => println!("reloaded {} rules", stats.detection_rules),
        Err(e) => eprintln!("reload failed: {e}"),
    }
});
```

The daemon's `notify` + SIGHUP + `POST /api/v1/reload` wiring lives in `rsigma-cli`; `LogProcessor` just exposes the primitive.

## Post-evaluation enrichment

`EnrichmentPipeline` runs after the engine has produced a `ProcessResult` and before the sink serializes it. Each enricher implements the `Enricher` trait, declares a `kind: detection | correlation` at construction, and writes into `RuleHeader::enrichments` under a configured `inject_field`. The pipeline filters per-result by declared kind against the body variant, applies the optional `Scope` filter, wraps the call in a per-enricher timeout, and applies the configured `OnError` policy on failure: `Enricher::on_miss` for an `EnrichErrorKind::Miss`, and `Enricher::on_error` otherwise. Misses log at debug level, and other failures log at most one warning per enricher id every 10 seconds with a `suppressed` count. {{ added "0.28.0" }}

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

Wire a `MetricsHook` via `EnrichmentPipeline::with_metrics` to surface `rsigma_enrichment_total`, `rsigma_enrichment_duration_seconds`, and `rsigma_enrichment_queue_depth` (and the HTTP cache, MMDB, and DNS counters) into your own metrics backend. The daemon's Prometheus-backed `Metrics` struct implements the hook.

For YAML-driven configuration, use the `enrichment::config` loader: `load_enrichers_file(path)` parses an enrichers config file into an `EnrichersFile`, and `build_enrichers(file)` or `build_enrichers_full(file, EnricherResources, metrics)` turns it into an `EnrichmentPipeline` (validating template namespaces and bespoke types). Pass `EnricherResources { source_cache, stix_store }` when building `lookup` or `stix` enrichers. The daemon and the MCP server's `evaluate_events` tool share this loader.

Enricher templates resolve `${detection.fields.<name>}` from the event when the rule did not match on `<name>`, and `${detection.event.*}` always reads the event, so both need the event retained on the result. When you build your own engine, pass `pipeline.needs_event()` to `RuntimeEngine::set_include_event` (or `LogProcessor::set_include_event`), and call `strip_auto_retained_event` on each result after `pipeline.run` unless you want events delivered: {{ added "0.28.0" }}

```rust
use rsigma_runtime::{EnrichmentPipeline, LogProcessor, strip_auto_retained_event};

fn wire(processor: &LogProcessor, pipeline: &EnrichmentPipeline) {
    processor.set_include_event(pipeline.needs_event());
}

async fn enrich(pipeline: &EnrichmentPipeline, results: &mut Vec<rsigma_eval::EvaluationResult>) {
    pipeline.run(results).await;
    for result in results.iter_mut() {
        strip_auto_retained_event(result);
    }
}
```

Only `build_enrichers` and `build_enrichers_full` compute `needs_event`. A pipeline assembled by hand with `EnrichmentPipeline::new` always reports `false`, so if your enrichers render `${detection.fields.*}` or `${detection.event.*}`, call `set_include_event(true)` yourself. {{ added "0.28.0" }}

For the operator-facing schema, the seven primitives, and the recipe catalog, see [Enrichers](../guide/enrichers.md).

## Custom metrics

Implement `MetricsHook` to ship metrics into your own registry. `NoopMetrics` is a no-op implementation suitable for tests and embedders that do not care. The daemon's own `prometheus`-backed implementation lives in `rsigma-cli/src/daemon/metrics.rs` and is a good template. The hook methods mirror the [Prometheus metrics](../reference/metrics.md) the daemon exposes.

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
use rsigma_eval::pipeline::sources::DynamicSource;

let resolver = DefaultSourceResolver::new();
// `source` is a DynamicSource loaded from a standalone sources YAML file.
let value = resolver.resolve(&source).await?;
```

The full reusable-source spec (types, data formats, extract languages, refresh policies) lives in [Dynamic Sources](../reference/dynamic-sources.md). `RefreshScheduler` runs the periodic refresh policies; `TemplateExpander` substitutes `${source.X}` references into pipelines, and `lookup` enrichers can read the same `SourceCache`.

`LogProcessor::rebuild_from_sources` loads rules again from cached source values (`SourceFetch::CacheFirst`) and leaves the current engine in place when that load fails. `WatchlistRegistry` holds the unexpired indicators for `type: watchlist` sources. After a successful reload or rebuild, `apply_reference_limits` sets each watchlist's cap from the pipelines that loaded, and `restore` reports how many saved rows were left out because the source was already at that cap. `SourceResolver::cached` and `store_cached` let a push update the cache that a later rebuild or lookup reads. {{ added "0.28.0" }}

With the `stix-source` feature, `DefaultSourceResolver::prepare_taxii` builds the TAXII clients before the first resolve. `with_stix_clock` fixes the clock used for indicator lifecycle. File and HTTP sources with `format: stix` use the same build. Array values escape `\`, `*`, and `?`, and the `indicators` keys stay raw. A TAXII poll reads a `PollBudget` derived from `max_indicators` and `page_size`, and the next refresh continues when that poll stops with an added-date. Indicators past the cap stay while the retained set is under twice `max_indicators`. The feature-off resolver rejects both with an error that names `stix-source`. {{ added "0.28.0" }}

## Error handling

`RuntimeError` from `thiserror` wraps `EvalError`, `SigmaParserError`, `io::Error`, and `SourceError`. Per-event errors (failed input parse, sink write) are surfaced through the result types instead of aborting; the daemon's optional DLQ collects them.

## See also

- [Streaming Detection](../guide/streaming-detection.md) for the operator-facing daemon walkthrough.
- [Architecture](../reference/architecture.md) for the runtime data flow.
- [Dynamic Sources](../reference/dynamic-sources.md) for the source spec.
- [Dynamic Pipelines](../reference/dynamic-pipelines.md) for pipeline binding.
- [`rsigma-runtime` README](https://github.com/timescale/rsigma/blob/main/crates/rsigma-runtime/README.md).
- [docs.rs/rsigma-runtime](https://docs.rs/rsigma-runtime).
