# RSigma

[![CI](https://github.com/timescale/rsigma/actions/workflows/ci.yml/badge.svg)](https://github.com/timescale/rsigma/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/rsigma.svg)](https://crates.io/crates/rsigma)
[![MSRV](https://img.shields.io/badge/MSRV-1.88.0-blue)](https://github.com/timescale/rsigma/blob/main/Cargo.toml)
[![Docker](https://img.shields.io/badge/ghcr.io-rsigma-blue?logo=docker)](https://ghcr.io/timescale/rsigma)
[![GitHub Release](https://img.shields.io/github/v/release/timescale/rsigma)](https://github.com/timescale/rsigma/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

The RSigma project is a complete Rust toolkit for the [Sigma](https://sigmahq.io/) detection standard, including a parser, evaluation engine, rule conversion, streaming runtime, linter, CLI, and LSP.

RSigma parses Sigma YAML rules into a strongly-typed AST, compiles them into optimized matchers, and evaluates them against log events in real time. It handles stateful correlation logic in-process with memory-efficient compressed event storage. Or as Zack Allen put it in [DEW #149](https://www.detectionengineering.net/i/191079258/detection-engineering-gem), "RSigma is essentially a SIEM."

You can send events in many formats, including JSON, syslog (RFC 3164/5424), logfmt, CEF, EVTX (Windows Event Log), plain text, and OTLP (OpenTelemetry Protocol), with auto-detection by default. pySigma-compatible processing pipelines handle field mapping and backend configuration. OTLP support lets any OpenTelemetry-compatible agent (Grafana Alloy, Vector, Fluent Bit, OTel Collector) forward logs to RSigma via HTTP or gRPC for detection.

For rule quality and editor integration, a built-in linter validates rules against 66 checks derived from the Sigma v2.1.0 specification, and an LSP server provides real-time diagnostics, completions, hover documentation, and quick-fix code actions in any editor.

## Supported Features

* Parse Sigma YAML into a strongly-typed AST with support for detection, correlation, and filter rules
* Compile and evaluate rules against JSON events in real time with stateless detection and stateful correlation (sliding windows, group-by, chaining, suppression)
* Accept JSON, syslog (RFC 3164/5424), logfmt, CEF, EVTX (Windows Event Log), plain text, and OTLP logs with format auto-detection
* pySigma-compatible processing pipelines for field mapping, transformations, conditions, and finalizers
* Dynamic pipelines: populate any pipeline value from external sources (HTTP, files, commands, NATS) with template expansion, auto-refresh, and data extraction via jq, JSONPath, or CEL
* Convert rules into backend-native query strings via a pluggable backend trait (PostgreSQL/TimescaleDB SQL, LynxDB)
* Optional eval prefilters for large rule sets: bloom filter for substring matchers (`--bloom-prefilter`) and cross-rule Aho-Corasick index for whole-rule pruning (`--cross-rule-ac`, requires `daachorse-index` feature)
* Run as a streaming detection daemon with hot-reload, Prometheus metrics, and HTTP/NATS/OTLP input
* NATS JetStream support with authentication (credentials, mTLS), replay, consumer groups, and dead-letter queues
* OTLP support for any OpenTelemetry-compatible agent (Grafana Alloy, Vector, Fluent Bit, OTel Collector) via HTTP or gRPC
* Built-in linter with 66 checks, four severity levels, a full suppression system, and auto-fix (`--fix`) for 13 safe rules
* LSP server with real-time diagnostics, completions, hover documentation, document symbols, and quick-fix code actions
* Multi-arch Docker images (linux/amd64, linux/arm64) with cosign signatures, SBOM, and SLSA Build L3 provenance
* Cross-platform binaries for Linux, macOS, and Windows on amd64 and arm64

## Crates

| Crate | Description |
|-------|-------------|
| [`rsigma-parser`](crates/rsigma-parser/) | Parse Sigma YAML into a strongly-typed AST |
| [`rsigma-eval`](crates/rsigma-eval/) | Compile and evaluate rules against JSON events |
| [`rsigma-convert`](crates/rsigma-convert/) | Transform rules into backend-native query strings |
| [`rsigma-runtime`](crates/rsigma-runtime/) | Streaming runtime with input adapters, log processor, and hot-reload |
| [`rsigma`](crates/rsigma-cli/) | CLI for parsing, validating, linting, evaluating, converting rules, field catalog, and running a detection daemon |
| [`rsigma-lsp`](crates/rsigma-lsp/) | Language Server Protocol (LSP) server for IDE support |

> [!TIP]
> To learn more about RSigma, read these articles:
> 
> - [Pattern Detection and Correlation in JSON Logs](https://mostafa.dev/pattern-detection-and-correlation-in-json-logs-fab16334e4ee)
> - [Streaming Logs to RSigma for Real-Time Detection](https://mostafa.dev/streaming-logs-to-rsigma-for-real-time-detection-72084b8041ad)
> - [Building a Detection Layer on PostgreSQL with Sigma Rules](https://mostafa.dev/building-a-detection-layer-on-postgresql-with-sigma-rules-042caeb42b2a)
> - [Security Observability with RSigma and the LGTM Stack](https://mostafa.dev/security-observability-with-rsigma-and-the-lgtm-stack-375ccd260795)
> - [Wiring Live Threat Intel into Sigma Detection with Dynamic Pipelines](https://mostafa.dev/wiring-live-threat-intel-into-sigma-detection-with-dynamic-pipelines-4de29b4af7ca)

> [!NOTE]
> RSigma has been featured in:
> 
> - [Detection Engineering Weekly #149](https://www.detectionengineering.net/i/191079258/detection-engineering-gem) (March 2026)
>   *"Building a tool like RSigma is challenging because the Sigma specification has evolved into a robust domain-specific language over the years."*
> - [tl;dr sec #320](https://tldrsec.com/p/tldr-sec-320#blue-team) (March 2026)
>   *"Accurately evaluating the full spectrum of what Sigma rules can express is quite complex, it's pretty neat to read about how RSigma handles all of these conditional expressions, correlating across rules, etc."*
> - [The Deep Purple Sec by BlackNoise - March 2026](https://www.blacknoise.co/the-deep-purple-sec-march-2026/) (April 2026)
>   *"Defensive teams can pipe logs through CLI commands, apply field-mapping pipelines, and chain correlations for multi-stage attack detection."*
> - [Detection Engineering Weekly #154](https://www.detectionengineering.net/i/195467950/state-of-the-art) (April 2026)
>   *"RSigma is not a SIEM, but it's an impressive feat to build a self-contained Rust binary that operates much like one. For teams doing pre-SIEM rule validation or forensics, it's a solid plug-and-play option."*

## Installation

```bash
# Build all crates
cargo build --release --all-features --workspace

# Install the CLI
cargo install --locked rsigma

# Install the LSP server
cargo install --locked --path crates/rsigma-lsp
```

### Docker

Multi-arch images (linux/amd64, linux/arm64) are published to GHCR on every release.

```bash
docker pull ghcr.io/timescale/rsigma:latest
docker run --rm ghcr.io/timescale/rsigma:latest --help
```

Run with full runtime hardening:

```bash
docker run --rm \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges:true \
  -v /path/to/rules:/rules:ro \
  ghcr.io/timescale/rsigma:latest validate /rules/
```

Verify the image signature:

```bash
cosign verify \
  --certificate-identity-regexp 'github.com/timescale/rsigma' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/timescale/rsigma:latest
```

## Quick Start

```bash
# Evaluate a single event against Sigma rules
rsigma eval -r rules/ -e '{"CommandLine": "cmd /c whoami"}'

# Stream NDJSON from stdin
cat events.ndjson | rsigma eval -r rules/

# Run as a daemon with hot-reload and Prometheus metrics
rsigma daemon -r rules/ -p ecs.yml --api-addr 0.0.0.0:9090

# Accept events via HTTP POST
rsigma daemon -r rules/ --input http

# Convert rules to PostgreSQL SQL
rsigma convert rules/ -t postgres
```

See the [CLI README](crates/rsigma-cli/) for complete documentation of all subcommands and flags.

### Daemon Input Modes

The daemon accepts events from multiple sources. The `--input` flag selects the primary source, and OTLP is always available as an additional ingestion path when the `daemon-otlp` feature is enabled.

```bash
# stdin (default): pipe events from any source
hel run | rsigma daemon -r rules/ -p ecs.yml

# HTTP: POST NDJSON events to /api/v1/events
rsigma daemon -r rules/ --input http
curl -X POST http://localhost:9090/api/v1/events -d '{"CommandLine":"whoami"}'

# NATS JetStream (requires daemon-nats feature)
rsigma daemon -r rules/ --input nats://localhost:4222/events.> --output nats://localhost:4222/detections

# OTLP (requires daemon-otlp feature): always active alongside any --input mode
# Agents (Grafana Alloy, Vector, Fluent Bit, OTel Collector) send logs to /v1/logs (HTTP) or gRPC
rsigma daemon -r rules/ --input http
curl -X POST http://localhost:9090/v1/logs -H 'Content-Type: application/json' -d '{"resourceLogs":[...]}'
```

### NATS Streaming

Production-grade NATS JetStream support with authentication, at-least-once delivery, replay, and horizontal scaling via consumer groups.

```bash
# Credentials file authentication
rsigma daemon -r rules/ --input nats://nats.example.com:4222/events.> --nats-creds /etc/rsigma/nats.creds

# Mutual TLS
rsigma daemon -r rules/ --input nats://localhost:4222/events.> \
  --nats-tls-cert client.pem --nats-tls-key client-key.pem --nats-require-tls

# Replay from a point in time
rsigma daemon -r rules/ --input nats://localhost:4222/events.> --replay-from-time 2026-04-30T00:00:00Z

# Replay with automatic state restore (forward catch-up)
rsigma daemon -r rules/ --input nats://localhost:4222/events.> --replay-from-sequence 1001 --state-db state.db

# Consumer groups for horizontal scaling
rsigma daemon -r rules/ --input nats://localhost:4222/events.> --consumer-group detection-workers

# Dead-letter queue for events that fail processing
rsigma daemon -r rules/ --input nats://localhost:4222/events.> --dlq file:///var/log/rsigma-dlq.ndjson
```

### Input Formats and Pipelines

Events are parsed with auto-detection by default (JSON, syslog, plain text). Feature-gated formats: `logfmt`, `cef`, `evtx`. Processing pipelines handle field mapping between source schemas and Sigma field names.

```bash
# With a processing pipeline for field mapping
rsigma eval -r rules/ -p pipelines/ecs.yml -e '{"process.command_line": "whoami"}'

# Explicit syslog with timezone offset
tail -f /var/log/syslog | rsigma eval -r rules/ --input-format syslog --syslog-tz +0530

# logfmt (requires logfmt feature)
rsigma eval -r rules/ --input-format logfmt < app.log

# CEF / ArcSight (requires cef feature)
rsigma eval -r rules/ --input-format cef < arcsight.log

# EVTX / Windows Event Log (requires evtx feature)
rsigma eval -r rules/ -e @security.evtx
```

### Dynamic Pipelines

Standard Sigma pipelines are static: every value is hardcoded in YAML. RSigma extends this with dynamic pipelines where external data sources feed into any part of a pipeline via `${source.*}` template references. This means field mappings, condition values, and even entire transformation blocks can be populated from live APIs, configuration files, commands, or NATS subjects.

```yaml
# pipeline.yml with dynamic sources
name: dynamic_example
sources:
  - id: threat_intel
    type: http
    url: https://intel.example.com/v1/iocs
    format: json
    extract: ".indicators[].ip"
    refresh: 300s
    timeout: 10s
    on_error: use_cached

  - id: field_map
    type: file
    path: /etc/rsigma/fields.json
    format: json
    refresh: watch

transformations:
  - id: map_fields
    type: field_name_mapping
    mapping: ${source.field_map}

  - id: block_known_bad
    type: add_condition
    conditions:
      - field: DestinationIp
        value: ${source.threat_intel}
```

```bash
# Test source resolution offline
rsigma resolve -p pipeline.yml --pretty

# Run the daemon with a dynamic pipeline
rsigma daemon -r rules/ -p pipeline.yml
```

Sources support four types (file, HTTP, command, NATS), multiple data formats (JSON, YAML, lines, CSV), three extraction languages (jq, JSONPath, CEL), configurable refresh policies, error handling with caching, and include directives for injecting entire transformation blocks. See the [CLI README](crates/rsigma-cli/README.md#dynamic-pipelines) for the full reference and the [runtime README](crates/rsigma-runtime/README.md) for the library API.

### Rule Conversion

Convert Sigma rules into backend-native queries for historical threat hunting.

```bash
# PostgreSQL SQL
rsigma convert rules/ -t postgres

# PostgreSQL with OCSF field mapping
rsigma convert rules/ -t postgres -p pipelines/ocsf_postgres.yml

# PostgreSQL views, TimescaleDB continuous aggregates, or sliding window correlation
rsigma convert rules/ -t postgres -f view
rsigma convert rules/ -t postgres -f continuous_aggregate
rsigma convert rules/ -t postgres -f sliding_window

# JSONB mode: access fields inside a JSONB column
rsigma convert rules/ -t postgres -O table=okta_events -O json_field=data -O timestamp_field=time

# LynxDB search queries
rsigma convert rules/ -t lynxdb

# List all fields referenced by a ruleset
rsigma fields -r rules/

# Show fields after pipeline mapping
rsigma fields -r rules/ -p ecs.yml --json

# List available backends and formats
rsigma list-targets
rsigma list-formats postgres
```

### Library Usage

Or use the library directly:

```rust
use rsigma_parser::parse_sigma_yaml;
use rsigma_eval::Engine;
use rsigma_eval::event::JsonEvent;
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
let mut engine = Engine::new();
engine.add_collection(&collection).unwrap();

let event = JsonEvent::borrow(&json!({"CommandLine": "cmd /c whoami"}));
let matches = engine.evaluate(&event);
assert_eq!(matches[0].rule_title, "Detect Whoami");
```

## Streaming Runtime

`rsigma-runtime` provides a reusable pipeline for streaming log detection. It handles input parsing (JSON, syslog, logfmt, CEF, plain text, auto-detect), batch evaluation with parallel detection + sequential correlation, atomic hot-reload via `ArcSwap`, and pluggable metrics.

```rust
use std::sync::Arc;
use rsigma_eval::CorrelationConfig;
use rsigma_runtime::{InputFormat, LogProcessor, NoopMetrics, RuntimeEngine};

// Load rules
let mut engine = RuntimeEngine::new(
    "rules/".into(),
    vec![],
    CorrelationConfig::default(),
    false,
);
engine.load_rules().unwrap();

let processor = LogProcessor::new(engine, Arc::new(NoopMetrics));

// Process a batch of raw log lines (any format)
let batch = vec![
    r#"{"CommandLine": "cmd /c whoami", "EventID": 1}"#.to_string(),
];
let results = processor.process_batch_with_format(
    &batch,
    &InputFormat::Json,
    None,
);

for result in &results {
    for det in &result.detections {
        println!("Detection: {}", det.rule_title);
    }
}
```

Input formats are selected via `--input-format` on the CLI or `InputFormat` in the library. Auto-detect (the default) tries JSON, syslog, and plain text. Feature-gated formats: `logfmt`, `cef`, `evtx`. EVTX files (`.evtx`) are binary and auto-detected by file extension when using the `@path` syntax.

See [`examples/jsonl_stdin.rs`](crates/rsigma-runtime/examples/jsonl_stdin.rs) and [`examples/tail_syslog.rs`](crates/rsigma-runtime/examples/tail_syslog.rs) for complete working examples.

## Observability

The daemon emits Prometheus metrics on `/metrics` and structured JSON logs to stderr via [`tracing`](https://docs.rs/tracing). Verbosity is controlled with `RUST_LOG` (default `info`). Useful filter targets:

| Filter | Surfaces |
|--------|----------|
| `RUST_LOG=info,tower_http=debug` | HTTP API access logs (method, URI, status, latency) for every REST request |
| `RUST_LOG=info,rsigma=debug` | batch processing spans, DLQ routing, OTLP per-request fields, snapshot save duration |
| `RUST_LOG=info,rsigma_runtime::sources=debug` | dynamic source resolution and refresh scheduler |
| `RUST_LOG=info,rsigma_eval=debug` | correlation engine internals (chain depth, hard-cap eviction at `warn`) |

`tracing` spans installed on hot paths (batch processing, source resolution, OTLP ingest, rule loading) double as profiling hooks consumable by `tokio-console` or `tracing-timing` without code changes. Non-daemon subcommands default to human-readable output; pass `--log-format json` (or `text`) to additionally install a stderr subscriber for CI/log aggregation use cases.

## Architecture

Everything starts with a Sigma rule in YAML format:

- **Parsing:** `serde_yaml` deserializes the YAML into a raw value, then `rsigma-parser` turns it into a strongly-typed AST. A PEG grammar (`sigma.pest`) handles the document structure while a Pratt parser (`condition.rs`) handles condition expressions. Supporting modules define value types (`value.rs`: `SigmaStr`, wildcards, timespans) and AST nodes (`ast.rs`: modifiers, enums). The result is a `SigmaRule`, `CorrelationRule`, `FilterRule`, or `SigmaCollection`.

From there, the AST can go in three directions depending on what you need:

- **Evaluation:** `rsigma-eval` compiles rules into optimized matchers (`compiler.rs`), runs stateless detection through `Engine`, and tracks stateful correlation (`correlation.rs`: sliding windows, group-by, chaining, suppression) across events. Processing pipelines handle field mapping, transformations, conditions, and finalizers before compilation. Dynamic pipelines extend this with `${source.*}` template references that are resolved at runtime from external data sources. Events are accessed through a trait with implementations for JSON, key-value, and plain text.

- **Conversion:** `rsigma-convert` transforms rules into backend-native query strings through a pluggable `Backend` trait. A condition walker traverses the AST and delegates to the backend for each node. `TextQueryConfig` exposes ~90 configuration fields for text-based backends. Concrete implementations include PostgreSQL/TimescaleDB (SQL for historical threat hunting) and LynxDB (SPL2-compatible search queries for log analytics).

- **Editor support:** `rsigma-lsp` provides an LSP server over stdio (via `tower-lsp`) with real-time diagnostics (lint + parse + compile errors), completions, hover documentation, document symbols, and code actions. Works with VSCode, Neovim, Helix, Zed, and any LSP-capable editor.

When running as a streaming detection engine, `rsigma-eval` feeds into `rsigma-runtime`:

- **Input:** Format adapters parse raw log lines (JSON, syslog, logfmt\*, CEF\*, plain text, with auto-detection) into `EventInputDecoded`. EVTX\* files are parsed directly from binary via `EvtxFileReader`. Sources include stdin, HTTP POST, NATS JetStream, and OTLP\* (HTTP protobuf/JSON and gRPC).
- **Dynamic sources:** `SourceResolver` fetches data from files, commands, HTTP APIs, and NATS subjects. Resolved values are injected into pipelines via `TemplateExpander`. A `SourceCache` (in-memory + optional SQLite) provides fallback data. `RefreshScheduler` manages auto-refresh (interval, file watch, NATS push, on-demand). Extraction supports jq, JSONPath, and CEL.
- **Processing:** `LogProcessor` runs batch evaluation with parallel detection and sequential correlation. `RuntimeEngine` wraps `Engine` and `CorrelationEngine` with rule loading and `ArcSwap` hot-reload.
- **Output:** Sinks write detection results to stdout, files, or NATS. Multiple sinks can run in fan-out. The output is `MatchResult` and `CorrelationResult`, containing rule title, id, level, tags, matched selections, field matches, aggregated values, and optionally the triggering events.

Feature-gated items are marked with \* in the diagram.

<details>
<summary>Architecture diagram</summary>

```
                    ┌──────────────────┐
   YAML input ───>  │   serde_yaml     │──> Raw YAML Value
                    └──────────────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │   parser.rs      │──> Typed AST
                    │  (YAML → AST)    │   (SigmaRule, CorrelationRule,
                    └──────────────────┘    FilterRule, SigmaCollection)
                             │
            ┌────────────────┼──────────────┐
            ▼                ▼              ▼
     ┌────────────┐  ┌────────────┐  ┌────────────┐
     │ sigma.pest │  │  value.rs  │  │   ast.rs   │
     │  (PEG      │  │ (SigmaStr, │  │ (AST types │
     │  grammar)  │  │  wildcards,│  │  modifiers,│
     │     +      │  │  timespan) │  │  enums)    │
     │condition.rs│  └────────────┘  └────────────┘
     │  (Pratt    │
     │  parser)   │
     └────────────┘
           │
     ┌─────┴───────────────────────────────────────────────────────────┐
     │                                   │                             │
     ▼                                   ▼                             ▼
    ┌─────────────────────────┐   ┌─────────────────────┐   ┌────────────────────┐
    │      rsigma-eval        │   │   rsigma-convert    │   │    rsigma-lsp      │
    │                         │   │                     │   │                    │
    │  Event trait ──>        │   │  Backend trait ──>  │   │  LSP server over   │
    │    JsonEvent, KvEvent,  │   │    pluggable query  │   │  stdio (tower-lsp) │
    │    PlainEvent           │   │    generation       │   │                    │
    │                         │   │                     │   │  • diagnostics     │
    │  pipeline/ ──>          │   │  TextQueryConfig    │   │    (lint + parse   │
    │    Pipeline, conditions,│   │    ──> ~90 config   │   │     + compile)     │
    │    transformations,     │   │    fields for text  │   │  • completions     │
    │    state, finalizers    │   │    query backends   │   │  • hover           │
    │                         │   │                     │   │  • document        │
    │  compiler.rs ──>        │   │  Condition walker,  │   │    symbols         │
    │    CompiledRule         │   │    deferred exprs,  │   │                    │
    │  engine.rs ──>          │   │    conversion state │   │  Editors:          │
    │    Engine (stateless)   │   │                     │   │  VSCode, Neovim,   │
    │                         │   │  backends/ ──>      │   │  Helix, Zed, ...   │
    │  correlation.rs ──>     │   │    TextQueryTest,   │   └────────────────────┘
    │    sliding windows,     │   │    PostgreSQL/      │
    │    group-by, chaining,  │   │    TimescaleDB,     │
    │    suppression, events  │   │    LynxDB           │
    │                         │   └─────────────────────┘
    │                         │
    │  rsigma.* custom        │
    │    attributes           │
    └─────────────────────────┘
              │
              ▼
    ┌──────────────────────────────────────────┐
    │            rsigma-runtime                │
    │                                          │
    │  input/ ──> format adapters:             │
    │    JSON, syslog, logfmt*, CEF*,          │
    │    EVTX*, plain text, auto-detect        │
    │    ↓ raw line → EventInputDecoded        │
    │                                          │
    │  LogProcessor ──> batch evaluation       │
    │    ArcSwap hot-reload, MetricsHook,      │
    │    EventFilter (JSON payload extraction) │
    │                                          │
    │  RuntimeEngine ──> wraps Engine +        │
    │    CorrelationEngine with rule loading   │
    │                                          │
    │  io/ ──> EventSource (stdin, HTTP, NATS) │
    │          OTLP* (HTTP + gRPC)             │
    │          Sink (stdout, file, NATS)       │
    └──────────────────────────────────────────┘
              │                (* = feature-gated)
              ▼
     ┌────────────────────┐
     │  MatchResult       │──> rule title, id, level, tags,
     │  CorrelationResult │   matched selections, field matches,
     └────────────────────┘   aggregated values, optional events
```

</details>

A [Mermaid version](assets/architecture.mmd) of this diagram is also available.

## Performance

RSigma is designed for high-throughput detection. On an Apple M4 Pro:

- **Parsing**: 12.7 MiB/s for 1000 rules
- **Detection**: 1.06M events/sec (JSON, 100 rules)
- **Correlation**: 569K events/sec (temporal + event-count)
- **Dynamic pipelines**: 2.71M events/sec once built (no per-event overhead)

See [BENCHMARKS.md](BENCHMARKS.md) for full Criterion results across all subsystems.

## Reference

- [pySigma](https://github.com/SigmaHQ/pySigma): reference Python implementation
- [Sigma Specification V2.1.0](https://github.com/SigmaHQ/sigma-specification): formal specification
- [sigma-rust](https://github.com/jopohl/sigma-rust): Pratt parsing approach
- [sigmars](https://github.com/crowdalert/sigmars): correlation support patterns
- [sigma_engine](https://github.com/SigmaHQ/sigma_engine): official SigmaHQ Rust library for parsing and matching Sigma rules against events
- [pySigma-backend-sqlite](https://github.com/SigmaHQ/pySigma-backend-sqlite): SQLite backend for pySigma (inspiration for the PostgreSQL backend)
- [pySigma-backend-athena](https://github.com/SigmaHQ/pySigma-backend-athena): AWS Athena backend for pySigma (SELECT fields, CTE-based correlation, sliding window patterns)

## Releasing

All crates share a single version (set in the workspace `Cargo.toml`) and are published together.

### Publishing a new version

1. Bump the version in the root `Cargo.toml`.
2. Commit, push to `main`.
3. Create a GitHub Release (e.g. tag `v0.2.0`). The `publish.yml` workflow triggers automatically and publishes all crates in dependency order.

### Dry run

Trigger the workflow manually via **Actions → Publish to crates.io → Run workflow**.
Manual runs automatically pass `--dry-run` to every `cargo publish` invocation.

### Recovering from a partial failure

If the workflow fails midway (e.g. `rsigma-parser` was published but `rsigma-eval` failed), re-running the workflow will fail at the already-published crate. To recover, publish the remaining crates manually in order:

```bash
# Skip crates that were already published successfully
cargo publish -p rsigma-eval && sleep 30
cargo publish -p rsigma
cargo publish -p rsigma-lsp
```

## License

MIT
