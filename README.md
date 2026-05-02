# RSigma

A complete Rust toolkit for the [Sigma](https://github.com/SigmaHQ/sigma) detection standard, including parser, evaluation engine, rule conversion, streaming runtime, linter, CLI, and LSP. RSigma parses Sigma YAML rules into a strongly-typed AST, compiles them into optimized matchers, and evaluates them against log events in real time. It accepts JSON, syslog (RFC 3164/5424), logfmt, CEF, and plain text, with auto-detection by default, and runs detection and stateful correlation logic in-process with memory-efficient compressed event storage. pySigma-compatible processing pipelines handle field mapping and backend configuration. A conversion engine transforms rules into backend-native query strings (SQL, SPL, KQL, Lucene, etc.) via a pluggable backend trait. No external SIEM required. A built-in linter validates rules against 66 checks derived from the Sigma v2.1.0 specification with four severity levels, a full suppression system, and auto-fix support (`--fix`) for 13 safe rules. An LSP server provides real-time diagnostics, completions, hover documentation, and quick-fix code actions in any editor.

| Crate | Description |
|-------|-------------|
| [`rsigma-parser`](crates/rsigma-parser/) | Parse Sigma YAML into a strongly-typed AST |
| [`rsigma-eval`](crates/rsigma-eval/) | Compile and evaluate rules against JSON events |
| [`rsigma-convert`](crates/rsigma-convert/) | Transform rules into backend-native query strings |
| [`rsigma-runtime`](crates/rsigma-runtime/) | Streaming runtime with input adapters, log processor, and hot-reload |
| [`rsigma`](crates/rsigma-cli/) | CLI for parsing, validating, linting, evaluating, converting rules, and running a detection daemon |
| [`rsigma-lsp`](crates/rsigma-lsp/) | Language Server Protocol (LSP) server for IDE support |

> [!TIP]
> To learn more about RSigma, read these articles:
> 
> - [Pattern Detection and Correlation in JSON Logs](https://mostafa.dev/pattern-detection-and-correlation-in-json-logs-fab16334e4ee)
> - [Streaming Logs to RSigma for Real-Time Detection](https://mostafa.dev/streaming-logs-to-rsigma-for-real-time-detection-72084b8041ad)
> - [Building a Detection Layer on PostgreSQL with Sigma Rules](https://mostafa.dev/building-a-detection-layer-on-postgresql-with-sigma-rules-042caeb42b2a)

> [!NOTE]
> RSigma has been featured in:
> 
> - [Detection Engineering Weekly #149](https://www.detectionengineering.net/i/191079258/detection-engineering-gem) (March 2026)
>   *"Building a tool like RSigma is challenging because the Sigma specification has evolved into a robust domain-specific language over the years."*
> - [tl;dr sec #320](https://tldrsec.com/p/tldr-sec-320#blue-team) (March 2026)
>   *"Accurately evaluating the full spectrum of what Sigma rules can express is quite complex, it's pretty neat to read about how RSigma handles all of these conditional expressions, correlating across rules, etc."*
> - [Detection Engineering Weekly #154](https://www.detectionengineering.net/i/195467950/state-of-the-art) (April 2026)
>   *"RSigma is not a SIEM, but it's an impressive feat to build a self-contained Rust binary that operates much like one. For teams doing pre-SIEM rule validation or forensics, it's a solid plug-and-play option."*

## Installation

```bash
# Build all crates
cargo build --release

# Install the CLI
cargo install rsigma

# Install the LSP server
cargo install --path crates/rsigma-lsp
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

Evaluate events against Sigma rules from the command line:

```bash
# Single event (inline JSON)
rsigma eval -r path/to/rules/ -e '{"CommandLine": "cmd /c whoami"}'

# Stream NDJSON from stdin
cat events.ndjson | rsigma eval -r path/to/rules/

# Long-running daemon with hot-reload and Prometheus metrics
hel run | rsigma daemon -r rules/ -p ecs.yml --api-addr 0.0.0.0:9090

# Daemon with file output (detections appended as NDJSON)
hel run | rsigma daemon -r rules/ --output file:///var/log/detections.ndjson

# Fan-out: write detections to both stdout and a file
hel run | rsigma daemon -r rules/ --output stdout --output file:///tmp/detections.ndjson

# Accept events via HTTP POST instead of stdin
rsigma daemon -r rules/ --input http
# Then: curl -X POST http://localhost:9090/api/v1/events -d '{"CommandLine":"whoami"}'

# NATS JetStream source and sink (requires daemon-nats feature)
rsigma daemon -r rules/ --input nats://localhost:4222/events.> --output nats://localhost:4222/detections

# NATS with credentials file authentication
rsigma daemon -r rules/ --input nats://nats.example.com:4222/events.> --nats-creds /etc/rsigma/nats.creds

# NATS with mutual TLS
rsigma daemon -r rules/ --input nats://localhost:4222/events.> \
  --nats-tls-cert client.pem --nats-tls-key client-key.pem --nats-require-tls

# Dead-letter queue for events that fail processing
rsigma daemon -r rules/ --input nats://localhost:4222/events.> --dlq file:///var/log/rsigma-dlq.ndjson

# Replay from a specific stream sequence
rsigma daemon -r rules/ --input nats://localhost:4222/events.> --replay-from-sequence 42

# Replay from a point in time
rsigma daemon -r rules/ --input nats://localhost:4222/events.> --replay-from-time 2026-04-30T00:00:00Z

# Replay with automatic state restore (forward catch-up)
rsigma daemon -r rules/ --input nats://localhost:4222/events.> --replay-from-sequence 1001 --state-db state.db

# Force restore correlation state during replay (overrides automatic decision)
rsigma daemon -r rules/ --input nats://localhost:4222/events.> --replay-from-sequence 1 --state-db state.db --keep-state

# Consumer groups for horizontal scaling (multiple instances share workload)
rsigma daemon -r rules/ --input nats://localhost:4222/events.> --consumer-group detection-workers

# Skip events without timestamps for correlation (useful for forensic replay)
rsigma daemon -r rules/ --timestamp-fallback skip

# Tune pipeline: micro-batch 64 events per lock, 50K buffer, 10s drain on shutdown
rsigma daemon -r rules/ --batch-size 64 --buffer-size 50000 --drain-timeout 10

# With a processing pipeline for field mapping
rsigma eval -r rules/ -p pipelines/ecs.yml -e '{"process.command_line": "whoami"}'

# Multi-format input (auto-detect is the default: JSON → syslog → plain)
rsigma daemon -r rules/ --input-format auto

# Explicit syslog with timezone offset
tail -f /var/log/syslog | rsigma eval -r rules/ --input-format syslog --syslog-tz +0530

# logfmt (requires logfmt feature)
rsigma eval -r rules/ --input-format logfmt < app.log

# CEF / ArcSight (requires cef feature)
rsigma eval -r rules/ --input-format cef < arcsight.log

# Convert rules to backend-native queries
rsigma convert rules/ -t test

# Convert with a processing pipeline and specific output format
rsigma convert rules/ -t test -p pipelines/ecs.yml -f state

# Convert to PostgreSQL SQL
rsigma convert rules/ -t postgres

# Convert to PostgreSQL with OCSF field mapping pipeline (single table)
rsigma convert rules/ -t postgres -p pipelines/ocsf_postgres.yml

# Convert with per-logsource table routing (multi-table)
rsigma convert rules/ -t postgres -p pipelines/ocsf_postgres_multi_table.yml

# Generate PostgreSQL views for each rule
rsigma convert rules/ -t postgres -f view

# Generate TimescaleDB continuous aggregates
rsigma convert rules/ -t postgres -p pipelines/ocsf_postgres.yml -f continuous_aggregate

# Custom backend options (table, schema, timestamp field, etc.)
rsigma convert rules/ -t postgres -O table=security_logs -O schema=public -O timestamp_field=created_at

# JSONB mode: access fields inside a JSONB column (supports nested paths properly)
rsigma convert rules/ -t postgres -O table=okta_events -O json_field=data -O timestamp_field=time

# Sliding window correlation format (per-row detection using window functions)
rsigma convert rules/ -t postgres -f sliding_window

# Convert to LynxDB search queries
rsigma convert rules/ -t lynxdb

# Convert to LynxDB with a pipeline (custom index)
rsigma convert rules/ -t lynxdb -p pipeline.yml

# LynxDB minimal format (search expression only, for the API q parameter)
rsigma convert rules/ -t lynxdb -f minimal

# List available conversion backends
rsigma list-targets

# List available output formats for a backend
rsigma list-formats postgres
```

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

Input formats are selected via `--input-format` on the CLI or `InputFormat` in the library. Auto-detect (the default) tries JSON → syslog → plain text. Feature-gated formats: `logfmt`, `cef`.

See [`examples/jsonl_stdin.rs`](crates/rsigma-runtime/examples/jsonl_stdin.rs) and [`examples/tail_syslog.rs`](crates/rsigma-runtime/examples/tail_syslog.rs) for complete working examples.

## Architecture

Everything starts with a Sigma rule in YAML format:

- **Parsing:** `serde_yaml` deserializes the YAML into a raw value, then `rsigma-parser` turns it into a strongly-typed AST. A PEG grammar (`sigma.pest`) handles the document structure while a Pratt parser (`condition.rs`) handles condition expressions. Supporting modules define value types (`value.rs`: `SigmaStr`, wildcards, timespans) and AST nodes (`ast.rs`: modifiers, enums). The result is a `SigmaRule`, `CorrelationRule`, `FilterRule`, or `SigmaCollection`.

From there, the AST can go in three directions depending on what you need:

- **Evaluation:** `rsigma-eval` compiles rules into optimized matchers (`compiler.rs`), runs stateless detection through `Engine`, and tracks stateful correlation (`correlation.rs`: sliding windows, group-by, chaining, suppression) across events. Processing pipelines handle field mapping, transformations, conditions, and finalizers before compilation. Events are accessed through a trait with implementations for JSON, key-value, and plain text.

- **Conversion:** `rsigma-convert` transforms rules into backend-native query strings through a pluggable `Backend` trait. A condition walker traverses the AST and delegates to the backend for each node. `TextQueryConfig` exposes ~90 configuration fields for text-based backends. Concrete implementations include PostgreSQL/TimescaleDB (SQL for historical threat hunting) and LynxDB (SPL2-compatible search queries for log analytics).

- **Editor support:** `rsigma-lsp` provides an LSP server over stdio (via `tower-lsp`) with real-time diagnostics (lint + parse + compile errors), completions, hover documentation, document symbols, and code actions. Works with VSCode, Neovim, Helix, Zed, and any LSP-capable editor.

When running as a streaming detection engine, `rsigma-eval` feeds into `rsigma-runtime`:

- **Input:** Format adapters parse raw log lines (JSON, syslog, logfmt\*, CEF\*, plain text, with auto-detection) into `EventInputDecoded`. Sources include stdin, HTTP POST, and NATS JetStream.
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
    │    plain text, auto-detect               │
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
