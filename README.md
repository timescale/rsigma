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
rsigma convert -r rules/ -t test

# Convert with a processing pipeline and specific output format
rsigma convert -r rules/ -t test -p pipelines/ecs.yml -f state

# Convert to PostgreSQL SQL
rsigma convert -r rules/ -t postgres

# Convert to PostgreSQL with OCSF field mapping pipeline (single table)
rsigma convert -r rules/ -t postgres -p pipelines/ocsf_postgres.yml

# Convert with per-logsource table routing (multi-table)
rsigma convert -r rules/ -t postgres -p pipelines/ocsf_postgres_multi_table.yml

# Generate PostgreSQL views for each rule
rsigma convert -r rules/ -t postgres -f view

# Generate TimescaleDB continuous aggregates
rsigma convert -r rules/ -t postgres -p pipelines/ocsf_postgres.yml -f continuous_aggregate

# List available conversion backends
rsigma list-targets

# List available output formats for a backend
rsigma list-formats -t postgres
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
    │    group-by, chaining,  │   │    TimescaleDB      │
    │    suppression, events  │   └─────────────────────┘
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

## Reference

- [pySigma](https://github.com/SigmaHQ/pySigma): reference Python implementation
- [Sigma Specification V2.0.0](https://github.com/SigmaHQ/sigma-specification): formal specification
- [sigma-rust](https://github.com/jopohl/sigma-rust): Pratt parsing approach
- [sigmars](https://github.com/crowdalert/sigmars): correlation support patterns

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
