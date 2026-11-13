---
description: "RSigma architecture: the crate map of the Rust workspace, the execution shapes of eval and daemon, and how parsing, evaluation, and I/O fit together."
---

# Architecture

RSigma is a workspace of nine crates organised around one principle: rule processing and event evaluation are pure library code; everything I/O-bound or runtime-shaped is layered on top. This page documents the crate map, the execution shapes, and how the pieces interact at runtime.

For operator-facing material see the [User Guide](../guide/evaluating-rules.md). For per-crate API docs see [docs.rs/rsigma](https://docs.rs/rsigma).

## Ecosystem

The streaming-detection ecosystem at a glance: rules, pipelines, dynamic sources, threat intel, and log events flow into the daemon, which evaluates, enriches, and scores them before fanning results out to sinks and downstream systems. The same engine also runs outside the daemon for one-shot evaluation, conversion, hunting, and rule authoring.

![RSigma streaming detection architecture](../../assets/images/architecture.svg)

## Crate map

Each arrow points from a crate to a crate it depends on; edges already implied by a longer path are left out.

![RSigma crate dependency graph](../../assets/images/internal_architecture.svg)

## rstix

STIX 2.1 bundle parsing, T1 advisory validation, optional T2 Validation Pipeline, patterning, and graph/marking/store live in the [`rstix`](https://github.com/timescale/rsigma/tree/main/crates/rstix) crate. API, validation tiers, wire conformance, tests, and feature flags are documented on the [rstix library page](../library/rstix.md) and in the [crate README](https://github.com/timescale/rsigma/blob/main/crates/rstix/README.md). Pattern Engine engineering choices (for example `IndicatorBuilder` validation at `build()`) are recorded as [design decisions](../library/rstix.md#rstix-graph-marking-store-pattern-engine-design-decisions).

## Crate responsibilities

Dependencies point down the [crate map](#crate-map): higher crates depend on lower crates, and the reverse is never true.

| Crate | Role | Key types | Feature gates |
|-------|------|-----------|---------------|
| [`rsigma-parser`](https://docs.rs/rsigma-parser) | YAML → AST. The only crate that touches Sigma source. | `SigmaCollection`, `SigmaRule`, `CorrelationRule`, `FilterRule`, `Condition`, `SigmaStr`, `Modifier` | `fix` (default) |
| [`rsigma-ir`](https://docs.rs/rsigma-ir) | Lower the AST into a shared, modifier-resolved HIR consumed by both eval and convert. Faithful, lossless matchers; opt-in optimization passes; a versioned CBOR cache. | `IrRule`, `IrDetection`, `IrCondition`, `IrMatcher`, `IrPattern`, `lower_rule`, `optimize_rule`, `HirCacheHeader`, `encode_rules`, `decode_rules` | none |
| [`rsigma-eval`](https://docs.rs/rsigma-eval) | Lower rules to HIR, then materialize a matcher tree and evaluate events. Detection and correlation engine. Exemplar-driven rule drafting and tuning. Processing pipeline machinery. HIR restart cache. | `Engine`, `CorrelationEngine`, `Pipeline`, `Transformation`, `CompiledRule`, `Event`, `JsonEvent`, `EvaluationResult`, `DetectionBody`, `CorrelationBody`, `DraftReport`, `TuneReport` | `parallel`, `daachorse-index` |
| [`rsigma-convert`](https://docs.rs/rsigma-convert) | Render backend-native queries from the HIR. Non-native targets are delegated to sigma-cli. | `Backend` trait, `TextQueryConfig`, `PostgresBackend`, `LynxDbBackend`, `FibratusBackend`, `TestBackend` | `sigma-cli` |
| [`rsigma-runtime`](https://docs.rs/rsigma-runtime) | Streaming runtime. Input adapters, post-evaluation enrichment, sinks, dynamic-source resolver, NATS/OTLP plumbing, hot-reload. | `LogProcessor`, `RuntimeEngine`, `EventSource`, `Sink`, `EnrichmentPipeline`, `SourceResolver`, `SourceCache`, `TemplateExpander`, `EvtxFileReader` | `nats`, `otlp`, `logfmt`, `cef`, `evtx`, `uds`, `daachorse-index` |
| [`rsigma-lsp`](https://docs.rs/rsigma-lsp) | Language Server Protocol for editors. Diagnostics from the linter + parser + compiler, plus completions, hovers, and symbols. | `Backend` (tower-lsp-server impl), `Diagnostic` mapping | none |
| [`rsigma-mcp`](https://docs.rs/rsigma-mcp) | Model Context Protocol server. Exposes parsing, linting, fixing, evaluation, conversion, reverse conversion, rule tuning, field extraction, and pipeline resolution as MCP tools and resources for AI agents, returning structured JSON. | `RsigmaMcp` handler, `serve_stdio`, `serve_http` | `http` |
| `rstix` | STIX 2.1 library crate. **Data Model + Serialization** complete (`serde`, default; wire MUST at parse [**DD-DM-001**](../library/rstix.md#rstix-wire-format-validation-dd-dm-001); [wire conformance (STIX 2.1)](../library/rstix.md#rstix-wire-conformance-stix-21)). **Pattern Engine** complete (`pattern`). **Validation Pipeline** complete (`validate`, all twelve checks, conformance corpus + per-code diagnostic coverage). **Graph + Marking + Store** complete (`graph`, `marking`, `store`, `store-fs`). **TAXII Client** (`taxii`; [TAXII Client](../library/rstix.md#rstix-taxii-client)). | `Bundle::parse`/`parse_reader`, `Bundle::validate`, `ParseOptions` + typed `TypeRegistry`, 42 typed object families (`serde`); `Pattern::parse`/`evaluate`/… (`pattern`); `Validator` and structured `STIX-E/W/I/H` diagnostics (`validate`); `StixGraph`, `MarkingResolver`, `MemoryStore`/`StixStore`/`FsStore` (`graph`/`marking`/`store`/`store-fs`); `TaxiiClient`, `TaxiiEnvelope`, auth + pagination (`taxii`); deterministic SCO IDs, vocabulary tables | `serde` (default), `pattern`, `validate`, `graph`, `marking`, `store`, `store-fs`, `taxii`, `taxii-store`, `taxii-native-tls` |
| `rsigma-cli` | The `rsigma` binary. Wires the other crates into a CLI and the streaming daemon. | `engine eval`, `engine daemon`, `rule *`, `backend *`, `pipeline resolve`, `mcp serve` | `daemon`, `mcp`, `daemon-nats`, `daemon-otlp`, `daemon-tls`, plus all eval/runtime feature flags. |

`rsigma-parser` and `rstix` have no dependencies on the other crates. `rsigma-ir` depends on `rsigma-parser`. `rsigma-eval` depends on `rsigma-parser` and `rsigma-ir`, and `rsigma-convert` adds `rsigma-eval` to those two. `rsigma-lsp` depends on `rsigma-parser` and `rsigma-eval`. `rsigma-runtime` depends on `rsigma-parser`, `rsigma-eval`, and `rstix`. `rsigma-mcp` depends on `rsigma-parser`, `rsigma-eval`, `rsigma-convert`, and `rsigma-runtime`. `rsigma-cli` depends directly on `rsigma-parser`, `rsigma-eval`, `rsigma-convert`, `rsigma-runtime`, `rsigma-mcp`, and `rstix`, and reaches `rsigma-ir` through them. `rsigma-lsp` ships as its own binary and is not a dependency of the CLI.

## The four execution shapes

The same compiled rules can be evaluated in four shapes; each is a different entry into the same engine.

### 1. Library

A program embeds `rsigma-parser` and `rsigma-eval` directly:

```rust
let collection = rsigma_parser::parse_sigma_yaml(yaml)?;
let mut engine = rsigma_eval::Engine::new();
engine.add_collection(&collection)?;
let event = rsigma_eval::JsonEvent::borrow(&json);
let matches = engine.evaluate(&event);
```

No I/O, no thread spawning, no async runtime. The same `Engine` struct backs every other shape.

### 2. One-shot CLI (`engine eval`)

`rsigma-cli` reads rules and events, instantiates `Engine`, evaluates each event, prints `EvaluationResult` lines to stdout, exits. Useful for fixtures, hunts, and forensic replay over `.evtx`. See [`engine eval`](../cli/engine/eval.md) and [Evaluating Rules](../guide/evaluating-rules.md).

### 3. Streaming daemon (`engine daemon`)

`rsigma-cli`'s `daemon` subcommand wires `rsigma-runtime`'s `LogProcessor` around `RuntimeEngine` (which embeds `Engine` + `CorrelationEngine`). Adds:

- One `EventSource` (stdin, HTTP, NATS, or a `unix://` domain socket on Unix targets behind the `uds` feature).
- A post-evaluation `EnrichmentPipeline` that injects context into each result before it reaches the sinks.
- Optional post-engine layers in the sink path, all off by default: a risk layer (`--risk`) that scores firings per entity and emits risk incidents, and an alert pipeline (`--alert-pipeline`) that silences, inhibits, deduplicates, and groups results into incidents. When both run the order is enrichment, risk, alert pipeline, sinks.
- An optional triage feedback loop (`--enable-dispositions`) that ingests analyst verdicts off the result stream and maintains a per-rule false-positive ratio. It is orthogonal to the eval and sink paths.
- Optional schema-aware routing (`--schema-routing`) that classifies each event and dispatches it to a per-schema `Engine`, feeding one shared correlation store; and optional conflict-based logsource pruning (`--logsource-routing`).
- One or more `Sink`s (stdout, file, NATS, OTLP, webhook, or a `unix://` socket), fanned out through a per-sink async delivery layer (bounded queue + worker, retry/backoff), plus an optional DLQ.
- Hot-reload via `ArcSwap` (file watcher + `SIGHUP` + `POST /api/v1/reload`).
- Optional SQLite-backed state (`--state-db`) for correlation, alert-pipeline, risk, and disposition snapshots.
- Optional OTLP receiver (HTTP + gRPC) when built with `daemon-otlp`.
- Optional in-process TLS termination (mTLS, cert hot-reload) on the shared API listener when built with `daemon-tls` (TCP only; a `unix://` listener is the trust boundary instead).
- Prometheus `/metrics`, REST control endpoints (status, reload, the opt-in tap and tail streams, and read-only `correlations`, `incidents`, `silences`, `risk`, and `dispositions` views), health probes.

See [Streaming Detection](../guide/streaming-detection.md) and the [`engine daemon`](../cli/engine/daemon.md) flag table.

### 4. Backend conversion (`backend convert`)

`rsigma-convert` lowers each rule to HIR and its `Backend` trait walks the resulting `IrDetection` and `IrCondition`, emitting backend-native queries (SQL, SPL2) or rule documents. The value leaves consume the faithful HIR (`IrPattern`, `IrStrOp`, `IrNumber`, `RegexFlags`, `CompareOp`) rather than parser types, so a backend never touches `rsigma-parser`. The trait uses `TextQueryConfig` (around 90 fields mirroring pySigma's `TextQueryBackend` configuration) to keep backend implementations declarative.

PostgreSQL/TimescaleDB, LynxDB, and Fibratus (rule YAML for Windows EDR sensors) are the native targets today. `backend convert` resolves targets native-first: any target without a native backend is delegated to an installed [sigma-cli](https://github.com/SigmaHQ/sigma-cli), so the wider pySigma backend ecosystem (Splunk, Elasticsearch, Microsoft Sentinel/KQL, QRadar, and 30+ more) is reachable from the same command. See [`backend convert`](../cli/backend/convert.md), [PostgreSQL backend](backends/postgres.md), [LynxDB backend](backends/lynxdb.md).

### Plus: LSP

`rsigma-lsp` runs over stdio via `tower-lsp-server`. On every save, it parses, lints, and compiles the buffer through `rsigma-parser` + `rsigma-eval`, then maps any findings into LSP diagnostics. It also exposes completions, hovers, and document symbols. See [VS Code](../editors/vscode.md) and [Neovim](../editors/neovim.md).

### Plus: MCP

`rsigma-mcp` exposes the toolchain to MCP-aware agents (Cursor, Claude Code, ...) over stdio, and over Streamable HTTP (with bearer-token auth) behind the `http` feature. TLS for the HTTP listener is provided by `rsigma-cli` when built with `daemon-tls` (`--tls-cert`/`--tls-key` on `mcp serve`). The `RsigmaMcp` handler wraps `rsigma-parser`, `rsigma-eval`, `rsigma-convert`, and `rsigma-runtime` behind 16 Engineer-cycle tools (parse, lint, fix, format, validate, evaluate, convert, reverse-convert, tune, test exemplars, list backends and fields, resolve and list pipelines, and author ADS metadata) and 4 resources (the lint catalogue, the ADS schema, the modifier reference, and MITRE tactics), returning structured JSON. Point `--daemon-url` at a running daemon to add the Operate-cycle tools (incidents, risk, silences, dispositions); `--allow-operate-writes` is required for the two mutating tools. It is driven by `rsigma mcp serve`. See the [MCP server guide](../guide/mcp-server.md).

## Data flow

### YAML to AST (`rsigma-parser`)

```text
.yml file → yaml_serde::Value → SigmaCollection {
    rules:        Vec<SigmaRule>,
    correlations: Vec<CorrelationRule>,
    filters:      Vec<FilterRule>,
}
```

- Multi-document YAML (`---`) maps to `SigmaCollection` with each document parsed into the appropriate kind.
- Conditions go through a separate Pratt parser (`condition.rs`) that consumes the [Sigma condition expression grammar](https://sigmahq.io/docs/basics/conditions.html) with `not > and > or` precedence.
- The parser is strict on the spec: unknown top-level keys fail compilation; unrecognised modifiers fail compilation. (Linting is a separate pass that surfaces best-practice issues without failing compilation.)

### Exemplar-driven authoring (`rsigma-eval::rule_draft` and `::rule_tune`)

Rule drafting and tuning are deterministic library workflows in `rsigma-eval`, shared by the CLI and MCP adapters. Both profile typed event values through the same stability, value-form, wildcard-escaping, and YAML-emission core. `draft_rule` contrasts positive exemplars with an optional baseline and emits a detection rule. `tune_rule` contrasts confirmed false positives with protected true positives and emits a separate Sigma filter rule targeting the existing detection.

Generated artifacts re-enter the normal parser and evaluator paths before they are returned. Tuning first proves that every supplied label fires the unfiltered target, then loads the target and proposed filter together through `Engine::add_collection` and verifies that covered false positives stop firing while every true positive remains. Pipelines transform the target before profiling, so emitted fields and logsource match the deployment shape.

### AST to HIR (`rsigma-ir`)

Both evaluation and conversion route through a shared intermediate representation. `lower_rule` walks the (post-pipeline) parser AST and resolves each field modifier into an explicit `IrMatcher`, producing an `IrRule` whose detections, conditions, and matchers are backend-neutral. Lowering is purely structural: it decides *which* comparison applies but keeps the value faithful (original case, wildcards, encodings recorded as explicit steps) and preserves quantified selectors, so the same HIR compiles to physical matchers for eval and renders to query strings for convert. The HIR is `serde`-serializable; `rsigma-ir::cache` writes a versioned CBOR blob (a `HirCacheHeader` plus the rules) that backs the engine restart cache.

### HIR to compiled rules (`rsigma-eval::compiler`)

`Engine::add_collection` first runs every loaded pipeline against each rule, in priority order, then lowers each rewritten rule to HIR (`lower_rule`) and materializes it into a `CompiledRule` via `compile_to_compiled`. Materialization builds the matcher tree, a tree of nodes per detection item with the concrete `Regex`, Aho-Corasick, and `IpNet` matchers, and the matcher optimizer transforms subtrees in-place. `Engine::save_hir` and `load_hir` persist and reload that lowered rule set through the HIR cache, so a warm process skips parse, pipeline, and lowering on restart. The engine keeps the lowered rules for this only when `Engine::set_retain_hir(true)` is set before loading; by default it drops them after compilation.

The matcher optimizer makes three transparent rewrites:

| Pass | Trigger | Effect |
|------|---------|--------|
| Aho-Corasick batching | `AnyOf` group of 8+ `contains` needles | Collapses into one Aho-Corasick automaton. |
| RegexSet batching | `AnyOf` group of 3+ regex matchers | Collapses into one `regex::RegexSet`. |
| `CaseInsensitiveGroup` | A group whose children are all case-insensitive | Lowercases the haystack once, dispatches via `matches_pre_lowered`. |

See [Performance Tuning: the matcher optimizer](../guide/performance-tuning.md#always-on-the-matcher-optimizer).

### Event evaluation (`rsigma-eval::engine`)

For each event:

1. Apply opt-in pre-filters in order:
   - `CandidateIndex` witness pruning (always on): exact values, substring needles, keywords, mandatory regex literals, and field presence.
   - Conflict-based logsource pruning (`set_logsource_extractor`), backed by a product-partitioned rule index, when logsource routing is enabled.
   - Bloom trigram filter (`set_bloom_prefilter(true)`).
   - Cross-rule Aho-Corasick (`set_cross_rule_ac(true)`, requires `daachorse-index` build feature).
2. For each candidate rule, walk the matcher tree against the event.
3. Emit an `EvaluationResult` with a `Detection` body per firing detection.
4. Feed every firing detection into `CorrelationEngine`; any correlation that crosses its threshold emits an `EvaluationResult` with a `Correlation` body.

The engine itself is stateless. Correlation state lives on the `CorrelationEngine`, with a hard cap (`max_state_entries`, default 100,000; 10% eviction on overrun). See [Performance Tuning: memory pressure and correlation state](../guide/performance-tuning.md#memory-pressure-and-correlation-state).

With schema-aware routing the daemon classifies each event by its content signature and builds one `Engine` per distinct pipeline set, dispatching the event to the engine bound to its schema. Detections from every per-schema engine feed one shared `CorrelationEngine`, and group-by extraction is schema-aware, so the same entity correlates across schemas even when each names the field differently. See [Schema Routing](../guide/schema-routing.md) and [Logsource Routing](../guide/logsource-routing.md).

### Streaming pipeline (`rsigma-runtime`)

The streaming runtime wraps the synchronous `Engine` in an async pipeline:

```text
EventSource ──► mpsc ──► LogProcessor ──► EnrichmentPipeline ──► post-engine ──► async sink layer ──► Sinks
   (stdin,                 (batch            (asset · GeoIP ·       layers           (per-sink queue       (stdout,
    HTTP,                   evaluation,       reputation ·          (risk · alert     + worker,             file,
    NATS,                   ArcSwap           runbook · ...)         pipeline,        retry/backoff)        NATS,
    OTLP,                   hot-reload)                              opt-in)                                OTLP,
    unix)                                                                                                  webhook,
                                                                                                           unix,
                                                                                                           DLQ)
```

The bounded mpsc channels apply back-pressure: when the engine cannot keep up, the source blocks instead of dropping events. `rsigma_back_pressure_events_total` counts how often that happens. See [Observability](../guide/observability.md#prometheus-metrics).

`ArcSwap` hot-reload swaps an `Arc<Engine>` atomically; in-flight evaluations see the old engine and complete normally; new events get the new one. The reload path is triggered by a `notify`-based file watcher on the rules and pipeline files, by `SIGHUP`, or by `POST /api/v1/reload`.

### Post-evaluation enrichment (`rsigma-runtime::enrichment`)

Between the engine and the sinks, the `EnrichmentPipeline` injects context (asset info, IP reputation, identity, GeoIP, KEV flags, runbook URLs, ...) into each result's `RuleHeader.enrichments` map. Six primitives (`template`, `lookup`, `http`, `command`, `stix`, and `mmdb`) compose into recipes; `stix` needs `stix-enrich` and `mmdb` needs `mmdb-enrich`. Kind-aware template namespaces (`${detection.*}` for detection-kind enrichers, `${correlation.*}` for correlation-kind) are validated at config-load time. An optional HTTP response cache, scope filtering by rule glob, tag set, and severity, and `on_error` policies (`skip`, `null`, `drop`) round it out. See [Enrichment](../guide/enrichers.md).

### Post-engine layers (`rsigma-runtime::risk`, `::alert_pipeline`, `::dispositions`)

After enrichment and before the sinks, two opt-in layers reshape the result stream while leaving the evaluation hot path untouched. The risk layer annotates each firing with a per-entity risk score and risk objects (drawn from a shared field-selector namespace), accumulates risk per entity over a sliding window, and emits a `RiskIncidentResult` when an entity crosses a score or ATT&CK-tactic-count threshold. The alert pipeline then silences, inhibits, and deduplicates results (modeled on Alertmanager) and groups the survivors into `IncidentResult`s. When both run the order is enrichment, risk, alert pipeline, sinks, since risk must accrue on every firing including the ones the alert pipeline is about to fold, silence, or inhibit. A separate triage feedback loop ingests analyst dispositions off the result stream to maintain a per-rule false-positive ratio; it is orthogonal to the sink path. All three persist versioned snapshots into the shared `--state-db` store, each in its own table. See [Risk-Based Alerting](../guide/risk-based-alerting.md), [Alert Pipeline](../guide/alert-pipeline.md), and [Triage Feedback](../guide/triage-feedback.md).

### Dynamic source resolution (`rsigma-runtime::sources`)

On every rule-load (including reloads), the `DaemonSourceRegistry` collects source declarations from external `--source` files (with collision-error semantics) and runs each through the `SourceResolver` machinery:

1. Per source, dispatch on type: HTTP (`reqwest`), command (tokio `Command`), file (read + optional `notify` watch), NATS (subject subscribe, requires `nats` feature).
2. Parse the response according to `format:` (`json`, `yaml`, `lines`, `csv`).
3. Apply the `extract:` expression (`jq` via `jaq`, JSONPath via `serde_json_path`, or CEL).
4. Store in `SourceCache` (in-memory by default; SQLite-backed under `--state-db`).
5. `TemplateExpander` substitutes the resolved values into dynamic pipeline `vars:` entries, while `lookup` enrichers read the same cache directly.

Refresh policies and on-error behavior are documented in [Dynamic Sources](dynamic-sources.md). Pipeline binding is documented separately in [Dynamic Pipelines](dynamic-pipelines.md).

## Performance posture

Three transparent passes (matcher optimizer) always run. Three opt-in passes (`--bloom-prefilter`, `--cross-rule-ac`, and the `parallel` rayon path enabled by default in the CLI) require explicit knobs. The streaming daemon's `--buffer-size` (default 10000) and `--batch-size` (default 128, capped at the buffer size) tune throughput vs tail latency.

Verified Criterion numbers ship in the [Benchmarks](../benchmarks.md) page. Headline figures: 2 µs per event for 100 rules, 30 µs per event for 1k rules, 162 µs per event for 5k rules. Cross-rule AC delivers up to ~100× speed-up on pure-substring rule sets dominated by non-matching events.

## Threat model

RSigma assumes a trusted operator providing rules, pipelines, and source declarations on disk, plus an event stream from a trusted upstream agent. Every external input is bounded by a hard limit (event size, condition size, response body size, command execution time, recursion depth) so a malformed input cannot exhaust memory or CPU. The daemon HTTP and gRPC listeners are unauthenticated by default; enable opt-in bearer-token authentication with per-token `resource:action` permissions (`--api-token-env` or the `daemon.api.auth` config block), and pair it with in-process TLS from the optional `daemon-tls` feature (`--tls-cert`/`--tls-key`, plus `--tls-client-ca` for mTLS) or a reverse proxy. Full catalogue in [Security Hardening](security.md).

## See also

- [Diagram sources](https://github.com/timescale/rsigma/tree/main/assets): `architecture.svg` and `internal_architecture.svg`, the SVGs this page embeds.
- [Per-crate READMEs](https://github.com/timescale/rsigma/tree/main/crates) for the implementation-side documentation.
- [docs.rs/rsigma](https://docs.rs/rsigma) for the library API.
- [Benchmarks](../benchmarks.md) for the Criterion results across parser, evaluator, correlation engine, runtime, and dynamic pipelines.
- [Performance Tuning](../guide/performance-tuning.md), [Observability](../guide/observability.md), [Security Hardening](security.md) for the operator-facing concerns.
