# Feature Flags

`rsigma` is a workspace of seven crates (`rsigma-parser`, `rsigma-eval`, `rsigma-convert`, `rsigma-runtime`, `rsigma-mcp`, `rsigma-cli`, `rsigma-lsp`), several of which expose Cargo features that gate optional dependencies and code paths. This page documents every feature, its default state, what it pulls in, and how to enable it when building from source.

The CLI ships with sensible defaults; the precompiled release archives and the GHCR Docker image are built with `--all-features`, so every feature documented here is available out of the box.

## `rsigma-cli`

The crate that produces the `rsigma` binary.

| Feature | Default | Pulls in | What it enables |
|---------|---------|----------|-----------------|
| `daemon` | yes | `rsigma-runtime`, `tokio`, `axum`, `prometheus`, `notify`, `rusqlite`, `tower-http` | `engine daemon`, the HTTP API server, `/metrics`, hot-reload, SQLite state persistence. The default; disable only for a minimal `engine eval` / `rule *` build. |
| `mcp` | no | `rsigma-mcp` (pulls in `rmcp`, `schemars`), `tokio` | `mcp serve`, the Model Context Protocol server exposing the toolchain to AI agents. Opt-in: build with `--features mcp`. The prebuilt binaries and Docker image (`--all-features`) include it. See the [MCP server guide](../guide/mcp-server.md). |
| `daemon-nats` | no | `daemon` + `async-nats`, `tokio-stream`, `time`, `rsigma-runtime/nats` | NATS JetStream as `--input` and `--output` (and DLQ). All `--nats-*` flags. `RSIGMA_CONSUMER_GROUP`. See [NATS Streaming](../guide/nats-streaming.md). |
| `daemon-otlp` | no | `daemon` + `prost`, `tonic`, `flate2`, `rsigma-runtime/otlp` | OTLP/HTTP and OTLP/gRPC receivers on `/v1/logs`. See [OTLP Integration](../guide/otlp-integration.md). |
| `daemon-tls` | no | `daemon` + `rustls` (aws-lc-rs), `tokio-rustls`, `rustls-pki-types`, `x509-parser`, `hyper`, `hyper-util`, `tower-service` | Server-side TLS termination for the API listener (HTTP REST, `/metrics`, OTLP/HTTP, OTLP/gRPC) with optional mTLS client verification, SIGHUP-triggered cert hot-reload, and two extra Prometheus metrics. See [TLS termination](security.md#tls-termination-for-the-api-listener). |
| `logfmt` | no | `rsigma-runtime/logfmt` | `--input-format logfmt` for the daemon and `engine eval`. |
| `cef` | no | `rsigma-runtime/cef` | `--input-format cef` for ArcSight-style logs. |
| `evtx` | no | `rsigma-runtime/evtx` (dep on the `evtx` crate) | Native `.evtx` file input via `engine eval -e @file.evtx`. See [Input Formats](../guide/input-formats.md#evtx-windows-event-log-feature-gated). |
| `daachorse-index` | no | `rsigma-eval/daachorse-index`, optionally `rsigma-runtime/daachorse-index` | The `--cross-rule-ac` flag for very large rule sets dominated by shared positive substrings. See [Performance Tuning](../guide/performance-tuning.md#cross-rule-aho-corasick-pre-filter). |

## `rsigma-eval`

The detection and correlation engine. Used as a library and re-exported by `rsigma-cli`.

| Feature | Default | Pulls in | What it enables |
|---------|---------|----------|-----------------|
| `parallel` | no | `rayon` | Parallel batch evaluation via `Engine::evaluate_batch_parallel`. The CLI enables this by default through its dependency declaration. |
| `daachorse-index` | no | `daachorse` | Cross-rule Aho-Corasick pre-filter. See above. |

## `rsigma-runtime`

The streaming runtime (event sources, sinks, daemon plumbing, dynamic pipelines).

| Feature | Default | Pulls in | What it enables |
|---------|---------|----------|-----------------|
| `nats` | no | `async-nats`, `tokio-stream`, `time`, `futures` | NATS source, sink, and dynamic-pipeline source type. |
| `otlp` | no | `opentelemetry-proto`, `prost` | OTLP log decoding. |
| `logfmt` | no | (none beyond the parser) | `logfmt` input parser. |
| `cef` | no | (none beyond the parser) | `cef` input parser. |
| `evtx` | no | `evtx` | `.evtx` file reader. |
| `daachorse-index` | no | `rsigma-eval/daachorse-index` | Cross-rule AC support when used from `rsigma-runtime` consumers. |

## `rsigma-convert`

The conversion engine. Used as a library and re-exported by `rsigma-cli`.

| Feature | Default | Gates | Enables |
|---------|---------|-------|---------|
| `sigma-cli` | no | nothing (std-only, no extra dependencies) | The `sigma_cli` module: discovery of an external [sigma-cli](https://github.com/SigmaHQ/sigma-cli), the `sigma convert` argument mapping, and subprocess output classification. Consumed by `rsigma-cli` (`backend convert` delegation) and `rsigma-mcp` (the opt-in `--allow-sigma-cli` delegation); conversion itself stays native and in-process. |

## `rsigma-parser`

| Feature | Default | Pulls in | What it enables |
|---------|---------|----------|-----------------|
| `fix` | yes | `yamlpath`, `yamlpatch`, tree-sitter YAML | The source-preserving `lint::fix` module and crate-root `apply_fixes_to_source`/`SourceFixOutcome` re-exports. Disable default features for parser/evaluator-only `wasm32-unknown-unknown` builds. Parsing, validation, lint diagnostics, and fix metadata remain available without it. |

## `rsigma-mcp`

The Model Context Protocol server library. No Cargo features of its own; it is gated into the CLI by the `mcp` feature above.

## `rstix`

STIX 2.1 library crate. **Data Model + Serialization** is complete with `serde` (default): typed objects, bundle parse/stream, advisory `Bundle::validate`, [wire MUST at parse (DD-DM-001)](../library/rstix.md#dd-dm-001--wire-must-at-parse), and closed spec-audit differentials. **Pattern Engine** is complete with `pattern`. **Validation Pipeline** is complete with `validate` (all twelve checks, conformance corpus, per-code diagnostic coverage). **Graph + Marking + Store** are complete with `graph`, `marking`, `store`, and `store-fs`. See [Validation Pipeline](../library/rstix.md#validation-pipeline).

| Feature | Default | Pulls in | What it enables |
|---------|---------|----------|-----------------|
| `serde` | yes | `serde`, `serde_json` | `Bundle::parse`, `parse_reader`, `serde` on all model types, advisory `Bundle::validate`. |
| `pattern` | no | `serde`, `base64`, `ipnet`, `regex`, `unicode-normalization` | `Pattern::parse`, `Pattern::evaluate`, `Pattern::matches_single`, `Pattern::matches_single_with_bundle`, `Pattern::evaluate_observed_data`, `Pattern::canonical`, `IndicatorPattern` STIX AST wiring at deserialize, `PatternAst`, `ObservationContext`, `PatternScoType`, `PatternError`, `PatternMatchError` — STIX Specification §9 Levels 1–3. See [rstix Pattern Engine](../library/rstix.md#pattern-engine-stix-9). |
| `validate` | no | `serde`, `pattern` | `Validator`, `ValidatorBuilder`, `ValidationPhase`, `ParseOptions` / `allow_custom`, structured `STIX-E/W/I/H` diagnostics, `validate_json_str` / `validate_json_value` / `validate_bundle` / `validate_object`. See [Validation Pipeline](../library/rstix.md#validation-pipeline). |
| `graph` | no | `serde` | `StixGraph`, `EdgeTraversal`, `RelationshipExpander`, SRO + ref graph construction. See [Graph + Marking + Store](../library/rstix.md#graph--marking--store). |
| `marking` | no | `serde` | `MarkingResolver`, `TlpV2Level`, granular selector resolution, disclosure checks. |
| `store` | no | `serde` | `StixStore`, `MemoryStore`, `StixQuery` (typed + full-text search), `ImportReport`. |
| `store-fs` | no | `store` | `FsStore` — filesystem-backed durable store. |

Without `serde`, only `core`, `id`, and `vocab` modules are available (no bundle parsing). Enable `pattern` for STIX patterning (implies `serde` — evaluation uses typed bundle/SCO model types). Enable `validate` for the profile-based Validation Pipeline (`cargo build -p rstix --features validate`).

## Building with features

### Cargo install

```bash
# Default: daemon + everything that ships with it, no extras.
cargo install --locked rsigma

# Recommended for production: daemon + TLS + NATS + OTLP + EVTX + cross-rule AC.
cargo install --locked rsigma --features daemon-tls,daemon-nats,daemon-otlp,evtx,daachorse-index

# Match the prebuilt release archives and Docker image exactly.
cargo install --locked rsigma --all-features
```

### Local development

```bash
# Workspace build with every feature on.
cargo build --release --all-features --workspace

# Run just the `engine daemon` tests with the NATS feature.
cargo test -p rsigma-cli --features daemon-nats
```

### CI coverage

The repo's `ci.yml` runs `cargo check`, MSRV, `cargo clippy`, `cargo test`, `cargo doc`, and the coverage job against `--all-features`, plus the cross-platform `cargo test --all-features` matrix on Ubuntu, macOS, and Windows. A separate job builds `rsigma-parser` and `rsigma-eval` for `wasm32-unknown-unknown` with `--no-default-features` and then instantiates a linked module in a JavaScript-free runtime (Wasmtime). There is no general per-feature opt-in matrix: every other gated dependency listed above is built on every push, but no job exercises, for example, `daemon-nats` in isolation.

If a feature combination matters to you (and especially if a build with `--no-default-features` or a single optional feature is part of your downstream pipeline) and CI does not currently exercise it, file an issue so a job can be added.

## Detecting features at runtime

The binary's `--help` enumerates only the flags compiled in. If a NATS flag is missing from `rsigma engine daemon --help`, the binary was built without `daemon-nats`. Equivalent shells for the other gated surfaces:

```bash
# daachorse-index?
rsigma engine daemon --help | grep -q cross-rule-ac && echo on || echo off

# evtx?
echo "" | rsigma engine eval -r /dev/null -e @/dev/null --input-format json 2>&1 | grep -q "evtx" || echo "evtx feature not required for JSON inputs"

# Inspect feature flags via the binary's version output (planned: not yet implemented).
```

A first-class `rsigma --features` introspection flag would be a nice-to-have but is not implemented today.

## See also

- [Installation](../getting-started/installation.md) for prebuilt binaries (which use `--all-features`) and source builds.
- [Performance Tuning](../guide/performance-tuning.md) for when `daachorse-index` actually pays off.
- [NATS Streaming](../guide/nats-streaming.md), [OTLP Integration](../guide/otlp-integration.md), [Input Formats](../guide/input-formats.md) for what each feature gates in practice.
