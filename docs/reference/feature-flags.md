# Feature Flags

`rsigma` is a workspace of six crates (`rsigma-parser`, `rsigma-eval`, `rsigma-convert`, `rsigma-runtime`, `rsigma-cli`, `rsigma-lsp`), several of which expose Cargo features that gate optional dependencies and code paths. This page documents every feature, its default state, what it pulls in, and how to enable it when building from source.

The CLI ships with sensible defaults; the precompiled release archives and the GHCR Docker image are built with `--all-features`, so every feature documented here is available out of the box.

## `rsigma-cli`

The crate that produces the `rsigma` binary.

| Feature | Default | Pulls in | What it enables |
|---------|---------|----------|-----------------|
| `daemon` | yes | `rsigma-runtime`, `tokio`, `axum`, `prometheus`, `notify`, `rusqlite`, `tower-http` | `engine daemon`, the HTTP API server, `/metrics`, hot-reload, SQLite state persistence. The default; disable only for a minimal `engine eval` / `rule *` build. |
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

## `rsigma-parser`

No features. The parser is unconditional.

## `rstix`

STIX 2.1 + TAXII 2.1 library crate under phased implementation.

| Feature | Default | Pulls in | What it enables |
|---------|---------|----------|-----------------|
| `serde` | yes | `serde`, `serde_json` | Serialization/deserialization support used by model and TAXII flows. |
| `pattern` | no | (none) | STIX pattern module surface. |
| `validate` | no | `serde`, `pattern` | Validation pipeline module surface. |
| `graph` | no | (none) | Graph traversal module surface. |
| `marking` | no | (none) | Marking/TLP module surface. |
| `store` | no | (none) | Storage module surface. |
| `enrichment` | no | `store`, `graph` | Enrichment module surface. |
| `taxii` | no | `serde`, `reqwest`, `tokio`, `secrecy` | TAXII client module surface and async/network dependencies. |
| `testing` | no | `wiremock` | Test utilities and mock-server support. |
| `full` | no | `pattern`, `validate`, `graph`, `marking`, `store`, `enrichment`, `taxii` | Convenience feature bundle for full functionality (excluding `testing`). |

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

The repo's `ci.yml` runs `cargo check`, MSRV, `cargo clippy`, `cargo test`, `cargo doc`, and the coverage job against `--all-features`, plus the cross-platform `cargo test --all-features` matrix on Ubuntu, macOS, and Windows. There is no per-feature opt-in matrix today: every gated dependency listed above is built on every push, but no job exercises e.g. `daemon-nats` in isolation.

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
