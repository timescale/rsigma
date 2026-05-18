# Security Hardening

RSigma deliberately bounds every input and every external resource it touches. This page catalogues the hard limits, the parsing safeguards, the operational concerns (process signals, lock primitives, daemon listener exposure), and the dynamic-pipeline-specific protections. None of these are configurable through CLI flags today; they are compile-time constants. Operators wanting different limits should fork and document the deviation locally.

For the SECURITY policy and disclosure process, see [`SECURITY.md`](../security-policy.md).

## Input size and depth caps

| Limit | Constant | Value | Scope | Behaviour on overrun |
|-------|----------|-------|-------|----------------------|
| Single event size | `MAX_LINE_BYTES` | 1 MiB | `engine daemon` HTTP/stdin event ingest | Line rejected with a `413`-equivalent error in HTTP mode; counted in `rsigma_events_parse_errors_total`. |
| Condition expression length | `MAX_CONDITION_LEN` | 64 KiB | Rule parser | Rule rejected at parse time with an `InvalidCondition` error. |
| Condition expression depth | `MAX_CONDITION_DEPTH` | 64 | Rule parser | Same. |
| JSON event traversal depth | `MAX_NESTING_DEPTH` | 64 | Keyword search inside nested JSON | Traversal stops; deeper fields are not matched against keyword detections. |
| Windash expansion | `MAX_WINDASH_DASHES` | 8 | `|windash` modifier (5^8 variants) | Compile error if a value contains more than 8 dashes. |
| Correlation chain depth | `MAX_CHAIN_DEPTH` | 10 | Engine | Stops chaining beyond 10 levels; logs at `WARN` (`rsigma_eval::correlation_engine`). |
| Correlation state entries | `max_state_entries` | 100,000 | Engine, all correlation rules combined | Hard cap; eviction drops the stalest 10% with a `WARN` log when reached. Watch via `rsigma_correlation_state_entries`. |

These limits are sized so that the engine remains bounded under pathological input (a single rule of unbounded size, a single event of unbounded size, or an attacker-controlled JSON document with multi-megabyte nesting). They were chosen to be larger than every plausible real Sigma rule and well above any legitimate JSON event.

## Dynamic pipeline resource limits

`engine daemon` and `pipeline resolve` enforce additional bounds on dynamic sources:

| Limit | Constant | Value | Per-source override |
|-------|----------|-------|---------------------|
| HTTP body, NATS payload, and command stdout | `MAX_SOURCE_RESPONSE_BYTES` | 10 MiB | `max_body_size` (HTTP), `max_stdout` (command) |
| Command stderr | (hard-coded) | 64 KiB | not configurable |
| HTTP fetch timeout | (default) | 30 s | `timeout` |
| Command execution timeout | `DEFAULT_COMMAND_TIMEOUT` | 30 s | `timeout` |
| Refresh interval minimum | `MIN_REFRESH_INTERVAL` | 1 s | not configurable (clamps with warning) |
| Include nesting depth | `MAX_INCLUDE_DEPTH` | 1 | not configurable |
| Remote include resolution | — | off | `--allow-remote-include` daemon flag |

Each limit produces a `SourceErrorKind::ResourceLimit` failure with a descriptive message. The full source-level catalogue lives at [Dynamic Pipeline Sources: resource limits](dynamic-sources.md#resource-limits).

### Include directive security model

The `include:` directive resolves to transformation YAML pulled from a source. By default, only local sources (`file`, `command`) are allowed to provide `include:` content. HTTP and NATS sources can serve other pipeline values but not `include:` content; this defends against a compromised CDN or NATS broker injecting transformation logic.

Operators that need remote-included pipelines (for centralised pipeline distribution across many daemons) must opt in explicitly with `--allow-remote-include` on `engine daemon`. The flag is also expected to be paired with mTLS on the upstream HTTP source so an arbitrary network attacker cannot serve content.

## Parser robustness

Every external parser rsigma ships uses panic-free libraries:

| Component | Library | Notes |
|-----------|---------|-------|
| Sigma rule YAML | `yaml_serde` 0.10 | The maintained fork of `serde_yaml`. Resists the recursion and aliasing attacks that plagued legacy `serde-yaml`. |
| Sigma condition expression | hand-written recursive descent | Bounded by `MAX_CONDITION_LEN` (64 KiB) and `MAX_CONDITION_DEPTH` (64). |
| Pipeline YAML | `yaml_serde` 0.10 | Same. |
| Input event JSON | `serde_json` | Bounded by `MAX_LINE_BYTES` (1 MiB) for streaming sources. |
| HTTP request bodies | `reqwest` with explicit size limit | Bounded by `MAX_SOURCE_RESPONSE_BYTES` (10 MiB). |
| OTLP requests | `prost` + `tonic` | The OTLP receiver enforces upstream size limits at the HTTP/gRPC layer. |
| EVTX records | `evtx` crate | Streaming parse; bounded record-by-record memory usage regardless of file size. |
| CEF | `cef-parser` | Bounded line size via the input format machinery. |

Fuzz testing under `cargo-fuzz` covers parser, condition, pipeline YAML, JSON event, EVTX, syslog, logfmt, CEF, and the conversion backends. Fourteen harnesses run on a scheduled CI workflow; crashes land in the `fuzz/artifacts/` tree and ship as regression fixtures.

## SQL injection prevention

The PostgreSQL backend (`backend convert -t postgres`) generates SQL by:

- Always double-quoting field names (`"CommandLine" ILIKE '%whoami%'`).
- Always single-quoting string literals with SQL-standard escaping (`'don''t'`).
- Validating identifiers (`table`, `schema`, `database`) against `^[A-Za-z_][A-Za-z0-9_$]*$` before insertion. Non-matching identifiers fail conversion with `InvalidIdentifier`.
- Never templating user-controlled strings into SQL keywords or structural positions.

This means a Sigma rule that contains a `'` or `;` or `--` in a value still produces safe SQL. The same conventions apply to the LynxDB backend. See [Backends: PostgreSQL](backends/postgres.md) and [Backends: LynxDB](backends/lynxdb.md).

Custom identifiers passed through `-O table=...` or pipeline `set_state` are validated identically; an `-O table='evil; DROP'` is rejected at conversion time, not at execution time.

## Process and concurrency hygiene

- **SIGTERM/SIGINT**: the daemon installs a Unix signal handler and drains in-flight events bounded by `--drain-timeout` (default 5 s) before exiting. State is snapshotted to SQLite if `--state-db` is set.
- **SIGHUP**: triggers a rules + pipelines reload, equivalent to `POST /api/v1/reload`. Hot-reload swaps the engine via `ArcSwap`, so in-flight evaluations see the previous engine and new events get the new one. No locks are taken on the critical path.
- **Locking primitive**: `parking_lot::Mutex` on the hot engine path (`rsigma-runtime` processor); `std::sync::Mutex` elsewhere (`SourceCache`, the `rsigma-convert` backend registry). `parking_lot` mutexes do not poison on panic, so a panicked thread on the eval path does not deadlock the rest of the system. The trade-off is that a panicked thread cannot be detected by checking the lock state; the daemon relies on `tokio::task` panic propagation for that.
- **Async runtime**: `tokio` with a single multi-threaded scheduler. Source resolution, HTTP serving, and engine evaluation share the runtime; under load they are scheduled by tokio's work-stealing scheduler.
- **No `unsafe` in first-party code**: the rsigma workspace contains zero `unsafe` blocks. Dependencies (notably `tonic`, `rustls`, `tokio`) contain `unsafe` reviewed upstream.

## Daemon network exposure

The `engine daemon` HTTP and gRPC listeners are unauthenticated today. The recommended deployment shape is one of:

- Bind to loopback (`--api-addr 127.0.0.1:9090`) and access via a reverse proxy that adds TLS and authentication. Nginx, Caddy, and Traefik all work; an example is documented in [Docker deployment](../deployment/docker.md).
- Bind to a private network segment that the SOC controls.
- Future: in-process TLS termination including mTLS for OTLP agents. Tracked at [issue #128](https://github.com/timescale/rsigma/issues/128).

NATS connections from the daemon (source, sink, DLQ) support five auth methods (creds file, token, user+password, NKey, mTLS) and TLS-required mode. See [NATS Streaming: authentication](../guide/nats-streaming.md#authentication).

OTLP receiver authentication is the upstream agent's responsibility today (TLS terminates upstream of rsigma in any deployment that needs it).

## Filesystem footprint

The daemon never writes outside the paths it is explicitly given:

- `--state-db <PATH>`: SQLite file written periodically and on shutdown.
- `--dlq file://<PATH>`: append-only NDJSON.
- `--output file://<PATH>`: append-only NDJSON of detections.

Rules and pipeline files are read-only. The `notify` file-watcher does not write. The MkDocs documentation build is local and never touches `~/`.

`rule lint --fix` does write rule files in place. Always commit changes first, then run `--fix`, then diff.

## Dependency policy

The repo uses `cargo audit` in CI on every `Cargo.toml` / `Cargo.lock` change. The audit workflow is in [`.github/workflows/audit.yml`](https://github.com/timescale/rsigma/blob/main/.github/workflows/audit.yml). Dependabot keeps direct dependencies current; transitive fixes are applied via targeted `cargo update -p <crate>` when needed.

Supply-chain signal:

- The `cargo deny` configuration tracks deprecated and yanked crates.
- The Docker image (`ghcr.io/timescale/rsigma`) is signed with keyless cosign via the GitHub OIDC issuer and ships SLSA Build L3 provenance.
- Release archives carry SLSA build provenance attestations (verifiable with `gh attestation verify`).
- The base Docker image is pinned by digest, not tag.
- Grype scans block the Docker push on any critical CVE.

See [`.github/workflows/docker.yml`](https://github.com/timescale/rsigma/blob/main/.github/workflows/docker.yml) and [`.github/workflows/release-binaries.yml`](https://github.com/timescale/rsigma/blob/main/.github/workflows/release-binaries.yml) for the full pipelines.

## Threat model summary

In one paragraph: rsigma assumes a trusted operator providing rules, pipelines, and source declarations on disk, plus an event stream from a trusted upstream agent. The hardening here exists to defend against malformed input, unbounded resource consumption (an attacker-controlled JSON event, a rule that recurses without bound, a dynamic source serving 100 GiB of garbage), and supply-chain attacks against dependencies. The daemon HTTP listeners are NOT a hardened public surface; deploy them behind a reverse proxy. The NATS and OTLP entry points support authentication, but mTLS termination for the rsigma HTTP API itself is on the roadmap (issue #128).

## See also

- [`SECURITY.md`](../security-policy.md) for the disclosure policy.
- [Dynamic Pipeline Sources: resource limits](dynamic-sources.md#resource-limits) for the per-source enforcement table.
- [NATS Streaming: authentication](../guide/nats-streaming.md#authentication) for the five NATS auth methods and TLS.
- [Issue #128](https://github.com/timescale/rsigma/issues/128) for the planned in-process TLS for the daemon API and OTLP endpoints.
- [Prometheus metrics: dynamic pipeline sources](metrics.md#dynamic-pipeline-sources-5-metrics) for observability of limit hits.
- [`rsigma_runtime::sources`](https://github.com/timescale/rsigma/tree/main/crates/rsigma-runtime/src/sources) for the implementation of the resource limits.
- [`rsigma-eval` README: constants and limits](https://github.com/timescale/rsigma/blob/main/crates/rsigma-eval/README.md#constants-and-limits) for the engine-side enforcement.
