# Testing

The workspace runs six tiers of tests, all gated in CI. PRs are expected to pass every tier.

## At a glance

| Tier | Where it lives | How to run | Gated by |
|------|----------------|------------|----------|
| Unit | `src/` modules with `#[cfg(test)] mod tests` | `cargo test --workspace --all-features --locked` | `test` job on Linux, macOS, Windows. |
| Integration (in-process) | `crates/{rsigma-parser,rsigma-eval,rsigma-convert,rsigma-runtime}/tests/*.rs` | Same. | Same. |
| End-to-end (binary + containers) | `crates/rsigma-cli/tests/cli_*.rs`, `crates/rsigma-runtime/tests/nats_e2e.rs`, `crates/rsigma-convert/tests/postgres_integration.rs` | Same; testcontainers-based tests skip when Docker is unavailable. | Same. |
| Snapshot / golden | `crates/rsigma-{parser,eval,convert}/tests/snapshots/`, `tests/fixtures/dynamic-pipelines/golden/` | `cargo test` plus the SigmaHQ-corpus job for the dynamic-pipelines goldens. | `test` and `sigma-corpus` jobs. |
| SigmaHQ corpus | `.github/workflows/ci.yml` -> `sigma-corpus` | `cargo build --release --all-features --locked -p rsigma` then `target/release/rsigma rule validate /tmp/sigma/rules/ --verbose` | `sigma-corpus` job, on every PR. |
| Coverage | `cargo-llvm-cov` (Linux) | `cargo llvm-cov --workspace --all-features --lcov --output-path lcov.info` | `coverage` job (advisory, not gating). |

## Unit tests

Located inside the crate modules they test. Conventional Rust:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_rule() {
        let rule = parse_sigma_yaml(MINIMAL_YAML).unwrap();
        assert_eq!(rule.rules.len(), 1);
    }
}
```

Bias toward unit tests for pure-functional logic (parsers, matchers, formatters). Bias toward integration tests for end-to-end shapes (CLI invocations, daemon HTTP round-trips, dynamic source resolution).

## Integration tests (in-process)

These tests link directly against the crate as a library and exercise multi-component flows without spawning the compiled binary.

| Crate | Files | Tests | What they cover |
|-------|-------|------:|-----------------|
| `rsigma-parser` | `ast_snapshots.rs`, `parse_errors.rs` (+ `snapshots/` for `insta`) | ~30 | Multi-document parsing, malformed YAML, directory parsing; insta-locked AST snapshots. |
| `rsigma-eval` | `integration.rs`, `correlation_edge.rs`, `error_paths.rs`, `pipeline_errors.rs`, `regression_eval.rs`, `state_snapshot.rs` (+ shared `helpers/`) | ~56 | Full rule-eval pipelines, correlation edge cases, snapshot replay, pipeline error semantics. |
| `rsigma-convert` | `golden_postgres.rs`, `golden_lynxdb.rs` (+ `golden/` for committed expected outputs) | (golden) | Backend query generation for every `--format` (`default`, `view`, `timescaledb`, `continuous_aggregate`, `sliding_window`, `minimal`). |
| `rsigma-runtime` | `integration.rs`, `evtx_integration.rs`, `sources_integration.rs` (the `nats_*.rs` files live in the E2E section below) | ~40 | Streaming runtime; EVTX file parsing against the committed `security.evtx` fixture; dynamic source resolution (HTTP, file, command, in-process mocks) with TTL, refresh, and template expansion. |

Helpers (test rule fixtures, common test pipelines) live in `crates/<crate>/tests/helpers/mod.rs` or `crates/<crate>/tests/common/mod.rs`. Reuse them; do not duplicate.

Do not duplicate unit-level assertions in integration tests. Integration tests own the boundaries, the multi-component chains, and the error paths.

## End-to-end tests

E2E tests cross the binary boundary or stand up real external services through containers. They are the highest-confidence layer and the longest to run.

### CLI E2E (`crates/rsigma-cli/tests/cli_*.rs`)

The 19 `cli_*.rs` files contain roughly 250 tests that invoke the freshly built `rsigma` binary via [`assert_cmd`](https://docs.rs/assert_cmd). They exercise stdin, stdout, stderr, exit codes, and (for the daemon tests) the full HTTP, NATS, and OTLP wire surface. Run `cargo test -p rsigma --tests -- --list | wc -l` for the exact discovered count against your tree; the per-file table below is for orientation rather than as a contract.

| File | Tests | What it covers |
|------|------:|----------------|
| `cli_config.rs` | 15 | `config init`, `validate`, `show`, `schema`, `path`, `reload`; layered file / env / flag precedence. |
| `cli_convert.rs` | 14 | `backend convert` against every shipped backend and output format. |
| `cli_daemon.rs` | 21 | Long-running daemon (stdin input), hot-reload, health, shutdown. |
| `cli_daemon_dynamic.rs` | 16 | Dynamic-pipeline source resolution end-to-end via the daemon's `POST /api/v1/sources/resolve`. |
| `cli_daemon_enrichment.rs` | 2 | Smoke for the in-process enricher chain wired to the daemon. |
| `cli_daemon_fields_observer.rs` | 8 | `--observe-fields` gap / broken-coverage reports across `/api/v1/fields*`. |
| `cli_daemon_http.rs` | 10 | HTTP input mode, `POST /api/v1/events`, OTLP HTTP. |
| `cli_daemon_nats.rs` | 8 | NATS input + sink over an in-process NATS server. |
| `cli_daemon_otlp.rs` | 9 | OTLP HTTP and gRPC ingest, with the metric-label assertions added in PR #115. |
| `cli_daemon_tls.rs` | 12 | `daemon-tls` flag surface, mTLS, SIGHUP-triggered cert hot-reload. |
| `cli_eval.rs` | 40 | `engine eval`: inline events, `@file`, stdin, `jq` / JSONPath, fail-on-detection, exit codes. |
| `cli_fields.rs` | 16 | `rule fields` extraction across detection items, correlation, filters; `--no-filters`, `--json`. |
| `cli_lint.rs` | 24 | `rule lint`, `.rsigma-lint.yml`, `# rsigma-disable` suppressions, `--fix`, `--output-format json/ndjson/csv/tsv`. |
| `cli_migrate_sources.rs` | 4 | `rule migrate-sources` strategies and the post-extraction pipeline rewrite. |
| `cli_output_format.rs` | 19 | Cross-command global `--output-format`, `--color`, `--quiet`, `--no-stats` resolution. |
| `cli_parse.rs` | 8 | `rule parse` exit-code and structured-error contract. |
| `cli_sources_deprecation.rs` | 6 | Stderr warning when a pipeline still declares inline sources after the deprecation. |
| `cli_validate.rs` | 4 | `rule validate` against good and bad rule sets. |

The shared harness in `crates/rsigma-cli/tests/common/mod.rs` is the canonical reference for spawning a long-running daemon under test: it drains stdout in a background thread to prevent pipe stalls, forwards stderr lines via `mpsc`, probes the actual TCP socket with `TcpStream::connect_timeout` before returning a handle, and wraps the `Child` in a `ChildGuard` RAII type that kills it on drop. PR #115 hardened this against macOS-under-load flakes by replacing every `std::thread::sleep` wait with a `poll_until` retry loop that polls the actual observable condition (HTTP status, metric counter) every 50 ms up to a 5 s deadline. Use it for any new daemon-level test; do not roll your own.

### Container E2E (NATS and Postgres via testcontainers)

Four files spin up real services in Docker containers via [`testcontainers`](https://docs.rs/testcontainers). Together they cover **29 tests**, all guarded by a `can_run_linux_containers()` probe that shells out to `docker info` and checks that the daemon reports a Linux OS type. If Docker is missing or only provides Windows containers, the tests print "Skipping" and return successfully.

| File | Tests | Container | What it covers |
|------|------:|-----------|----------------|
| `crates/rsigma-runtime/tests/nats_e2e.rs` | 6 | NATS JetStream | Replay-from-offset, replay-from-timestamp, JetStream-based DLQ, consumer groups (the highest-rigor NATS surface). |
| `crates/rsigma-runtime/tests/nats_integration.rs` | 7 | NATS JetStream | Connection auth (token, NKey, JWT), TLS round-trips, ack semantics, source / sink fan-out. |
| `crates/rsigma-cli/tests/cli_daemon_nats.rs` | 8 | NATS JetStream | The full `rsigma engine daemon --input nats ...` shape: spawn the binary, point it at the container, assert against published detection matches. |
| `crates/rsigma-convert/tests/postgres_integration.rs` | 8 | PostgreSQL | Convert real Sigma rules to SQL with `convert_collection`, execute the generated queries against a live PostgreSQL container, assert match counts against the Okta cross-tenant impersonation chain from [the detection-layer-on-postgres companion project](https://github.com/mostafa/detection-layer-on-postgres). This is the only place where the documented PostgreSQL backend output formats (`default`, `view`, `timescaledb`, `continuous_aggregate`, `sliding_window`) are tested *as SQL the database actually accepts*, rather than just as text matching a golden file. |

The `skip_without_docker!()` macro pattern is identical in all four:

```rust
macro_rules! skip_without_docker {
    () => {
        if !can_run_linux_containers() {
            eprintln!("Skipping: Docker with Linux container support is not available");
            return;
        }
    };
}
```

Use the same `skip_without_docker!()` pattern for any new test that requires an external service via testcontainers. CI runs these on the Linux matrix entry; macOS and Windows entries skip them.

### What "e2e" means here

- **Goal**: cross every internal boundary the binary has, so a regression in the dispatch / IO / metric / exit-code surface fails CI rather than escaping to a user.
- **Scope**: the compiled binary; the HTTP API; NATS JetStream wiring (via testcontainers, 21 tests across three files); the OTLP HTTP and gRPC handlers; and the PostgreSQL backend's generated SQL (via testcontainers, 8 tests).
- **Out of scope (today)**: LynxDB, Splunk, Elastic, and KQL backends only have golden-text coverage, not live-query e2e. The Kubernetes deployment path has no e2e coverage yet (covered by the [Helm Chart roadmap item](https://github.com/timescale/rsigma/issues) when it lands).

## Golden tests

The dynamic-pipelines suite under `tests/fixtures/dynamic-pipelines/` is the canonical golden-file harness:

```text
tests/fixtures/dynamic-pipelines/
├── pipelines/                  # inputs (one *.yml per scenario)
├── sources/                    # mock source bodies (HTTP, file, command output)
└── golden/                     # expected `rsigma pipeline resolve --pretty` output
```

The CI loop in the `sigma-corpus` job iterates `pipelines/*.yml`, runs `rsigma pipeline resolve --pretty`, and diffs against `golden/${name}.json`. To run the same check locally:

```bash
cargo build --release --all-features --locked -p rsigma
for pipeline in tests/fixtures/dynamic-pipelines/pipelines/*.yml; do
  name=$(basename "$pipeline" .yml)
  golden="tests/fixtures/dynamic-pipelines/golden/${name}.json"
  diff -u "$golden" <(./target/release/rsigma pipeline resolve --pipeline "$pipeline" --pretty) \
    || echo "FAIL: $name"
done
```

To regenerate a golden after an intentional behaviour change:

```bash
./target/release/rsigma pipeline resolve --pipeline tests/fixtures/dynamic-pipelines/pipelines/<name>.yml --pretty \
    > tests/fixtures/dynamic-pipelines/golden/<name>.json
```

Then `git diff` the resulting golden file; if the diff matches your intent, commit it along with the code change. Otherwise revert and investigate.

## SigmaHQ corpus regression

CI clones [`SigmaHQ/sigma`](https://github.com/SigmaHQ/sigma) at `main` and runs three checks (see `.github/workflows/ci.yml`, job `sigma-corpus`):

```bash
# 1. Every rule must parse and compile.
./target/release/rsigma rule validate /tmp/sigma/rules/ --verbose

# 2. The dynamic-pipelines fixtures must still resolve cleanly against
#    the live corpus, validating that the field-mapping and include
#    expansion stay compatible with rules in the wild.
./target/release/rsigma rule validate /tmp/sigma/rules/ \
    --pipeline tests/fixtures/dynamic-pipelines/pipelines/field_mapping.yml \
    --pipeline tests/fixtures/dynamic-pipelines/pipelines/allowlist.yml \
    --pipeline tests/fixtures/dynamic-pipelines/pipelines/multi_format.yml \
    --pipeline tests/fixtures/dynamic-pipelines/pipelines/extract_languages.yml \
    --pipeline tests/fixtures/dynamic-pipelines/pipelines/include_expansion.yml \
    --resolve-sources --verbose

# 3. The dynamic-pipelines goldens must match (the diff loop shown above).
```

A regression in any of those steps fails the PR. Locally:

```bash
cargo build --release --all-features --locked -p rsigma
git clone --depth 1 https://github.com/SigmaHQ/sigma /tmp/sigma
./target/release/rsigma rule validate /tmp/sigma/rules/ --verbose
```

This is the only place we run "the real corpus". Keep it green.

## Coverage

The `coverage` job runs `cargo llvm-cov --workspace --all-features --lcov` on Linux and uploads `lcov.info`. It is advisory, not gating; there are no per-crate thresholds enforced today. Drops of more than a couple of percentage points warrant a comment on the PR.

## Performance regressions

Criterion benchmarks live under `crates/<crate>/benches/`. Run them manually:

```bash
cargo bench -p rsigma-eval -- eval
cargo bench -p rsigma-parser -- parse
cargo bench -p rsigma-runtime -- runtime_throughput
```

One bench target is not a Criterion suite: `correlation_memory` installs a counting global allocator and reports peak/settled heap for correlation window-state stress scenarios (high-cardinality group keys, long-lived chatty sessions), which Criterion cannot measure. It prints an aligned table and finishes in about half a minute:

```bash
cargo bench -p rsigma-eval --bench correlation_memory
```

Benchmarks are not gated in CI. The numbers in [Benchmarks](../benchmarks.md) come from a manual run on the development workstation; if a PR makes a hot-path change, attach a before/after Criterion summary in the PR description.

## Tips

- **Run only the failing test first.** `cargo test -p rsigma-runtime nats_e2e::test_replay_from_offset -- --nocapture` is much faster than `--workspace`.
- **Run feature-gated tests once with the feature off.** A `#[cfg(feature = "nats")] fn test_x()` is silently skipped if you forget; CI catches that. Locally, `cargo test --no-default-features -p rsigma-runtime` is a useful smoke test.
- **In-process NATS and OTLP** servers are spawned by the integration tests in `crates/rsigma-runtime/tests/nats_integration.rs` and `crates/rsigma-cli/tests/cli_daemon_otlp.rs`; they do not need external infrastructure.
- **Container-backed NATS e2e** in `crates/rsigma-runtime/tests/nats_e2e.rs` needs Docker. On a Mac, `colima start` or Docker Desktop is the easiest local setup.
- **CLI tests use `assert_cmd`.** They invoke the compiled `rsigma` binary, so the first run is slow because it triggers a full build. Subsequent runs reuse the cache.

See also: [Fuzzing](fuzzing.md), [Benchmarks](../benchmarks.md), [Contributing](../contributing.md).
