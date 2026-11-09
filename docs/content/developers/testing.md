# Testing

The workspace runs several test tiers. Most are gated in CI on every PR; coverage is advisory, and representative performance is path-selective on PRs with a fuller weekly matrix.

The `CI` and `Docs audit` workflows run on every pull request, whatever its base branch or changed paths, and on `merge_group` events, so they can serve as required checks for a merge queue. A workflow skipped by a path filter would leave its required checks pending and keep the PR out of the queue, so `CI` skips work inside the run instead. Its `Changes` job runs `scripts/ci-changes.sh`, and when a PR changes only documentation (`docs/`, `assets/`, `LICENSE`, `.gitignore`, and Markdown files outside a `tests/` directory), the build and test jobs are skipped. Merge queue entries always run every job. The `CI result` job reports one pass or fail for the whole run; require it rather than individual jobs, because a skipped matrix job reports one check instead of one per OS. Coverage is advisory and does not affect `CI result`. The `Security Audit` and `Workflow security (zizmor)` workflows keep their path filters but also run on PRs against any base branch, so a PR stacked on another PR's branch gets them too.

## At a glance

| Tier | Where it lives | How to run | Gated by |
|------|----------------|------------|----------|
| Unit | `src/` modules with `#[cfg(test)] mod tests` | `cargo test --workspace --all-features --locked` | `test` job on Linux, macOS, Windows. |
| Integration (in-process) | `crates/{rsigma-parser,rsigma-eval,rsigma-convert,rsigma-runtime}/tests/*.rs` | Same. | Same. |
| End-to-end (binary + containers) | `crates/rsigma-cli/tests/cli_*.rs`, `crates/rsigma-runtime/tests/nats_e2e.rs`, `crates/rsigma-convert/tests/postgres_integration.rs` | Same; testcontainers-based tests skip when Docker is unavailable. | Same. |
| Snapshot/golden | insta snapshots mainly under `crates/rsigma-parser/tests/snapshots/`; convert/runtime/cli goldens under each crate's `tests/golden/` (or fixtures); dynamic-pipeline goldens in `tests/fixtures/dynamic-pipelines/golden/` | `cargo test` plus the SigmaHQ-corpus job for the dynamic-pipelines goldens. | `test` and `sigma-corpus` jobs. |
| SigmaHQ corpus | `.github/workflows/ci.yml` -> `sigma-corpus` | `cargo build --release --all-features --locked -p rsigma` then `target/release/rsigma rule validate …` against the pinned corpus SHA | `sigma-corpus` job, on every PR. |
| Docs audit | `scripts/docs-audit/` | `python3 scripts/docs-audit/check_sources.py`; `cargo build --locked -p rsigma --all-features` then `python3 scripts/docs-audit/check_binary.py --bin target/debug/rsigma` | `Docs catalogues` and `Docs contracts` jobs in `docs-audit.yml`, on every PR. |
| Coverage | `cargo-llvm-cov` (Linux) | CI: `cargo llvm-cov --workspace --all-features --locked --no-report` then `cargo llvm-cov report --lcov …`. Locally a one-shot form is fine; prefer `--locked`. | `coverage` job (advisory, not gating). |
| Representative performance | `.github/workflows/performance.yml`, `scripts/perf/` | `scripts/perf/fetch-fixtures.sh` then the offline and daemon harnesses | Coarse same-runner base/PR gate for evaluator hot-path, dependency, toolchain, and performance-harness changes; weekly full matrix plus native glibc/static musl scaling on dedicated eight-core amd64/arm64 runners. |

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

| Crate | Files | What they cover |
|-------|-------|-----------------|
| `rsigma-parser` | `ast_snapshots.rs`, `parse_errors.rs` (+ `snapshots/` for `insta`) | Multi-document parsing, malformed YAML, directory parsing; insta-locked AST snapshots. |
| `rsigma-eval` | `integration.rs`, `correlation_edge.rs`, `error_paths.rs`, `pipeline_errors.rs`, `regression_eval.rs`, `state_snapshot.rs`, `hir_cache.rs`, `optimize_diff.rs`, `schema_classification_golden.rs`, `gcp_audit_pipeline.rs`, `ecs_linux_pipeline.rs`, `cim_network_traffic_pipeline.rs`, `wire_shape_golden.rs`, `match_detail.rs` (+ shared `helpers/`) | Full rule-eval pipelines, correlation edge cases, snapshot replay, pipeline error semantics, HIR cache, matcher optimizer differentials, schema classification and wire-shape goldens, shipped pipeline regressions (`gcp_audit`, `cim_network_traffic` path-only; `ecs_linux` builtin and file), match detail. |
| `rsigma-convert` | `golden_postgres.rs`, `golden_lynxdb.rs`, `golden_fibratus.rs`, `golden_lucene.rs` (+ `golden/` for committed expected outputs); live SQL via `postgres_integration.rs` in the E2E section | Backend query generation for every `--format` (`default`, `view`, `timescaledb`, `continuous_aggregate`, `sliding_window`, `minimal`, Fibratus/Lucene formats as applicable). |
| `rsigma-runtime` | `integration.rs`, `evtx_integration.rs`, `sources_integration.rs`, `ocsf_golden.rs`, `alert_pipeline_golden.rs`, `enrichment_lookup.rs`, `enrichment_integration.rs` (the `nats_*.rs` files live in the E2E section below) | Streaming runtime; EVTX file parsing against the committed `security.evtx` fixture; dynamic source resolution (HTTP, file, command, in-process mocks) with TTL, refresh, and template expansion; OCSF and alert-pipeline goldens; enrichment lookup and integration. |

Helpers (test rule fixtures, common test pipelines) live in `crates/<crate>/tests/helpers/mod.rs` or `crates/<crate>/tests/common/mod.rs`. Reuse them; do not duplicate.

Do not duplicate unit-level assertions in integration tests. Integration tests own the boundaries, the multi-component chains, and the error paths.

## End-to-end tests

E2E tests cross the binary boundary or stand up real external services through containers. They are the highest-confidence layer and the longest to run.

### CLI E2E (`crates/rsigma-cli/tests/cli_*.rs`)

There are 51 `cli_*.rs` files under [`crates/rsigma-cli/tests/`](https://github.com/timescale/rsigma/tree/main/crates/rsigma-cli/tests). They invoke the freshly built `rsigma` binary via [`assert_cmd`](https://docs.rs/assert_cmd) and exercise stdin, stdout, stderr, exit codes, and (for the daemon tests) the HTTP, NATS, and OTLP wire surface.

Categories for orientation (not a contract on per-file counts):

- **Core CLI**: config, convert, eval, lint, validate, parse, fields, output format.
- **Daemon**: core daemon plus auth, TLS, tap, tail, schemas/schema routing, risk, alert pipeline, webhook, UDS, HTTP, NATS, OTLP, enrichment, fields observer, delivery, status, correlations, audit trail, sink format, incident bundle, logsource routing.
- **Detection quality/authoring**: scorecard, backtest, coverage, tune, hygiene, visibility, doc, draft, discover, classify, explain, disposition recipes.
- **Pipeline/sources**: pipeline diff, migrate-sources, sources deprecation, dump correlation state, logsource/schema routing.

List discovered tests with `cargo test -p rsigma --tests -- --list`. Prefer that over memorizing counts.

The shared harness in `crates/rsigma-cli/tests/common/mod.rs` is the canonical reference for spawning a long-running daemon under test: it drains stdout in a background thread to prevent pipe stalls, forwards stderr lines via `mpsc`, probes the actual TCP socket with `TcpStream::connect_timeout` before returning a handle, and wraps the `Child` in a `ChildGuard` RAII type that kills it on drop. PR #115 hardened this against macOS-under-load flakes by replacing every `std::thread::sleep` wait with a `poll_until` retry loop that polls the actual observable condition (HTTP status, metric counter) every 50 ms up to a 5 s deadline. Use it for any new daemon-level test; do not roll your own.

### Container E2E (NATS and Postgres via testcontainers)

Four files spin up real services in Docker containers via [`testcontainers`](https://docs.rs/testcontainers). Together they cover 29 tests, all guarded by a `can_run_linux_containers()` probe that shells out to `docker info` and checks that the daemon reports a Linux OS type. If Docker is missing or only provides Windows containers, the tests print "Skipping" and return successfully.

| File | Tests | Container | What it covers |
|------|------:|-----------|----------------|
| `crates/rsigma-runtime/tests/nats_e2e.rs` | 6 | NATS JetStream | Replay-from-offset, replay-from-timestamp, JetStream-based DLQ, consumer groups (the highest-rigor NATS surface). |
| `crates/rsigma-runtime/tests/nats_integration.rs` | 7 | NATS JetStream | Connection auth (token, NKey, JWT), TLS round-trips, ack semantics, source and sink fan-out. |
| `crates/rsigma-cli/tests/cli_daemon_nats.rs` | 8 | NATS JetStream | The full `rsigma engine daemon --input nats ...` shape: spawn the binary, point it at the container, assert against published detection matches. |
| `crates/rsigma-convert/tests/postgres_integration.rs` | 8 | PostgreSQL | Convert real Sigma rules to SQL with `convert_collection`, execute the generated queries against a live PostgreSQL container, assert match counts against the Okta cross-tenant impersonation chain from [the detection-layer-on-postgres companion project](https://github.com/mostafa/detection-layer-on-postgres). This is the only place where the documented PostgreSQL backend output formats (`default`, `view`, `timescaledb`, `continuous_aggregate`, `sliding_window`) are run as SQL against a real database; the golden tests only compare them as text. |

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

- **Goal**: cross every internal boundary the binary has, so a regression in the dispatch, IO, metric, or exit-code surface fails CI rather than escaping to a user.
- **Scope**: the compiled binary; the HTTP API; NATS JetStream wiring (via testcontainers, 21 tests across three files); the OTLP HTTP and gRPC handlers; and the PostgreSQL backend's generated SQL (via testcontainers, 8 tests).
- **Out of scope (today)**: LynxDB, Splunk, Elastic, and KQL backends only have golden-text coverage, not live-query e2e. Kubernetes deployment has no e2e coverage in this repo.

## Golden tests

The dynamic-pipelines suite under `tests/fixtures/dynamic-pipelines/` is the canonical golden-file harness:

```text
tests/fixtures/dynamic-pipelines/
├── pipelines/                  # inputs (one *.yml per scenario)
├── source-files/               # per-scenario `--source-file` YAML (top-level sources:)
├── sources/                    # mock source bodies (HTTP, file, command output)
└── golden/                     # expected `rsigma pipeline resolve --pretty` output
```

The CI loop in the `sigma-corpus` job iterates `pipelines/*.yml`, runs `rsigma pipeline resolve --pipeline … --source-file … --pretty`, and diffs against `golden/${name}.json`. To run the same check locally:

```bash
cargo build --release --all-features --locked -p rsigma
for pipeline in tests/fixtures/dynamic-pipelines/pipelines/*.yml; do
  name=$(basename "$pipeline" .yml)
  golden="tests/fixtures/dynamic-pipelines/golden/${name}.json"
  source_file="tests/fixtures/dynamic-pipelines/source-files/${name}.yml"
  diff -u "$golden" <(./target/release/rsigma pipeline resolve --pipeline "$pipeline" --source-file "$source_file" --pretty) \
    || echo "FAIL: $name"
done
```

To regenerate a golden after an intentional behavior change:

```bash
./target/release/rsigma pipeline resolve \
    --pipeline tests/fixtures/dynamic-pipelines/pipelines/<name>.yml \
    --source-file tests/fixtures/dynamic-pipelines/source-files/<name>.yml \
    --pretty \
    > tests/fixtures/dynamic-pipelines/golden/<name>.json
```

Then `git diff` the resulting golden file; if the diff matches your intent, commit it along with the code change. Otherwise revert and investigate.

## SigmaHQ corpus regression

CI clones [`SigmaHQ/sigma`](https://github.com/SigmaHQ/sigma) at the pinned SHA `994da16651194500b607a3007186c29779e1f961` (`SIGMA_CORPUS_SHA` in `.github/workflows/ci.yml`) and runs three checks (job `sigma-corpus`):

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
    --source tests/fixtures/dynamic-pipelines/source-files/ \
    --resolve-sources --verbose

# 3. The dynamic-pipelines goldens must match (the diff loop shown above).
```

A regression in any of those steps fails the PR. Locally:

```bash
cargo build --release --all-features --locked -p rsigma
mkdir -p /tmp/sigma && cd /tmp/sigma
git init -q
git remote add origin https://github.com/SigmaHQ/sigma.git
git fetch --depth 1 origin 994da16651194500b607a3007186c29779e1f961
git checkout -q FETCH_HEAD
cd - >/dev/null
./target/release/rsigma rule validate /tmp/sigma/rules/ --verbose
```

The Performance workflow also uses this pinned corpus for representative throughput and candidate-rate checks. Keep both corpus consumers pinned to the same SHA.

## Docs audit

Two standard-library Python scripts keep the docs in step with the code. `.github/workflows/docs-audit.yml` runs both on every PR, including PRs that touch no docs, because most drift starts as a code change.

- `scripts/docs-audit/check_sources.py` reads only the source tree. It compares the hand-maintained catalogues with the code they describe: fuzz harnesses and the scheduled set, lint and metrics counts in `docs/_data/vars.yml`, metric names, daemon HTTP routes, CLI features, the config keys project files may not set, environment variables, native backends, and the navigation. It also rejects em and en dashes outside lines that describe the windash dash set.
- `scripts/docs-audit/check_binary.py --bin <path>` drives an all-features binary. Every flag in `--help` must appear on its `docs/content/cli/` page, and every flag in a page's tables must exist. `docs/rsigma.schema.json` must equal `rsigma config schema`, and every schema key must be documented directly or through its flag. Every MCP tool and resource must appear in the MCP guide, the `mcp serve` page, and the `rsigma-mcp` README. The `backend targets` and `backend formats` samples must match the output line for line. Self-contained YAML examples (rules with a `title`, pipelines, and config files) must pass `rule validate`, a pipeline load, or `config validate`. Blocks with `...` or `<placeholder>` elisions are skipped.

When a check fails, fix the docs, or fix the code if the docs describe the intended behavior.

## Coverage

The `coverage` job runs `cargo llvm-cov --workspace --all-features --locked --no-report`, then `cargo llvm-cov report --lcov --output-path lcov.info`, on Linux and uploads `lcov.info`. It is advisory, not gating; there are no per-crate thresholds enforced today. Drops of more than a couple of percentage points warrant a comment on the PR.

Locally a simpler one-shot form is fine:

```bash
cargo llvm-cov --workspace --all-features --locked --lcov --output-path lcov.info
```

Prefer `--locked` so the resolve matches CI.

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

Criterion microbenchmarks are not gated in CI. The numbers in [Benchmarks](../benchmarks.md) come from a manual run on the development workstation; if a PR makes a hot-path change, attach a before/after Criterion summary in the PR description.

The Criterion suites use synthetic, mostly exact-match-indexable rules, so they measure hot paths, not representative corpus throughput. For a representative before/after, materialize the pinned SigmaHQ workload with `scripts/perf/fetch-fixtures.sh` and run `scripts/perf/baseline-eval.sh` (offline eval matrix, single core, net of rule load) and `scripts/perf/daemon-matrix.sh` (daemon HTTP end to end across lanes and flag variants, wrapping `scripts/perf/baseline-daemon.sh`). Both take an `RSIGMA` override, so a pre-change build can be measured through the same harness for an honest before-and-after. The daemon matrix includes `--include-event` variants, including the match-heavy lane where event cloning matters most, and a handcrafted event-count/value-count/value-sum/temporal-ordered correlation lane because the pinned SigmaHQ tree contains no correlation rules.

The Performance workflow builds the PR and its base revision on the same GitHub-hosted runner, runs the load-corrected median-of-three offline matrix through one checked-in harness, verifies match counts, and rejects only a head/base EPS ratio below 0.5. The floor is intentionally coarse: it catches order-of-magnitude regressions, and shared-runner noise is too high for finer gating. A weekly/manual job runs five samples of the full offline matrix, reports a deterministic bootstrap 95% confidence interval, runs the daemon matrix, and retains the raw artifacts for 90 days.

Weekly/manual runs also build native glibc and static musl image binaries on dedicated eight-core amd64 and arm64 runners. `scripts/perf/inflight-compare.sh` alternates five samples each at detection depths 4 and 5, then rejects a depth-5 throughput ratio below 0.98 or a backpressure-rate increase above 0.008. This gate covers the allocator and architecture behavior that the native PR comparison cannot observe.

The production candidate index is measured directly, rather than inferred from the witness-audit simulation:

```bash
RSIGMA_DIFF_RULES="$PWD/target/perf-fixtures/sigma/rules" \
RSIGMA_DIFF_EVENTS="$PWD/target/perf-fixtures/events" \
    cargo test -p rsigma-eval --all-features \
      corpus_candidate_rate -- --ignored --nocapture
```

That ignored corpus test reports each lane's p95 candidate count/rate and fails at 10% of loaded rules. See the [SigmaHQ corpus baseline](../benchmarks.md#sigmahq-corpus-baseline-representative) for the recorded matrix.

## Tips

- **Run only the failing test first.** `cargo test -p rsigma-runtime nats_e2e::test_replay_from_offset -- --nocapture` is much faster than `--workspace`.
- **Run feature-gated tests once with the feature off.** A `#[cfg(feature = "nats")] fn test_x()` is silently skipped if you forget; CI catches that. Locally, `cargo test --no-default-features -p rsigma-runtime` is a useful smoke test.
- **In-process NATS and OTLP** servers are spawned by the integration tests in `crates/rsigma-runtime/tests/nats_integration.rs` and `crates/rsigma-cli/tests/cli_daemon_otlp.rs`; they do not need external infrastructure.
- **Container-backed NATS e2e** in `crates/rsigma-runtime/tests/nats_e2e.rs` needs Docker. On a Mac, `colima start` or Docker Desktop is the easiest local setup.
- **CLI tests use `assert_cmd`.** They invoke the compiled `rsigma` binary, so the first run is slow because it triggers a full build. Subsequent runs reuse the cache.

See also: [Fuzzing](fuzzing.md), [Benchmarks](../benchmarks.md), [Contributing](../contributing.md).
