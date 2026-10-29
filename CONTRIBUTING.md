# Contributing to rsigma

Thank you for considering a contribution to rsigma! This document covers the basics of setting up a development environment, running tests, and submitting changes.

## Getting Started

### Prerequisites

- Rust toolchain (MSRV: 1.96.0). Install via [rustup](https://rustup.rs/); opening the repository installs the pinned toolchain from `rust-toolchain.toml`.
- Docker (optional, required for integration tests that use testcontainers).
- Node.js 20+ (optional, only for building the documentation site under `docs/`; not needed for the Rust workspace).

### Building

```bash
cargo build --workspace
```

### Running Tests

```bash
# Unit and integration tests
cargo test --workspace

# Clippy lints (must pass with zero warnings)
cargo clippy --workspace --all-targets --all-features -- -D warnings

# Formatting check
cargo fmt --all -- --check

# Dependency audit
cargo deny check
```

## Development Workflow

### Rust toolchain updates

The compiler used for development, CI, release artifacts, and the minimum supported Rust version move together. Keep `Cargo.toml`, `rust-toolchain.toml`, the Dockerfile builder tag, the README badge, and this prerequisite on the same exact `X.Y.Z` version. Update the Docker digest for that exact image tag, run `scripts/check-toolchain-version.sh` and every pre-push gate, and ship the compatibility change in its own pull request.

### Branching

- Feature branches: `feat/<name>`
- Fix branches: `fix/<name>`
- Target `main` for all PRs.

### Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/) style:

- `feat(parser): add support for temporal_ordered correlation`
- `fix(convert): prevent SQL injection in identifier interpolation`
- `test: add snapshot tests for parser AST`
- `ci: add cargo-deny job to audit workflow`

### Pull Requests

- Keep PRs focused on a single concern.
- Reference any related issue numbers.
- Ensure CI is green before requesting review.
- New public API surface should include rustdoc with examples.
- New features should include tests. Prefer integration tests for cross-crate behavior and unit tests for isolated logic.

## Code Quality

- `cargo fmt` and `cargo clippy` must pass with zero warnings.
- `cargo deny check` must pass (licenses, advisories, bans, sources).
- Do not add `unsafe` code without justification and a safety comment.
- Avoid `.unwrap()` in library crates. Use `?` or return descriptive errors. `.unwrap()` is acceptable in tests.

## Testing

- **Unit tests** live in `#[cfg(test)]` modules alongside the code they test.
- **Integration tests** go under `crates/<crate>/tests/`.
- **Snapshot tests** use [insta](https://insta.rs/). Run `cargo insta review` after updating snapshots.
- **Fuzz targets** live in `fuzz/fuzz_targets/`. Add a fuzz target for any new untrusted input surface.
- **Benchmarks** use Criterion and live in `benches/`.

### Backend engine tests

Conversion backends are tested by running their queries in the real engines. Each case in `crates/rsigma-convert/tests/engines/cases/` is a Sigma rule with sample events and the indexes of the events it must match:

```yaml
description: What the case checks.
rule: { ... }            # a Sigma rule
events: [ ... ]          # one map per event
matches: [0, 2]          # indexes of the events the rule must match
pipeline: |              # optional: processing pipeline YAML applied before the engine's own pipelines
  ...
unsupported: [lynxdb]    # optional: engines whose backend must reject the rule
known_failures:          # optional: engine label to a confirmed defect
  postgres-jsonb:
    type: match-mismatch
    reason: why the result is wrong
    actual: [1]
```

The engine labels are `eval`, `postgres-jsonb`, `postgres-columns`, `lynxdb`, `fibratus`, `fibratus-nomacros`, and `test-pysigma`. Known failures use `type: match-mismatch` with the exact matched indexes, `type: engine-error` with a required error substring, or `type: output-difference` with the exact rsigma and reference queries. A failure that changes outcome or starts passing fails the test, so a fix must update or remove its entry. Prefer cases that probe edge behavior (missing fields, escapes, grouping, case) over happy paths.

The `eval` run is part of `cargo test`. The engine runs are `#[ignore]`d and need extra tooling:

```bash
# Docker: PostgreSQL 18 (both modes), LynxDB built from its release, pySigma's test backend
cargo test -p rsigma-convert --test engine_postgres -- --ignored
cargo test -p rsigma-convert --test engine_lynxdb -- --ignored
cargo test -p rsigma-convert --test engine_test_backend -- --ignored

# Windows with Go: the Fibratus filter engine
cargo test -p rsigma-convert --test engine_fibratus -- --ignored
```

The PostgreSQL and LynxDB runs also check SigmaHQ rules whose conditions need grouping. For each rule that uses only plain string matches they build events from the rule's own values, take the expected matches from `engine eval`, and require the engine to agree (PostgreSQL in both modes). LynxDB only takes rules whose values avoid characters it renders or matches wrongly. Point them at a SigmaHQ checkout to run them. Without one they are skipped locally and fail in CI:

```bash
RSIGMA_SIGMA_CORPUS=/path/to/sigma cargo test -p rsigma-convert --test engine_postgres -- --ignored
RSIGMA_SIGMA_CORPUS=/path/to/sigma cargo test -p rsigma-convert --test engine_lynxdb -- --ignored
```
In CI each engine has its own workflow (`.github/workflows/engine-*.yml`) that runs only when its backend, its harness, the shared cases, or the conversion core changes.

## Documentation

Two surfaces must stay in sync with what each release ships:

1. **Crate READMEs** (`README.md` at the workspace root, plus `crates/<crate>/README.md`) for any public API or behavior change. The root README documents runtime/security features (Docker hardening, signature verification, supported features).
2. **The docmd site under `docs/`:** the primary user-facing documentation surface, published at `https://rsigma.io/`. The whole docmd project (config, `package.json`, local plugin, assets, and Markdown under `docs/content/`) lives in `docs/`. A PR that adds or changes:
   - A user-facing capability → add or update the relevant `docs/content/guide/<topic>.md` page and an entry in `docs/docmd.config.js` navigation (under the appropriate User Guide sub-category)
   - A CLI subcommand or flag → update the matching `docs/content/cli/<group>/<command>.md` page (e.g. `docs/content/cli/engine/daemon.md`)
   - A daemon config key → update `docs/content/cli/engine/daemon.md` and any cross-referenced guide page
   - A public library API surface → update the matching `docs/content/library/<crate>.md` page
   - A Prometheus metric, HTTP endpoint, environment variable, lint rule, feature flag, or backend → update the corresponding `docs/content/reference/<topic>.md` page

The site publishes from `main`, so docs for a change that is not in a release yet must say so. Tag the page of a new command or feature on the line below its H1, a new section on the line below its heading, and a new flag, key, or table row at the end of its description, with `{{ added "unreleased" }}`. Docs that only describe already-released behavior need no tag. The release PR replaces every `{{ added "unreleased" }}` with `{{ added "X.Y.Z" }}` for the version being cut, except on lines marked with a `<!-- keep-unreleased -->` comment. The docs plugin renders the tag as a link to that version's release notes and fails the build on a version that is not in `CHANGELOG.md`. Keep section headings free of tags so their anchors stay stable.

From `docs/`, run `npm install` once, then `npm run docs:build` and `npm run docs:validate` before pushing docs changes; `.github/workflows/docs.yml` enforces both on every PR. `.github/workflows/docs-audit.yml` also checks the docs catalogues, CLI pages, config schema, MCP tool list, backend samples, and YAML examples against the code on every PR; see [Testing: Docs audit](https://rsigma.io/developers/testing/#docs-audit) for running the two scripts locally.

A `CHANGELOG.md` entry under `## [X.Y.Z] - YYYY-MM-DD` is part of the release commit (the same content gets copied to the GitHub Release body). For features with public-API impact, the release notes mention the affected README and `docs/` pages so reviewers can sanity-check the doc sync.

## Architecture

rsigma is a Cargo workspace with the following crates:

| Crate | Purpose |
| ----- | ------- |
| `rsigma-parser` | YAML parsing, AST, linting, auto-fix |
| `rsigma-eval` | Rule compilation, matching engine, correlation |
| `rsigma-convert` | Backend conversion (PostgreSQL, LynxDB, Fibratus) |
| `rsigma-runtime` | Streaming I/O, daemon engine, input adapters |
| `rsigma-mcp` | Model Context Protocol server exposing rsigma to AI agents |
| `rsigma-cli` | CLI binary (validate, lint, convert, daemon) |
| `rsigma-lsp` | Language Server Protocol implementation |
| `rstix` | STIX 2.1 library: typed objects, bundle parse/stream, semantic validation (TAXII client planned) |

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](https://github.com/timescale/rsigma/blob/main/LICENSE).
