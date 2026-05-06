# Contributing to rsigma

Thank you for considering a contribution to rsigma! This document covers the basics of setting up a development environment, running tests, and submitting changes.

## Getting Started

### Prerequisites

- Rust toolchain (MSRV: 1.88.0). Install via [rustup](https://rustup.rs/).
- Docker (optional, required for integration tests that use testcontainers).

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

## Architecture

rsigma is a Cargo workspace with the following crates:

| Crate | Purpose |
| ----- | ------- |
| `rsigma-parser` | YAML parsing, AST, linting, auto-fix |
| `rsigma-eval` | Rule compilation, matching engine, correlation |
| `rsigma-convert` | Backend conversion (PostgreSQL, Splunk, etc.) |
| `rsigma-runtime` | Streaming I/O, daemon engine, input adapters |
| `rsigma-cli` | CLI binary (validate, lint, convert, daemon) |
| `rsigma-lsp` | Language Server Protocol implementation |

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
