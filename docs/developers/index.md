# Developer orientation

These pages are for contributors hacking on rsigma itself, not consumers of the Sigma engine. If you came here looking for "how do I run rules", that lives in the [Quick start](../getting-started/quick-start.md); the public Rust API surface is in [Library](../library/index.md).

## Repo map

```text
rsigma/
├── crates/
│   ├── rsigma-parser/      # Sigma YAML → AST, 68 lint rules
│   ├── rsigma-eval/        # Compiler, matcher, correlation engine, pipelines
│   ├── rsigma-convert/     # Backend trait + Postgres and LynxDB implementations
│   ├── rsigma-runtime/     # Streaming runtime, input parsers, dynamic sources
│   ├── rsigma-cli/         # The `rsigma` binary
│   └── rsigma-lsp/         # The `rsigma-lsp` language server
├── docs/                   # This site (MkDocs Material)
├── fuzz/                   # 15 cargo-fuzz harnesses
├── tests/fixtures/         # Cross-crate test data (dynamic pipelines, etc.)
├── pipelines/              # Built-in processing pipelines (ecs_windows, sysmon)
├── .github/workflows/      # CI: test, fuzz, audit, docker, publish, release
└── Cargo.toml              # Workspace; single shared version
```

For the runtime data flow and how the crates talk to each other, see [Architecture](../reference/architecture.md).

## Where to start

| You want to... | Start with |
|----------------|------------|
| Understand the crate graph and data flow | [Architecture](../reference/architecture.md). |
| Add a new SIEM backend (Elastic, Splunk, …) | [Adding Backends](adding-backends.md). |
| Add a new input format (CEF, EVTX, custom binary) | [Adding Input Formats](adding-input-formats.md). |
| Add or change a lint rule, or extend the LSP | [Linter and LSP](linter-and-lsp.md). |
| Write or run tests | [Testing](testing.md). |
| Write or run fuzz harnesses | [Fuzzing](fuzzing.md). |
| Send your first PR | [Contributing](../contributing.md). |
| See how each component performs | [Benchmarks](../benchmarks.md). |

## Conventions

- **Single workspace version.** Every crate bumps together. Do not bump individually; the release pipeline expects a single `vX.Y.Z` tag.
- **Edition 2024.** MSRV is `{{ rsigma.msrv }}` (the workspace's `rust-version` in `Cargo.toml`), enforced by the `msrv` CI job. Edition 2024 itself compiles on Rust 1.85+, but features and tests are written against the MSRV.
- **No warnings.** `RUSTFLAGS=-Dwarnings` is set globally in CI.
- **`cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets --all-features -- -D warnings`** must pass.
- **All features for testing.** CI runs `cargo test --workspace --all-features --locked`; if your change is feature-gated, make sure the gate works in isolation too.
- **Reproducible builds.** `Cargo.lock` is committed and reproducible builds are required.
- **Hooks, not branches, gate releases.** PRs target `main`; only the release pipeline pushes tags.

Full process is in [Contributing](../contributing.md), and the workspace-level CI/CD posture is in the [development-workflow rule](https://github.com/timescale/rsigma/blob/main/.cursor/rules/development-workflow.mdc).

## Tooling expectations

You should have:

- `rustup` with the stable toolchain, plus `clippy` and `rustfmt`.
- `cargo-deny` (or be ready to install it) for dependency policy checks.
- `cargo-fuzz` if you plan to run or extend the [fuzz harnesses](fuzzing.md).
- Docker, if you plan to touch the [Docker image](../deployment/docker.md) or the cross-platform release pipeline.
- Optionally `act` to dry-run GitHub Actions locally.

## Editor setup

Either of:

- The [rsigma VS Code extension](https://marketplace.visualstudio.com/items?itemName=timescale.rsigma) for Sigma rule authoring; this also drives the language server (`rsigma-lsp`).
- A `rust-analyzer`-aware editor for the Rust code itself. The workspace uses Cargo features extensively; configure `rust-analyzer.cargo.features` to `"all"` to get sensible IntelliSense.

## Reading list

- [Architecture](../reference/architecture.md) for the system overview.
- [Lint Rules reference](../reference/lint-rules.md) before you touch lints.
- The per-crate README on GitHub for the exhaustive trait surface that the [Library](../library/index.md) pages summarise.
- The [GitHub issues](https://github.com/timescale/rsigma/issues) tagged `good first issue` for entry points.
