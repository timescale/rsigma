# Changelog

All notable changes to RSigma are documented in this file.
Each entry corresponds to a [GitHub Release](https://github.com/timescale/rsigma/releases).

## [Unreleased]

### Release pipeline, CI, Docker, and supply-chain hardening

Tightens every link in the release chain before v0.14.0 ships so the act of publishing itself does not undermine the correctness work that already landed.

**`publish.yml`** no longer masks `cargo publish` failures with `|| echo "::warning::… already published or failed"`. A new pre-flight step dry-runs every crate in dependency order before any side-effecting publish; authentication, lockfile drift, and dependency-resolution issues now abort the workflow before any crate hits crates.io. Every actual publish passes `--locked`. The `workflow_dispatch` trigger keeps the dry-run rehearsal path; only `release: published` touches the real registry. The `Swatinem/rust-cache` step was removed to close a cache-poisoning vector against the signed artifacts.

**`release-binaries.yml`** pins the toolchain through `dtolnay/rust-toolchain@... stable` with `targets:` set inline (replacing the unpinned `rustup update` plus follow-up `rustup target add`). After downloading the per-target archives, the release job generates a `SHA256SUMS` manifest and uploads it as a release asset, covered by the same `actions/attest-build-provenance` subject path as the archives. Consumers who do not pull the SLSA attestation can still verify download integrity against the manifest.

**Workspace.** `rust-toolchain.toml` pins ambient `cargo` invocations to the MSRV of 1.88.0, so contributors who do not pass `+stable` build against the same Rust the MSRV CI job uses. A new `[profile.release]` block enables `lto = "thin"`, `codegen-units = 1`, and `strip = true`. The pin surfaced an existing 1.88.0 clippy / rustdoc backlog (collapsible-else, uninlined-format-args, duplicated `#[cfg(feature = "daemon-tls")]`, broken intra-doc links, unclosed `<host>` HTML tags); this release ships the cleanup so `cargo clippy --workspace --all-targets --all-features -- -D warnings` and `cargo doc --workspace --no-deps -D warnings -D rustdoc::broken-intra-doc-links` are gate-green.

**CI.** The Sigma corpus regression job now fetches `SigmaHQ/sigma` at a pinned commit (bumped by editing `SIGMA_CORPUS_SHA` in `ci.yml`) instead of `master` tip, so an upstream rule edit cannot turn the workspace red without a deliberate commit here. The MSRV check gains `--all-targets` so a test- or example-only dependency that requires a newer Rust cannot slip past the MSRV gate. The coverage job uploads `lcov.info` as an artifact for external trackers. A new `doc` job runs `cargo doc --workspace --all-features --locked --no-deps` with the strict rustdoc gate so a future broken intra-doc link fails CI rather than landing silently.

**Docker.** Both `cargo build` stages in the `Dockerfile` add `--locked`, and `rust-toolchain.toml` is part of the dependency-cache layer so the toolchain version is part of the layer's cache key. `.dockerignore` excludes `/fuzz`, `/tests`, `/docs`, `/docs-drafts`, `/site`, and `/benches` from the build context (root-anchored so per-crate `tests/` subdirectories are unaffected). The Grype vulnerability scan runs as a 2-leg matrix (`amd64` × `arm64`) so arch-specific CVEs cannot land on a release image unnoticed; SARIF uploads label findings by arch in the Security tab.

**Supply chain.** `deny.toml` denies wildcard dependency versions (`wildcards = "deny"`), surfaces unmaintained-crate advisories via `unmaintained = "workspace"`, and grows a quarterly-review note plus "Last reviewed" date on the `RUSTSEC-2021-0153` ignore. The `audit` workflow now triggers on `deny.toml` and its own workflow file in addition to manifest and lockfile changes, and pulls `cargo-audit` from `taiki-e/install-action` prebuilds instead of compiling it from source on every invocation. Dependabot picks up two new ecosystems: `docker` against `/` (so a new digest for the pinned `rust:1-alpine` base image surfaces as a PR) and `npm` against `/editors/vscode` (so the extension's TypeScript / `@vscode/vsce` / eslint deps follow the same weekly batching as the Cargo deps).

### Runtime hardening: HTTP egress policy, body cap, hot-reload tuning, fail-closed dynamic sources (#167)

Cluster of P0 hardening fixes for the daemon's HTTP surfaces and rule hot-reload. None of these were exploitable in a default deployment, but each silently produced behavior different from what the operator (or rule author) wrote, and all of them ship together before v0.14.0.

**HTTP egress policy for sources and enrichers.** Both the dynamic-source HTTP resolver and the HTTP enricher previously accepted any URL declared by a rule or pipeline, including the cloud-metadata IMDS endpoint at `169.254.169.254`, IPv6 link-local (`fe80::/10`), and the AWS IPv6 metadata address `fd00:ec2::254`. The new `rsigma_runtime::EgressPolicy` describes a category-based deny list applied at *DNS resolution time* (`EgressFilteredResolver` implements `reqwest::dns::Resolve`), so DNS rebinding cannot defeat host-string checks. Three presets ship: `default` (block link-local + cloud metadata, allow loopback + private), `strict` (also block loopback + RFC1918 private), and `permissive`. Per-category builders (`with_block_link_local`, `with_block_cloud_metadata`, `with_block_loopback`, `with_block_private`) cover the in-between cases. The policy is selectable on `rsigma engine daemon` via `--egress-policy <default|strict|permissive>` and on the layered YAML config via `daemon.engine.egress_policy`. Default is `default`.

**HTTP enricher response body cap.** `HttpEnricher::enrich` used to consume the upstream body via `reqwest::Response::bytes`, which buffers the entire response into memory. A misbehaving enrichment endpoint streaming an unbounded body could OOM the daemon. The fetch path now checks `Content-Length` up-front and streams chunks with a 10 MiB ceiling (`DEFAULT_ENRICHER_MAX_RESPONSE_BYTES`, matching the existing source-side cap), configurable per enricher via `with_max_response_bytes`.

**Engine tuning survives hot-reload.** `LogProcessor::reload_rules` rebuilt the `RuntimeEngine` through `RuntimeEngine::new`, which defaults `bloom_prefilter` off, `bloom_max_bytes` to `None`, and (with `daachorse-index`) `cross_rule_ac` off. Daemons that enabled those flags at startup silently lost them on every reload. The reload path now snapshots those settings on the old engine via three new accessors (`RuntimeEngine::bloom_prefilter`, `bloom_max_bytes`, `cross_rule_ac`) and replays them on the new engine before `load_rules` runs.

**Dynamic-source reload fails closed.** `RuntimeEngine::load_rules` resolved dynamic sources inside `block_in_place` and, when resolution returned an error, logged a warning and continued with the captured pipelines as-is. `${source.*}` placeholders stayed unexpanded, producing rules with semantics different from the operator's intent. On a hot-reload this silently replaced a healthy engine with a broken one. Both the "resolver failed" and "no tokio runtime available" branches now return an error from `load_rules`, so `LogProcessor::reload_rules` propagates it and skips the engine swap. The captured pipelines are restored before the error returns so a retry sees the same input state.

**Shared HTTP client for dynamic sources.** `resolve_http_with_limit` constructed a fresh `reqwest::Client` on every call. Under a refresh storm (a dynamic-source pipeline polling several feeds every 30 seconds) this rebuilt TLS state, DNS resolvers, and connection pools each iteration. A process-wide `OnceLock<Arc<reqwest::Client>>` exposed through `sources::http::shared_http_source_client` now backs every source fetch; per-call timeouts ride along via `RequestBuilder::timeout(...)`. HTTP enrichers already shared an `Arc<reqwest::Client>` (`build_default_http_client`), and the policy resolver above is wired through both clients.

**API additions.** `pub use` from `rsigma-runtime`: `EgressDenial`, `EgressFilteredResolver`, `EgressPolicy`, `default_egress_policy`, `set_default_egress_policy`, `enrichment::http::DEFAULT_ENRICHER_MAX_RESPONSE_BYTES`, `sources::http::shared_http_source_client`. `EngineStats` now derives `Debug` / `Clone` / `Copy`. `HttpEnricher::with_max_response_bytes` is the only new method on an existing public type.

**Tests.** Cumulative: 12 new unit + integration tests across `rsigma-runtime` (egress policy categories, IPv4-mapped IPv6 recursion, builder overrides, filtered resolver against literal `169.254.169.254` and `8.8.8.8`, body-cap rejection via `Content-Length`, body-cap rejection via chunked-stream overflow, reload tuning preservation, fail-closed dynamic source, shared client `Arc` identity) plus 2 new integration tests in `rsigma-cli` (`engine.egress_policy` config-to-flag flow and clap rejection of an invalid policy value). The 14 enrichment integration tests (wiremock on 127.0.0.1) and the 35 source integration tests continue to pass under the default policy.

### Sigma correctness: multi-field correlations, empty median, unsupported convert modifiers (#166)

Closes a cluster of silently-wrong evaluation and conversion behaviors so v0.14.0 ships none of them.

**Multi-field `value_count` now uses a composite distinct-key.** Previously the engine read `fields.first()` and ignored the rest, so `field: [User, SrcIp]` over events with the same user from different source IPs counted as one distinct value. The fix joins the rendered field values with the ASCII Unit Separator (`\u{1f}`) and counts distinct tuples; a missing field on any component drops the event (matching the prior single-field behavior). The single-field hot path keeps its old allocation profile.

**Multi-field `value_sum` / `value_avg` / `value_percentile` / `value_median` are now rejected at compile time.** The Sigma spec does not define how to combine several numeric fields under one of these aggregations. The previous behavior silently used only the first field and dropped data. The compiler now returns a structured `CorrelationError` listing the offending fields.

**Empty `value_median` windows now return `None`.** They used to return `0.0`, which spuriously satisfied predicates like `lte: 0` and `eq: 0`. The behavior now mirrors `value_percentile`, which already returned `None` for empty windows.

**Detection-name selector matching is now consistent across crates.** The evaluator's `pattern_matches` lacked the middle-`*` branch (`sel*main`) that the converter had, so the same selector pattern silently resolved to different detection sets in eval vs convert. Hoist a single `detection_name_matches` (plus `SelectorPattern::matches_detection_name`) into `rsigma-parser` and reuse it from both crates, with cross-crate tests covering exact, full wildcard, prefix wildcard, suffix wildcard, and middle wildcard cases.

**The `rsigma-convert` default item dispatch rejects modifiers it cannot express.** `default_convert_detection_item` previously fell through to `Backend::convert_field_eq_str` for any modifier it did not handle explicitly, so a rule using `|neq`, `|base64`, `|base64offset`, `|wide`, `|utf16`, `|utf16be`, `|windash`, `|expand`, regex flags without `re` (`|m`, `|s`), or timestamp parts (`|minute`/`|hour`/`|day`/`|week`/`|month`/`|year`) shipped SQL/SPL with different semantics from what the author wrote. The dispatch now returns `ConvertError::UnsupportedModifier` before the fall-through. Backends that handle one of these modifiers natively can override `Backend::convert_detection_item` and bypass the default. A defensive `ok_or_else` replaces the last `unwrap()` on the selector-dispatch path.

**Dependency cleanup.** `base64` and `ipnet` were declared in `crates/rsigma-convert/Cargo.toml` but never referenced from anywhere under `crates/rsigma-convert/src/`. Dropped.

**Docs.** `crates/rsigma-eval/README.md` now explains that `percentile` selects *which* percentile to compute (not the threshold), that an empty window does not fire, and that the four numeric aggregations require a single field.

### Custom tag namespaces for the linter (#161, #162)

`rsigma rule lint` no longer forces teams to disable `unknown_tag_namespace` wholesale just to use organisation-specific tags. A repeatable `--tag-namespace <ns>` flag and a `tag_namespaces` list in `.rsigma-lint.yml` register extra namespaces that are recognised alongside the built-in spec set (`attack`, `car`, `cve`, `d3fend`, `detection`, `stp`, `tlp`). Namespace values are normalised to lowercase, and when `unknown_tag_namespace` does fire its message lists the full combined set of known namespaces.

On the library side, `LintConfig` gains a `tag_namespaces` field that layers through the same merge path as `disabled_rules` and `exclude_patterns`. Both list-valued fields, `exclude_patterns` and `tag_namespaces`, are now de-duplicated (first occurrence wins) when a config file and CLI flags are layered, so overlapping entries no longer accumulate. Docs cover the new flag and config key across the lint CLI reference, the linting guide, the lint-rules reference, and the linter developer guide; the CLI and root READMEs list the flag.

### TTY-aware output + structured output formats (#157)

Every rsigma subcommand can now emit its structured output in one of five formats, selected by a new **global** `--output-format <json|ndjson|table|csv|tsv>` flag. The default is TTY-aware: pretty JSON when stdout is a terminal, plain NDJSON when piped or redirected, so `rsigma engine eval … | jq` does the right thing without any extra flag and `rsigma engine eval` in a terminal is finally readable.

**New global flags.** Three more global knobs ride alongside `--output-format` and the existing `--log-format`:

- `--color <auto|always|never>` honours [`NO_COLOR`](https://no-color.org/) under `auto` (the default).
- `--quiet` / `-q` suppresses every non-data line (progress, summary, fallback warnings); errors still go to stderr.
- `--no-stats` suppresses only the trailing summary line; progress messages still appear.

All four resolve through the same layered precedence as the rest of the config: **flag > `RSIGMA_GLOBAL__*` env > `global.*` in the YAML config > TTY-aware default**.

**Per-command rendering.**

- **`engine eval`** is the showcase. `table` renders a `LEVEL | RULE | TYPE | DETAIL` summary (numeric columns right-aligned). `csv` and `tsv` stream a header line plus one row per match. `--pretty` is preserved as a backwards-compatibility alias for "pretty JSON" and wins over the TTY default.
- **`rule fields`** folds its `--json` flag into the new selector; `--json` is kept as a hidden deprecated alias for `--output-format json`. The legacy table view stays the default even when piped, so existing pipelines are unchanged. `--output-format ndjson` streams one field record per line.
- **`rule lint`** keeps the coloured human view as the default. `--output-format json` emits a `{summary, findings}` envelope; `ndjson` streams one `Finding` per line; `csv` / `tsv` write a `PATH,SEVERITY,RULE,LINE,MESSAGE` table. The per-command `--color` flag is gone in favour of the global one; behaviour is identical.
- **`rule parse`**, **`rule condition`**, **`rule stdin`**: routed through the shared JSON renderer; `--pretty` still defaults to on (the AST is small and human-friendly is the default).
- **`backend convert`**: keeps its existing `-f, --format` for the backend query format and `-o, --output` for the output file unchanged. `--output-format json` wraps the queries in a `{target, format, queries: [{rule_title, rule_id, query}, …]}` envelope. The non-JSON tabular formats are not meaningful for free-form query text, so the command prints a stderr warning and falls back to raw text (the warning is itself suppressible with `--quiet`).

**Output module.** A new `crates/rsigma-cli/src/output/` module owns the `OutputFormat` and `ColorChoice` enums, the `OutputCtx` resolver, the `Tabular` trait + width-aligning `render_table` (with auto-right-align for numeric columns), the streaming `DelimitedWriter` for CSV/TSV (hand-rolled RFC 4180-style escaping, no new dependency), and the `Painter` previously in `commands/lint.rs` (now reused by every command). The lint Painter is gone; the shared one resolves color from `--color` plus `NO_COLOR` plus TTY detection just like before.

**Config schema.** `global.format` is renamed to `global.output_format` (the old key was reserved for this work and was inert), and `eval.format` is dropped (it was inert too). The committed template, the JSON Schema emitted by `rsigma config schema`, and the schema drift-guard test all reflect the rename.

**Tests.** New unit tests in `crates/rsigma-cli/src/output/mod.rs` cover format / color parsing, TTY default resolution, `--quiet` / `--no-stats` semantics, CSV/TSV escaping edge cases, and the `Tabular` row shape. A new `crates/rsigma-cli/tests/cli_output_format.rs` integration suite (19 tests) exercises every format end to end on `engine eval`, `rule lint`, `rule fields`, and `backend convert`, plus the env-layer and config-file resolution and the flag-beats-env precedence.

**Docs.** New canonical `docs/reference/output.md` page (registered in `docs/reference/.pages`) covering formats, TTY behaviour, color, quiet/no-stats, precedence, and per-command behaviour. The eval CLI doc gains an output-format section and a table-view example; the env-vars doc lists the two new variables; root README and CLI README gain a Global flags section. The configuration reference example shows the new `global.output_format` / `global.color` keys.

### Layered YAML configuration + `rsigma config` group (#152)

`engine daemon` and `engine eval` are now driven by an optional layered YAML config file with explicit precedence **CLI flag > env > project file > user file > system file > compiled default**, applied per leaf. The same machinery is exposed through a new `rsigma config` command group for scaffolding, validation, introspection, and reload.

**Discovery (lowest to highest precedence):** compiled defaults, `/etc/rsigma/config.yaml`, `$XDG_CONFIG_HOME/rsigma/config.yaml` (defaulting to `~/.config/rsigma/config.yaml`), the nearest `.rsigmarc` walked up from the current directory, `./rsigma.yaml`, the environment layer, and finally CLI flags. `--config <PATH>` replaces the discovery chain entirely with one explicit file. The XDG path is computed by honouring `XDG_CONFIG_HOME` directly, not `dirs::config_dir()`, so macOS stays under `~/.config/rsigma` to match the `rsigma install` layout.

**Schema.** A single typed `RsigmaConfigPartial` (`Option`-typed partial structs merged by a generic `merge`) covers three sections: `global` (currently `log_format`; `color`/`format` are reserved for the output-format work), `daemon` (mirrors every non-secret daemon flag, with nested `api`/`api.tls`/`input`/`output`/`correlation`/`state`/`engine`/`nats` sub-sections), and `eval` (mirrors the eval flag surface). Secret-bearing daemon settings (NATS creds/token/password/nkey, TLS key password) are deliberately absent from the schema; they remain env/flag-only.

**Resolution.** The resolver folds each layer's partial into a `serde_json::Value` with a generic deep-merge and tracks the winning layer per leaf (`default`, `file`, `env`, `flag`). CLI flag wins are detected via clap `ArgMatches::value_source`; the env layer reads a uniform `RSIGMA_<SECTION>__<KEY>` scheme (the `__` separator deliberately leaves the existing single-underscore clap-bound names like `NATS_CREDS` and `RSIGMA_CONSUMER_GROUP` untouched). Values are parsed as YAML scalars so ints/bools/lists coerce naturally. A `defaults` module of named constants is the single source of every default; clap's `default_value` attributes are referenced from those constants and a drift-guard test pins the two together.

**`rsigma config` subcommand group.** Six subcommands, all agent-friendly (data to stdout, diagnostics to stderr):

- `config init [-o PATH] [--force]` writes a commented template (default `./rsigma.yaml`) with a `# yaml-language-server: $schema=` header. Refuses to overwrite without `--force`.
- `config validate [-c PATH] [--format text|json] [--strict]` deserializes every layer, warns on unknown keys via `serde_ignored`, warns on sections set but inert in this build (`daemon.api.tls` without `daemon-tls`, `daemon.nats` without `daemon-nats`, `daemon.engine.cross_rule_ac` without `daachorse-index`), and prints a structured envelope (`{ ok, sources, unknown_keys, inactive_sections }`) in JSON mode. `--strict` upgrades unknown keys to exit `3`.
- `config show [-c PATH] [--for global|daemon|eval] [--format text|json|yaml]` prints the effective config (defaults < file < env) with the source of each leaf.
- `config schema` emits a [JSON Schema](https://json-schema.org/) (draft 2020-12) derived from the same partial structs the loader uses, via `schemars::JsonSchema`. The schema is what powers editor autocomplete (yaml-language-server) and what agents/CI can validate against.
- `config path [-c PATH]` lists the config files that would be loaded.
- `config reload [--addr ADDR] [-c PATH]` triggers a daemon hot-reload via `POST /api/v1/reload`, mapping `0.0.0.0`/`[::]` bind addresses to loopback so the client can actually connect. Cross-platform (works on Windows, where `SIGHUP` does not exist); `kill -HUP <pid>` still works on unix.

**Command wiring.** `DaemonArgs` and `EvalArgs` both gain `--config <PATH>` and `--dry-run`. `--rules` is now optional on both: it can be supplied via `daemon.rules` / `eval.rules` instead, with a clear error if neither layer provides it. `main()` now goes through `Cli::command().get_matches() + from_arg_matches` so the daemon and eval dispatch paths (including the deprecated flat `daemon` and `eval` aliases) can hand the sub-`ArgMatches` to the resolver. `global.log_format` from a discovered config file (or `RSIGMA_GLOBAL__LOG_FORMAT`) drives the CLI log subscriber when `--log-format` is not passed, so the `global` section is no longer inert.

**Dependencies.** Adds the tiny `serde_ignored 0.1` (unknown-key detection) and promotes `schemars 1.x` (already present transitively via `jsonschema`) to a direct dependency. No new top-level versions in `Cargo.lock` beyond `serde_ignored`. `--config reload` reuses the existing `ureq` dependency.

**Tests.** Unit tests cover layered file discovery, `serde_ignored` unknown-key collection, per-field precedence on both daemon and eval (CLI > env > file > default), JSON deep-merge with Null no-op, the `RSIGMA_*__*` env scheme, and the daemon-defaults drift guard. A new `crates/rsigma-cli/tests/cli_config.rs` integration suite (10 tests) exercises the real binary end to end: `config init` round-trips (the committed template validates clean and carries zero unknown keys), `--force` guard, unknown-key warnings + `--strict` exit, missing-file error, JSON schema emission, `config show` JSON source annotations, `config path`, and the config-to-command flow (`engine eval` reading rules from config, an explicit `--rules` overriding the config, and `engine daemon --dry-run` printing config values).

**Docs.** New `docs/cli/config/{init,validate,show,schema,path,reload}.md` pages with a `.pages` nav entry, a canonical `docs/reference/configuration.md` page (precedence, discovery, schema, env scheme, secrets policy, `--dry-run` semantics, `version: 1` migration field) registered in `docs/reference/.pages`, `--config` and `--dry-run` rows added to `docs/cli/engine/daemon.md` and `docs/cli/engine/eval.md`, the top-level `docs/cli/index.md` updated to include the new `config` group in the quick-nav and command tree, and `docs/reference/environment-variables.md` rewritten to document the uniform `RSIGMA_<SECTION>__<KEY>` scheme alongside the legacy single-underscore names. Root README gains a Configuration section and the CLI README a `config` block under Subcommands.

### Pipeline-embedded `sources:` deprecation gets louder (#140, closes #136)

Phase 3 of the [detached-dynamic-sources](https://github.com/timescale/rsigma/issues/135) cycle. Pipeline files that declare an inline `sources:` block now print a `warning:` line on stderr in addition to the existing `tracing::warn!` event:

```
warning: pipeline '<name>' (<path>) declares an inline 'sources:' block, which is deprecated and will be removed in v1.0. Migrate with `rsigma rule migrate-sources -p <path> -o sources.yml` and load via `--source sources.yml` on `rsigma engine daemon`.
```

The structured warning is unchanged (now enriched with a `path` field), so log aggregators that already parse the message keep working. The emission moves out of `commands/daemon.rs` into a new public `rsigma_runtime::warn_pipeline_inline_sources` helper that two paths share:

- **CLI startup.** The CLI's `load_pipelines` (the entry point for `engine eval`, `engine daemon`, `rule validate`, `rule fields`, `backend convert`) and `pipeline resolve` both call the helper directly for every pipeline file loaded at startup.
- **Daemon hot-reload.** `RuntimeEngine::load_rules` -> `reload_pipelines` in `rsigma-runtime` now calls the helper too, so a SIGHUP, file-watcher event, or `POST /api/v1/reload` that re-reads a deprecated pipeline surfaces the warning even though the daemon's reload path does not go back through the CLI's `load_pipelines`. Library consumers that drive `RuntimeEngine` themselves inherit the same behaviour.

Canonical-path deduplication via a process-wide `OnceLock<Mutex<HashSet<PathBuf>>>` inside the helper keeps the daemon from re-spamming the same pipeline path on every reload tick once the warning has already fired for it.

**Doc and README sweep.** Every example for dynamic sources now declares them in a standalone YAML file loaded via `--source`. The pipeline-embedded form is documented only as a short "Deprecated" callout that points operators at `rsigma rule migrate-sources` and the v1.0 removal issue (#137). The reference page (`docs/reference/dynamic-sources.md`), the user guide (`docs/guide/processing-pipelines.md` and `docs/guide/enrichers.md`), the daemon CLI page (`docs/cli/engine/daemon.md`), the top-level README, the CLI README, and the runtime README all switch to the external-file form. The CLI README's recipe-catalog refresh values also switch from the unsupported `{ interval: ... }` mapping form to the literal-duration syntax (`1h`, `24h`) that the parser actually accepts.

**Deprecation timeline.** v0.13.0 (#135) introduced the `tracing::warn!`. This release adds the louder stderr warning, plumbs the warning through the daemon hot-reload path, and hides the deprecated form from docs. v1.0 (#137) turns it into a hard parse error and removes the `Pipeline.sources` field.

**Tests.** A new `cli_sources_deprecation.rs` integration suite pins the stderr emission across `rule validate`, `engine eval`, and `pipeline resolve`, plus the dedup invariant when the same pipeline is passed twice via `-p`, the negative case (pipelines without inline sources do not warn), and the migration-command suggestion (the warning embeds the actual pipeline path so the suggested `rsigma rule migrate-sources` invocation is copy-pasteable). Three new unit tests in `crates/rsigma-runtime/src/engine.rs` exercise the runtime path directly: a `RuntimeEngine::load_rules` call records the canonical pipeline path in the dedup set, a clean pipeline does not, and a hot-reload (second `load_rules` call) leaves the dedup set unchanged. Two more in `crates/rsigma-runtime/src/pipeline_deprecation.rs` cover the dedup primitive in isolation.

### Dependency bumps (#156)

Rolls up four open Dependabot PRs into a single merge. Rust: `serde_json` 1.0.149 to 1.0.150 and `tower-http` 0.6.10 to 0.6.11 in the workspace `Cargo.lock` (#154), with the same `serde_json` bump applied to `fuzz/Cargo.lock` alongside a resync of that stale lockfile to the current workspace state (the jaq 3.0 migration to `jaq-core` / `jaq-json` / `jaq-std` and the internal crate versions catching up from 0.11.0 to 0.13.0) (#153). CI: `taiki-e/install-action` 2.78.0 to 2.79.3, `docker/build-push-action` 7.1.0 to 7.2.0, `github/codeql-action` 4.35.4 to 4.35.5, and `zizmorcore/zizmor-action` 0.5.5 to 0.5.6, all repinned by commit SHA (#155). VS Code extension: the `tmp` dev dependency bumps 0.2.5 to 0.2.7, picking up the upstream security fix that rejects non-string and relative `prefix` / `postfix` / `template` values.

## [0.13.0] - 2026-05-26

**TL;DR**
RSigma v0.13.0 is the "post-evaluation enrichment, server-side TLS, and field observability" release:
* Post-evaluation enrichment between `engine.evaluate()` and the sinks: four primitives (`template`, `lookup`, `http`, `command`), strict detection-vs-correlation kind separation, scope filters, `on_error` policies, six new Prometheus metrics, and a public `register_builtin(name, factory)` registry.
* Server-side TLS on the daemon API listener (Axum REST + Prometheus + OTLP/HTTP + OTLP/gRPC sharing one socket via ALPN), gated by the new `daemon-tls` Cargo feature, with optional mutual TLS and cross-platform cert hot-reload via `POST /api/v1/reload`.
* Field observability: opt-in `--observe-fields` on `engine daemon` and `engine eval` exposes the gap and broken-coverage signals via four `/api/v1/fields/*` endpoints and three Prometheus surfaces, sharing a `RuleFieldSet` + `FieldCoverage` join primitive across CLI and daemon.
* Detached dynamic sources: declare sources in standalone YAML loaded via `--source <file_or_dir>`, with a unified `DaemonSourceRegistry` and a new `rsigma rule migrate-sources` helper. Pipeline-embedded `sources:` is visible-deprecated this release.
* Library API: `MatchResult` and `CorrelationResult` collapse into a single `EvaluationResult` (`RuleHeader` + `ResultBody`), wire shape preserved. Deprecated CLI aliases are now hidden from `rsigma --help`. The reserved-but-empty `attack` subcommand group is removed.
* Dependency bumps: jsonschema 0.46.5, jaq-core / jaq-std 1.x to 3.0 with jaq-json 2.0 (Radically Open Security audit fixes), assert_cmd 2.2.2, plus CI action bumps and two VS Code Dependabot security fixes (`@azure/msal-node` ^5.2.2, `brace-expansion` ^5.0.6).

### Unknown-field discovery API (#149)

The `engine daemon` learns to surface two halves of detection coverage live from inside the process: which event fields are not referenced by any loaded rule (gap signal) and which rule fields have never appeared in an event (broken-coverage signal). RSigma owns both rule parsing and event ingestion end-to-end, so this view does not need an external pipeline.

**Two new flags on `rsigma engine daemon`** (off by default; zero overhead when not set):

| Flag | Default | Purpose |
|------|---------|---------|
| `--observe-fields` | off | Enable the field observer. When enabled, every event evaluated by the engine task has its dotted field paths recorded. |
| `--observe-fields-max-keys <N>` | `10000` | Hard ceiling on distinct field names. Existing keys keep counting once the cap is hit; new keys are dropped and counted as overflow. |

**Four new HTTP endpoints.**

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/fields` | Snapshot bundling `summary` + `unknown` + `missing` for a one-shot dashboard read. |
| `GET` | `/api/v1/fields/unknown` | Event fields not referenced by any rule. Sorted by descending count. |
| `GET` | `/api/v1/fields/missing` | Rule fields never seen in events. Each entry includes up to 10 rule titles with a `truncated` flag for fields that span more rules. |
| `DELETE` | `/api/v1/fields/observer` | Clear the observer's counters and return `{previous_keys, previous_events}`. |

Each list endpoint accepts `?limit=N&offset=M` (default `limit=100`, cap `1000`) and returns `total` + `next_offset` for deterministic pagination. All four return `503 Service Unavailable` with `{"error":"field observation disabled","hint":"..."}` when `--observe-fields` is not set.

**Three new Prometheus surfaces.**

| Metric | Type | Description |
|--------|------|-------------|
| `rsigma_fields_observed_total` | counter | Total events scanned by the opt-in field observer. |
| `rsigma_fields_observer_unique_keys` | gauge | Distinct field names currently tracked. |
| `rsigma_fields_observer_overflow_dropped_total` | counter | New-key insert attempts dropped because the observer was at capacity. |

The gauges refresh on every `/metrics` scrape and after every successful `/api/v1/fields/*` call, so a Prometheus alert on `rsigma_fields_observer_overflow_dropped_total` fires the moment an operator's `--observe-fields-max-keys` choice is too low for the deployment.

**Shared extraction with `rsigma rule fields`.** The rule-field side of the join lives in a new `rsigma_eval::fields` module (`RuleFieldSet`) that both the CLI subcommand and the daemon import. The daemon caches the post-pipeline set on `RuntimeEngine` via `ArcSwap` and refreshes it on every successful `load_rules()`, so the HTTP handlers run lock-free against a stable view even during hot reloads.

**Shared join primitive.** `FieldObservation::coverage(&RuleFieldSet) -> FieldCoverage` lives in `rsigma-eval` and partitions an observation snapshot into the unknown / intersection / missing buckets in one pass. Both the daemon's HTTP handlers and the eval report consume this, so the partition semantics cannot drift across runtimes.

**Implementation cost.** Default-off; the engine task takes a single `ArcSwap` load per batch when no observer is attached and skips field iteration entirely. With `--observe-fields` set, the only added work is one `Event::field_keys()` walk per parsed event (one `String` allocation per leaf path, depth-capped at 64; flat formats like `KvEvent` return `Cow::Borrowed`) plus a short `std::sync::Mutex` lock to update counters. Memory is bounded by `--observe-fields-max-keys` (10k default ≈ a few hundred KB; keys stored as `Arc<str>` so snapshots refcount-bump rather than copy).

**Offline coverage report.** `rsigma engine eval` mirrors the daemon's field-observability surface with three new flags: `--observe-fields` enables observation; `--observe-fields-max-keys <N>` (default 10000, validated as `NonZeroUsize` so 0 is rejected at parse time); `--observe-fields-report <PATH>` writes the JSON report to a file (defaults to stderr if omitted so detections on stdout stay machine-consumable; clap-`requires` `--observe-fields` so the typo case fails fast). The report has the same shape as `GET /api/v1/fields`, so the same `jq` queries work against either runtime. To make this possible without coupling `engine eval` to the `daemon` Cargo feature, `FieldObserver` lives in `rsigma-eval` (which every consumer already links) and uses `std::sync::Mutex` to keep `rsigma-eval` dependency-light. `rsigma-runtime` keeps a `pub use rsigma_eval::{FieldObserver, FieldObservation, FieldObservationEntry, FieldCoverage}` re-export so existing imports continue to compile unchanged.

**Docs.** Endpoint reference under "Field observability" in `docs/reference/http-api.md`; flag rows in `docs/cli/engine/daemon.md` and `docs/cli/engine/eval.md`; metric rows in `docs/reference/metrics.md`; combined daemon/eval workflow in `docs/guide/observability.md`.

### Server-side TLS for the daemon API listener (#128)

The `engine daemon` API listener now terminates TLS in-process for every protocol that already shares `--api-addr`: the Axum HTTP REST API (`/healthz`, `/readyz`, `/metrics`, `/api/v1/*`), OTLP/HTTP on `POST /v1/logs`, and OTLP/gRPC via `LogsService/Export`. Operators can drop the sidecar reverse proxy they previously needed for confidentiality, integrity, and agent-to-daemon pinning.

**New Cargo feature.** `daemon-tls` on `rsigma-cli` gates the TLS surface and pulls in `rustls` (with the `aws-lc-rs` provider, matching the NATS client TLS path and inheriting upstream FIPS-mode work), `tokio-rustls`, `rustls-pemfile`, `rustls-pki-types`, `x509-parser`, and `hyper`/`hyper-util`. The default build is unchanged.

**Six new flags on `rsigma engine daemon`.**

| Flag | Env | Default | Purpose |
|------|-----|---------|---------|
| `--tls-cert <PATH>` | -- | -- | PEM-encoded leaf certificate (chain). Requires `--tls-key`. |
| `--tls-key <PATH>` | -- | -- | PEM-encoded private key (PKCS#8, PKCS#1, or SEC1). Requires `--tls-cert`. |
| `--tls-key-password <PASS>` | `RSIGMA_TLS_KEY_PASSWORD` | -- | Password for an encrypted `--tls-key`. Currently rejected with a clear hint pointing at `openssl rsa` for offline decryption; reserved for a future release. |
| `--tls-client-ca <PATH>` | -- | -- | PEM bundle of trusted CAs. Enables mutual TLS: clients without a CA-signed cert are rejected during the handshake. |
| `--tls-min-version <1.2\|1.3>` | -- | `1.3` | Minimum negotiated TLS protocol version. |
| `--allow-plaintext` | -- | off | Opt-in for plaintext on a non-loopback `--api-addr`. |

**Plaintext refusal policy.** When `daemon-tls` is built in, the daemon refuses to start on any non-loopback address unless either `--tls-cert`/`--tls-key` or `--allow-plaintext` is supplied. Loopback (`127.0.0.0/8`, `::1`) always allows plaintext to keep local development friction-free.

**Unified serving path.** The implementation collapses the previous split between `axum::serve` (for plaintext non-OTLP) and `tonic::transport::Server::serve_with_incoming_shutdown` (for OTLP) into a single `axum::Router` built via `tonic::service::Routes::into_axum_router`. For TLS, a small custom `axum::serve::Listener` wraps the `TcpListener` and performs the `tokio-rustls` handshake on every accepted connection. ALPN advertises both `h2` and `http/1.1`, so the same socket continues to serve REST + Prometheus + OTLP/HTTP + gRPC after TLS termination.

**Cross-platform cert hot-reload.** Cert rotation funnels through the daemon's central debounced reload task, which is triggered by `POST /api/v1/reload` (works on every platform, including Windows), `SIGHUP` (Unix), or a YAML change picked up by the file watcher. All three paths re-read the certificate and key from disk and atomically swap the active `rustls::ServerConfig` via `Arc<ArcSwap<…>>`. Inflight TLS connections are not dropped; failed reloads keep the previous certificate active, bump `rsigma_reloads_failed_total`, and log an error so a typo in the cert path cannot black-hole the listener. Encrypted-key support and ACME/Let's Encrypt automation are intentionally out of scope; operators rotate cert files (cert-manager, certbot, Vault PKI, ...) and trigger a reload.

**Two new Prometheus metrics.**

| Metric | Type | Description |
|--------|------|-------------|
| `rsigma_tls_certificate_expiry_seconds` | gauge | Seconds until the active TLS server certificate's `not_after`. Signed: negative once expired. Updated at startup and after every successful reload. |
| `rsigma_tls_active_connections` | gauge | Currently active TLS-terminated connections on the API listener. Decrements on connection close (including handshake failure). |

A single WARN is logged at startup (and after every successful reload) when the active cert expires within 30 days, so operators can plug the line into existing log-based alerting alongside the longer-horizon Prometheus alert on `rsigma_tls_certificate_expiry_seconds`.

**Docs.** Full reference under "TLS termination for the API listener" in `docs/reference/security.md`; flag table in `docs/cli/engine/daemon.md`; agent recipes (Grafana Alloy, Vector, Fluent Bit, OpenTelemetry Collector) with `tls`/mTLS blocks in `docs/guide/otlp-integration.md`; quick-start note in `docs/getting-started/quick-start.md`; new row in `docs/reference/feature-flags.md`; two new alerts in `docs/reference/metrics.md`.

### Deprecated CLI aliases hidden from `--help` (#125)

The 12 flat top-level CLI aliases (`eval`, `daemon`, `parse`, `validate`, `lint`, `fields`, `condition`, `stdin`, `convert`, `list-targets`, `list-formats`, `resolve`) introduced as visible-deprecated forwarders in v0.12.0 (PR #124) are now hidden from `rsigma --help` via `#[command(hide = true)]`. The dispatch arms and the `deprecation_warn` helper are otherwise unchanged, so:

- Every alias still runs successfully and still prints the migration warning on stderr.
- `rsigma <alias> --help` is still routable and renders the same flag list as the new grouped form, so scripts that introspect a subcommand keep working.
- `rsigma --help` now lists only the four noun-led groups (`engine`, `rule`, `backend`, `pipeline`) plus `help`.

The warning text was updated from "This alias will be hidden in the next release and removed in v1.0." to "This alias is hidden from `--help` and will be removed in v1.0." to reflect the new lifecycle stage. Removal at v1.0 is tracked in #126.

### Detached dynamic sources (#135)

Dynamic source declarations are decoupled from pipeline YAML files. Sources are now a first-class daemon-level concept declared in standalone YAML files and loaded via the new `--source <file_or_dir>` flag (repeatable). Both pipelines and enrichers reference sources by `source_id` as before; the daemon resolves them through a unified `DaemonSourceRegistry` that enforces collision-error semantics (same ID in two sites is a startup error with both paths in the message).

**Pipeline-embedded `sources:` is deprecated.** Existing pipeline files that declare `sources:` continue to work but emit a `tracing::warn!` at parse time recommending `--source` and `rsigma rule migrate-sources`. The deprecation runs over three releases: visible-deprecated this release, hidden from docs next release (#136), removed at v1.0 (#137).

**New subcommand.** `rsigma rule migrate-sources -p <pipeline-dir> -o <out>` extracts every pipeline-embedded `sources:` block into a standalone file, deduplicating by source ID with collision detection, and rewrites the pipeline files with the `sources:` block removed. Supports `--strategy single` (default, one consolidated file) and `--strategy per-pipeline`.

**CLI flag additions.** `--source-file` on `rsigma pipeline resolve` and `--source` on `rsigma rule validate --resolve-sources` so offline tooling can validate pipelines that reference external sources.

**API change.** `GET /api/v1/sources` now returns an `origin` field on each entry (`external:<path>` or `pipeline:<name>`) instead of the previous `pipeline` field.

### Post-evaluation enrichment (#134)

The daemon now runs a configurable enrichment pipeline between `engine.evaluate()` and the sinks. Each detection or correlation gets context (asset owner, IP reputation, identity, GeoIP, KEV flag, runbook URL, ...) injected into its `RuleHeader::enrichments` map before serialization, so every downstream consumer sees the same structured data without re-fetching it.

**New flag.** `rsigma engine daemon --enrichers <PATH>` points at a YAML file with `max_concurrent_enrichments: <N>` (default `16`) plus a list of enricher entries. The file is hot-reloaded on `SIGHUP`, file-watcher events, and `POST /api/v1/reload`; a reload that fails validation logs the error and keeps the previous pipeline active, so a typo never silently degrades production to "no enrichment".

**Four primitives.** Every entry declares a `type:` from a fixed set, modeled on what Splunk (`lookup` + `rest`), Cribl Stream (`Lookup` + `HTTP` + `Code` + `Eval`), and Vector (`enrichment_tables` + `remap`) all converged on:

| `type` | Surface |
|--------|---------|
| `template` | Pure string interpolation. No I/O. Used for runbook URLs and synthetic identifiers. |
| `lookup` | Reads a dynamic source (as declared today via pipeline `sources:`) from the existing `Arc<SourceCache>` by `source_id`, with an optional jq / JSONPath / CEL `extract` to slice the cached value and an optional `default` for cache miss or no extract match. Zero-network-cost. |
| `http` | Per-result `reqwest` request with template-expanded URL, headers, and optional body. Optional response cache keyed on `(method, url, body_hash)` with configurable TTL is mandatory in practice for any rate-limited API. |
| `command` | Per-result `tokio::process::Command` invocation with template-expanded argv and environment. Stdout capped at 10 MiB; output parsed as JSON (default) or raw string. |

The IRQL-style catalog (`enrich_ip_employee`, `enrich_ip_geoip`, `enrich_hash_virustotal`, `enrich_cve_kev`, `enrich_url_runbook`, `enrich_ip_passive_dns`) ships as field-parametric YAML recipes in `docs/guide/enrichers.md`, not Rust code. External crates that need a Rust-coded named enricher (bundled data, complex parser, stable contract, non-obvious algorithm) register one via the public `register_builtin(name, factory)` API.

**Strict kind separation.** Every enricher declares `kind: detection | correlation`. The kind drives two checks. At config load time, a `kind: detection` enricher may only reference `${detection.*}` template variables and a `kind: correlation` enricher may only reference `${correlation.*}`; cross-namespace references are rejected with a clear error pointing at the offending field. At runtime, the pipeline skips enrichers whose declared kind does not match the current `EvaluationResult` body variant before invoking `enrich()`, so a detection-kind enricher pays no cost on correlation results and vice versa. Available variables are documented in the Kind and template namespaces section of `docs/guide/enrichers.md`.

**`scope` filtering and `on_error` policies.** Within its declared kind, an enricher can be limited via `scope.rules` (rule ID or title glob), `scope.tags` (tag-set intersection with `prefix.*` wildcards), and `scope.levels` (severity membership). Axes are AND-ed; an empty axis is not a filter. On failure, `on_error` selects between `skip` (drop the enrichment, keep the result), `null` (inject `null`), and `drop` (drop the entire result). The default is `skip`, so an enrichment outage never silently swallows detections.

**Six new Prometheus metrics.** All six are pre-registered at startup, so every label triple renders with `# HELP` and `# TYPE` lines and zero counts on the first scrape, before any event has fired:

| Metric | Labels |
|--------|--------|
| `rsigma_enrichment_total` | `enricher_id`, `kind`, `status` (`success`/`skip`/`error`/`timeout`/`drop`) |
| `rsigma_enrichment_duration_seconds` | `enricher_id`, `kind` |
| `rsigma_enrichment_queue_depth` | -- |
| `rsigma_enrichment_http_cache_hits_total` | `enricher_id` |
| `rsigma_enrichment_http_cache_misses_total` | `enricher_id` |
| `rsigma_enrichment_http_cache_expirations_total` | `enricher_id` |

Filtered (kind- or scope-mismatched) enricher calls do not increment any counter, so cardinality stays bounded by the number of configured enrichers.

**Library API.** `rsigma-runtime` exports the `Enricher` async trait, `EnrichmentPipeline`, `EnricherKind`, `OnError`, `Scope`, the four primitive types (`TemplateEnricher`, `LookupEnricher`, `HttpEnricher`, `CommandEnricher`), `HttpEnricherClient`, `HttpResponseCache`, `OutputFormat`, the `MetricsHook` trait, and the `register_builtin(name, factory)` registry. Reserved names (`template`, `lookup`, `http`, `command`) are rejected at registration time; duplicate registrations of the same name are rejected to keep the registry append-only.

**Documentation.** New `docs/guide/enrichers.md` (config schema, the four primitives, recipes catalog, promotion criteria, output shape, metrics) and `docs/developers/adding-enrichers.md` (testing pattern, metrics wiring, naming conventions). `docs/cli/engine/daemon.md`, `docs/library/runtime.md`, and `docs/reference/metrics.md` updated. The `crates/rsigma-cli/README.md` gains a full enrichment surface section that mirrors the docs-site guide.

**New dependencies.** `humantime` and `arc-swap` in `rsigma-cli` (humantime for `5s` / `1h` duration parsing in the YAML; arc-swap for the hot-reload swap), `globset` and `jaq-core` / `jaq-std` / `jaq-json` in `rsigma-runtime` (globset for `scope.rules` / `scope.tags` patterns; the jaq additions wire the enrichment `extract` flow through jaq 3.0). `wiremock` added as a dev-dependency in both crates for HTTP enricher integration tests.

### Unified evaluation result type (#132)

`MatchResult` and `CorrelationResult` are collapsed into a single `EvaluationResult` via composition. The five fields shared between detection and correlation today (`rule_title`, `rule_id`, `level`, `tags`, `custom_attributes`) move into a new `RuleHeader` struct along with a new optional `enrichments` map. Kind-specific fields live in `DetectionBody` and `CorrelationBody`, behind a `#[serde(untagged)]` `ResultBody` enum.

**Wire shape preservation.** Both the header and the body flatten into the parent JSON object via `#[serde(flatten)]`, so each NDJSON line remains a single flat object: same field set, same values, same `skip_serializing_if` behavior. Downstream consumers continue to distinguish detection from correlation by presence of `correlation_type` (correlation-only). The one cosmetic change is key order on rules with a non-empty `custom_attributes` map: `custom_attributes` is now emitted between the rule header fields and the kind-specific body fields rather than after them. JSON objects are unordered per spec, so this is invisible to compliant consumers; the golden snapshot tests at `crates/rsigma-eval/tests/wire_shape_golden.rs` pin the new ordering for both kinds.

**Library API is breaking but pre-1.0.** The old `MatchResult`, `CorrelationResult`, and the struct shape of `ProcessResult { detections, correlations }` are replaced by:

- `EvaluationResult` (the single result type)
- `RuleHeader`, `DetectionBody`, `CorrelationBody`, `ResultBody` (the composable parts)
- `ProcessResult` (now a type alias for `Vec<EvaluationResult>`; detections come first, correlations after, in evaluation order)
- `ProcessResultExt` extension trait on `[EvaluationResult]` exposing `detections()` / `correlations()` iterators and `detection_count()` / `correlation_count()`

Migration on the consumer side:

| Before | After |
|--------|-------|
| `m.rule_title`, `m.tags`, etc. | `m.header.rule_title`, `m.header.tags`, ... |
| `m.matched_fields`, `m.event` | `m.as_detection().unwrap().matched_fields`, `m.as_detection().unwrap().event` |
| `m.correlation_type`, `m.group_key`, ... | `m.as_correlation().unwrap().correlation_type`, ... |
| `result.detections.len()` | `result.detection_count()` |
| `result.correlations.iter()` | `result.correlations()` |
| `result.detections[0]` | `result.detections().next().unwrap()` |

Internally, the three duplicated `for m in &result.detections / for m in &result.correlations` loops in the file, stdout, and NATS sinks collapse to one `for m in result` loop.

A new Criterion bench (`crates/rsigma-eval/benches/result_serialize.rs`) pins serialize throughput of the new design against a byte-for-byte copy of the old types across four representative inputs; the derived `#[serde(flatten)]` path is within ±4% of the baseline on every sample.

### Drop reserved `attack` subcommand

The empty `attack` command group that v0.12.0 reserved as a forward declaration for MITRE ATT&CK tooling is removed. The corresponding `Commands::Attack` clap variant, the `AttackCommands` enum, the dispatcher branch, the help-text test assertion, and the "reserved; populated by the upcoming MITRE ATT&CK contributor PR" README line are gone. The CLI now exposes four groups instead of five (`engine`, `rule`, `backend`, `pipeline`); the `attack` namespace remains available for a future contributor PR to populate but is no longer reserved ahead of time.

### Dependency and security bumps (#145)

Rolls up five open Dependabot PRs and closes two Dependabot security alerts. Rust: `jsonschema` 0.46.5, `assert_cmd` 2.2.2 (#141), and `jaq-core` / `jaq-std` 1.x to 3.0 with the new `jaq-json` 2.0 (#142, #143) -- the jaq 3.0 release ships the Radically Open Security audit fixes and a new `Loader` + `Compiler` + `Ctx` API that both `apply_jq` sites in `rsigma-runtime` and `rsigma-cli` are ported to; valid jq expressions in `extract:` and `--jq` are unaffected. CI: `cargo-deny-action` 2.0.18, `taiki-e/install-action` 2.78.0, `zizmor-action` 0.5.5 (#144). VS Code extension: top-level npm overrides bump `@azure/msal-node` to ^5.2.2 (drops the vulnerable `uuid` 8.x, closes [GHSA-w5hq-g745-h8pq](https://github.com/advisories/GHSA-w5hq-g745-h8pq), #138) and `brace-expansion` to ^5.0.6 (closes [CVE-2026-45149](https://nvd.nist.gov/vuln/detail/CVE-2026-45149)).

### Other changes

* **Documentation (PR #131):** version references no longer hardcode the current release in the docs site -- `rsigma.version` now reads from `Cargo.toml` at build time via the macros plugin, so the docs auto-bump on every release rather than drifting behind. `docs/guide/performance-tuning.md` gains a "Rule loading at scale" section covering the v0.12.0 single-rebuild batched loaders and amortized O(1) `add_rule` with verified Criterion numbers at 1K / 10K / 100K rules. The `rsigma-parser` README intro paragraph's stale lint count (65) was bumped to 66 to match every other authoritative location.
* **Enrichment wording:** the `lookup` enricher's startup error message and `docs/guide/enrichers.md` describe sources as "configured on the daemon" rather than "declared in your pipeline `sources:` block" so the copy stays accurate after a forthcoming release lets sources be declared independently of pipelines.
* **README and home page:** [Detection Engineering Weekly #157](https://www.detectionengineering.net/p/dew-157-shai-hulud-goes-open-source) added to the "featured in" list (`README.md` and `docs/index.md`) with a quote calling out RSigma's dynamic-pipelines model.
* **Contributing guidelines:** the `docs/` MkDocs site is now listed as a release deliverable in `CONTRIBUTING.md` alongside the crate READMEs, with a page-to-change matrix that maps each kind of change (new CLI flag, new daemon config key, new library API, new metric, new feature flag) to the page that must stay in sync.

[v0.12.0...v0.13.0](https://github.com/timescale/rsigma/compare/v0.12.0...v0.13.0)

## [0.12.0] - 2026-05-20

**TL;DR**
RSigma v0.12.0 is the "operability, performance, and documentation" release:
* Comprehensive daemon and CLI observability: tower-http API access logs, per-request OTLP tracing, batch processing spans, source resolution spans, DLQ visibility, NATS and sink lifecycle events, correlation state eviction warnings, rule load diagnostics, daemon lifecycle logs, and a global `--log-format` flag for non-daemon subcommands.
* Eval rule loading is no longer O(N²): `Engine::add_rule` is amortized O(1), and bulk loaders (`Engine::add_rules`, `extend_compiled_rules`, `add_collection`) rebuild indexes exactly once per batch. The full 3,120-rule SigmaHQ corpus that previously appeared to hang now loads in ~120 ms.
* CLI subcommands reorganized into five noun-led groups (`engine`, `rule`, `backend`, `pipeline`). Flat aliases continue to work as deprecated forwarders for one release.
* Full documentation site live at <https://timescale.github.io/rsigma/>: 47 pages spanning Getting Started, User Guide, CLI Reference, Library API, Developers, Reference (including a 66-rule lint catalogue and a 27-metric Prometheus catalogue), Deployment, Editors, and Ecosystem. Built from `docs/` on every merge to `main` via the new `.github/workflows/docs.yml`.
* Test reliability: `cli_daemon_http` and `cli_daemon_otlp` E2E suites are now flake-free on macOS under load.
* Dependency bumps: opentelemetry-proto 0.31.0 to 0.32.0, async-nats 0.47 to 0.48, yamlpath/yamlpatch 1.25.2 (with the `serde_yaml` cargo rename replaced by `yaml_serde` directly), tokio 1.52.3, jsonschema 0.46.4, tower-http 0.6.10, tonic 0.14.6.

### Daemon and CLI observability (PR #107)

The daemon and CLI ship with structured logs, distributed tracing spans, and profiling hooks across the three observability pillars. All new instrumentation flows through the existing `tracing-subscriber` (JSON, env-filter) and is controlled via `RUST_LOG`. Spans are designed to be consumable by future `tokio-console` or `tracing-opentelemetry` exporters without code changes.

**Phases.** One commit per phase, in landing order:

| Phase | Scope |
|-------|-------|
| HTTP API access logs | `tower-http::TraceLayer::new_for_http()` on the Axum router; each request produces a span with method, URI, status, and latency |
| Event pipeline | Per-batch debug span (`batch_size`, `input_format`, `match` count, `elapsed_ms`); DLQ parse-failure debug events; checked DLQ channel send with warn-on-closed; DLQ task lifecycle logging |
| Source resolution | `InstrumentedResolver` debug span (`source_id`, `source_type`); cache hit / fetch boundary events; refresh scheduler cycle completion logs (`sources`, `duration_ms`) |
| Correlation memory pressure | Warn on hard-cap eviction (current count, max, evicted, target capacity) so high-cardinality traffic causing data loss is no longer silent |
| NATS, sinks, backpressure | NATS source/sink publish and ack events; `spawn_source` backpressure warn alongside the existing metric; `Sink::FanOut` per-sink labels (`sink_index`, `sink_type`, error) |
| Rule load diagnostics | `load_rules` info span (`rules_path`, `duration_ms`); first three parse error details when bad rules fail to compile |
| OTLP per-request tracing | `otlp_ingest` debug span on both HTTP and gRPC handlers; `record_count` event after decoding `ExportLogsServiceRequest` |
| Daemon lifecycle | Health state transitions; file watcher errors; reload-channel coalesce vs closed events; periodic state snapshot duration and serialized size; SQLite migration column events; per-task shutdown-join logs |
| `--log-format` for CLI | Global `--log-format <json\|text>` initializes a stderr subscriber on non-daemon subcommands. `engine eval`, `rule validate`, and `rule lint` emit info events on completion (rules loaded, validation totals, lint summary) when a subscriber is installed. The daemon always logs JSON, so the flag is a no-op there. |

**Verbosity targets.**

| `RUST_LOG` filter | Surfaces |
|-------------------|----------|
| `info,tower_http=debug` | HTTP API access logs |
| `info,rsigma=debug` | Batch processing spans, DLQ routing, OTLP per-request fields, snapshot save duration |
| `info,rsigma_runtime::sources=debug` | Dynamic source resolution and refresh scheduler |
| `info,rsigma_eval=debug` | Correlation engine internals |

**Span correctness fix.** Holding an `EnteredSpan` guard from `Span::enter()` across `.await` is an anti-pattern on the multi-threaded tokio runtime: when the task is suspended, the thread-local span context can leak into other tasks scheduled on the same thread, producing incorrect span nesting. `InstrumentedResolver::resolve`, the OTLP HTTP and gRPC handlers, and the engine batch loop now use `.instrument()` on async blocks instead. Span fields, event payloads, and runtime behavior are unchanged.

**Documentation.** A new Observability section in the root README and an updated Logging paragraph in the CLI README list the supported `RUST_LOG` filter targets and document the new `--log-format` flag.

### Eval rule loading performance (PRs #119, #121, #122, #123)

Loading rules into an engine is no longer O(N²) in the rule count.

**Batched loaders rebuild indexes exactly once.** New `Engine::add_rules` (compiles each rule with the configured pipelines and collects per-rule compile errors without aborting the batch) and `Engine::extend_compiled_rules` (pre-compiled equivalent) rebuild the inverted index and per-field bloom exactly once at the end of the batch. `Engine::add_collection`, the `rsigma rule validate` path, and the `rsigma engine eval` rule load path now route through these APIs so the daemon and every `RuntimeEngine` caller share the one-rebuild fast path. Loading the SigmaHQ corpus (~3,120 rules) used to pay around 3K full index rebuilds and appeared to hang; it now completes in roughly 120 ms.

**Single-rule add path is amortized O(1).** `Engine::add_rule` and `Engine::add_compiled_rule` no longer rebuild the indexes from scratch on every push. They fold the new rule into the inverted index incrementally via the new `RuleIndex::append_rule(rule_idx, rule)` primitive, and into the per-field bloom via `FieldBloomIndex::append_rule(rule)`. The bloom uses a doubling watermark with a 64-rule floor to schedule full rebuilds when the rule count has at least doubled past the last rebuild, capping false-positive-rate drift while keeping the amortized per-rule cost O(1). Rules that introduce a brand-new indexed field get a fresh bloom on the fly.

| Rules   | `add_collection` | `add_rules` | `add_rule` loop |
|--------:|-----------------:|------------:|----------------:|
| 1,000   |          1.15 ms |     1.17 ms |         1.64 ms |
| 10,000  |         11.82 ms |    11.85 ms |        17.23 ms |
| 100,000 |        121.65 ms |   122.13 ms |       166.07 ms |

(M4 Pro, release build. Run via `cargo bench -p rsigma-eval --bench eval -- rule_load`.)

When `cross_rule_ac_enabled` is on, the daachorse cross-rule index has no incremental update story, so the single-rule add path falls back to a full `Engine::rebuild_index`. Bulk loaders are unaffected.

**Correctness.** Between bloom rebuilds, probes may answer `MaybeMatch` where the batched-rebuild path would answer `DefinitelyNoMatch`. Both verdicts are correct (`MaybeMatch` is always safe); the engine just evaluates the rule directly instead of short-circuiting. The new differential test `append_rule_matches_build_verdicts` pins this property by checking that positive verdicts match exactly and that disjoint haystacks are still rejected at >= 90% under incremental builds.

**Benchmarks.** A new `rule_load` Criterion group compares the three load entry points at 1K / 10K / 100K rules. Numbers recorded in `BENCHMARKS.md` under the Rule Load Paths (0.11.x) subsection.

### CLI command groups (PR #124)

The 12 flat top-level subcommands are reorganized into five noun-led command groups so the CLI scales as more subcommands arrive. The flat aliases continue to work for one release as visible-deprecated forwarders, are hidden in the next release, and are removed in v1.0. Every existing invocation keeps working, so there is no breaking change in this release.

```bash
$ rsigma
Parse, validate, and evaluate Sigma detection rules

Usage: rsigma [OPTIONS] <COMMAND>

Commands:
  engine        Run rules against events (eval / daemon)
  rule          Inspect and operate on Sigma rule files
  backend       Convert Sigma rules to backend-native queries
  pipeline      Pipeline tooling (resolve dynamic sources, …)
  attack        MITRE ATT&CK tooling (reserved; populated by the ATT&CK contributor PR)
  eval          [deprecated] Use `rsigma engine eval` instead
  daemon        [deprecated] Use `rsigma engine daemon` instead
  parse         [deprecated] Use `rsigma rule parse` instead
  validate      [deprecated] Use `rsigma rule validate` instead
  lint          [deprecated] Use `rsigma rule lint` instead
  fields        [deprecated] Use `rsigma rule fields` instead
  condition     [deprecated] Use `rsigma rule condition` instead
  stdin         [deprecated] Use `rsigma rule stdin` instead
  convert       [deprecated] Use `rsigma backend convert` instead
  list-targets  [deprecated] Use `rsigma backend targets` instead
  list-formats  [deprecated] Use `rsigma backend formats` instead
  resolve       [deprecated] Use `rsigma pipeline resolve` instead
  help          Print this message or the help of the given subcommand(s)

Options:
      --log-format <LOG_FORMAT>  Emit structured diagnostic logs to stderr (for CI / log aggregation) [possible values: json, text]
  -h, --help                     Print help (see more with '--help')
  -V, --version                  Print version
```

**Migration:**

| Old (flat) | New (grouped) |
|------------|---------------|
| `rsigma eval ...` | `rsigma engine eval ...` |
| `rsigma daemon ...` | `rsigma engine daemon ...` |
| `rsigma parse ...` | `rsigma rule parse ...` |
| `rsigma validate ...` | `rsigma rule validate ...` |
| `rsigma lint ...` | `rsigma rule lint ...` |
| `rsigma fields ...` | `rsigma rule fields ...` |
| `rsigma condition ...` | `rsigma rule condition ...` |
| `rsigma stdin ...` | `rsigma rule stdin ...` |
| `rsigma convert RULES ...` | `rsigma backend convert RULES ...` |
| `rsigma list-targets` | `rsigma backend targets` |
| `rsigma list-formats TARGET` | `rsigma backend formats TARGET` |
| `rsigma resolve ...` | `rsigma pipeline resolve ...` |

**What you'll see.** Invoking any flat alias prints one stderr line:

```
warning: `rsigma <old>` is deprecated; use `rsigma <new>` instead. This alias will be hidden in the next release and removed in v1.0.
```

stdout is unchanged. Exit codes are unchanged. Every flag accepted by the old form is accepted by the new form, with identical defaults and semantics.

**Why noun-led groups.** Every group is a noun (`engine`, `rule`, `backend`, `pipeline`), so command paths read as "rsigma's X tooling: do Y" rather than the awkward verb-on-verb chains a `run` or `convert` group would produce (`rsigma convert run RULES` vs the chosen `rsigma backend convert RULES`). The five groups are deliberately stable and small so future commands have an obvious home rather than landing as more top-level sprawl.

**Deprecation timeline.**

- **This release**: flat aliases visible in `rsigma --help` with a `[deprecated]` tag, stderr warning on invocation. Every test, script, and pipeline keeps working.
- **Next release** ([issue #125](https://github.com/timescale/rsigma/issues/125)): `#[command(hide = true)]` removes the aliases from `--help` but the invocations still work.
- **v1.0** ([issue #126](https://github.com/timescale/rsigma/issues/126)): flat aliases removed.

**Internal refactor.** The CLI dispatch layer is collapsed: each subcommand's clap arguments now live in `crates/rsigma-cli/src/commands/<name>.rs` as a `pub struct <Name>Args` deriving `clap::Args`, and the daemon's 35-field arg set + `cmd_daemon` body moved out of `main.rs` into a new `crates/rsigma-cli/src/commands/daemon.rs`. `main.rs` dropped from ~1360 lines to ~520 with no behavior change; the dispatch becomes a thin two-layer match (group -> leaf).

### Documentation site (PR #129)

A full documentation site now lives at <https://timescale.github.io/rsigma/>, built from `docs/` with [MkDocs Material](https://squidfunk.github.io/mkdocs-material/) and deployed by `.github/workflows/docs.yml`. 47 pages were written from scratch or migrated out of the README sprawl, structured so a detection engineer can get from "what is rsigma" to a running daemon in five minutes and to backend conversion or correlation in fifteen.

**Sections.**

| Section | Pages | What it covers |
|---------|-------|----------------|
| Getting Started | 3 | Installation (cargo, Docker, signed binary archives), quick-start (first eval, first daemon, first convert in five minutes), core concepts (Sigma primer, rule kinds, eval-vs-daemon, noun-led CLI). |
| User Guide | 11 | Evaluating rules, streaming detection, rule conversion, linting, processing pipelines (static + dynamic), input formats (incl EVTX), NATS streaming, OTLP integration with copy-paste recipes for Grafana Alloy / Vector / Fluent Bit / OTel Collector, CI/CD, performance tuning (matcher optimizer, bloom, cross-rule AC), observability (`--log-format`, `RUST_LOG` filter targets). |
| CLI Reference | 13 | One page per grouped subcommand (`engine eval`, `engine daemon`, `rule parse/validate/lint/fields/condition/stdin`, `backend convert/targets/formats`, `pipeline resolve`) plus an overview with the migration table from the deprecated flat aliases. |
| Library | 5 | Per-crate overviews of `rsigma-parser`, `rsigma-eval`, `rsigma-convert`, `rsigma-runtime`, each with a verified minimum working example and the public API surface that matters for embedders. |
| Developers | 6 | Orientation, testing (the five-tier CI shape), fuzzing (all 15 cargo-fuzz harnesses), walkthroughs for adding a new backend, adding a new input format, and adding a new lint rule (the linter and LSP). |
| Reference | 13 | 66-rule lint catalogue with worked examples for the trickier rules; PostgreSQL and LynxDB backend references; 27-metric Prometheus catalogue with verified labels; HTTP API; exit codes; environment variables; feature flags; custom attributes; builtin pipelines (`ecs_windows`, `sysmon`); dynamic-pipeline source spec; security hardening (input caps, resource limits, parser robustness, SQL injection prevention, network exposure, filesystem footprint, dependency policy); architecture diagram with the full crate map. |
| Deployment | 1 | Docker deployment with all hardening flags verified end-to-end against a `rsigma:local` build, including cosign signature verification and SLSA Build L3 attestation lookup via `gh attestation`. |
| Editors | 2 | VS Code / Cursor extension (wrapping `rsigma-lsp`); Neovim, Helix, Zed, Emacs `eglot`, and Sublime LSP wiring for the same server. |
| Ecosystem | 1 | Helr companion page with a full docker-compose stack pairing Helr's HTTP-API log collection with the rsigma daemon over NATS. |
| Top-level | 5 | Home (with a `Built with RSigma` section featuring [detection.studio](https://detection.studio/), a browser-based Sigma rule playground compiled from rsigma to WASM), Release Notes (mirrors this CHANGELOG), Contributing, Security Policy, Benchmarks (mirror of the root-level `BENCHMARKS.md`). |

**Verification.** Every documented CLI flag, exit code, metric label, HTTP endpoint, environment variable, feature flag, and Docker hardening flag was checked against the live binary or the workspace source rather than transcribed from memory. The Docker page was tested end-to-end against a local `rsigma:local` build from `main` (compose stacks, bind-mount permissions, `--state-db` persistence, signature verification with cosign, SLSA attestation lookup via `gh attestation`).

**CI.** `.github/workflows/docs.yml` has a `build` job that runs `mkdocs build --strict` on every PR touching `docs/`, `mkdocs.yml`, or `docs/requirements.txt`, and a `deploy` job that runs only on `main` and publishes via `actions/deploy-pages`. Every action is SHA-pinned with a version comment; top-level `permissions: {}` with least-privilege per-job overrides (`contents: read` for build, `pages: write` + `id-token: write` for deploy); `persist-credentials: false` on checkout; `concurrency` group with cancel-in-progress; `workflow_dispatch` for manual dry-runs. `zizmor --pedantic` reports zero findings.

**One-time setup.** GitHub Pages source must be set to "GitHub Actions" under `Settings -> Pages`. The first push to `main` after the v0.12.0 release does the first deploy; subsequent docs-only changes redeploy automatically.

**Deferred.** The Kubernetes deployment page is staged under `docs-drafts/` until the Helm Chart (#1a roadmap item) lands. The `attack` CLI subcommand group has a reserved enum but no docs yet; documentation will arrive with the MITRE ATT&CK contributor PR.

### Test reliability (PRs #115, #123)

The `cli_daemon_http` and `cli_daemon_otlp` E2E suites are no longer flaky on macOS under load. Three real issues caused intermittent `ConnectionRefused`:

1. The daemon's stdout was piped but never drained, so a chatty detection-match sink could fill the ~64 KiB pipe buffer and stall the daemon mid-write.
2. The spawn handshake stopped reading stderr after seeing "Sink started", so any subsequent log line could fill the stderr buffer too.
3. "Sink started" is emitted before `axum::serve` enters its accept loop; tests that fired requests immediately after the handshake sometimes hit the kernel before the listener was wired up.

The shared `DaemonProcess` helper (now in `tests/common/mod.rs`) drains stdout in a background thread, forwards interesting stderr lines to the main thread via `mpsc`, probes the actual TCP socket with `TcpStream::connect_timeout` before returning, and wraps the `Child` in a `ChildGuard` RAII type. Fixed `std::thread::sleep` waits in three OTLP tests and two HTTP tests are replaced with a `poll_until` helper that retries every 50 ms up to a 5 s deadline against the specific observable condition (metric labels present, status counters incremented). Each test now finishes in around 1.0 s, with the suite passing consistently across many consecutive macOS runs.

PR #123 also de-flaked an eval bloom test (`append_rule_matches_build_verdicts`) by replacing brittle three-needle assertions with a 1000-trigram aggregate sweep, since `BuildHasherDefault<ahash::AHasher>` uses a runtime-randomized seed by default and bit positions shift between process invocations.

### Other changes

* **Dependencies (PRs #111, #113, #114, #120):** opentelemetry-proto 0.31.0 -> 0.32.0 with handling for the new `StringValueStrindex` and `key_strindex` schema fields; async-nats 0.47 -> 0.48 (JetStream 2.14 features, panic fix); jsonschema 0.46.3 -> 0.46.4 (regex panic fix); tower-http 0.6.9 -> 0.6.10; tonic 0.14.5 -> 0.14.6; tokio 1.52.2 -> 1.52.3. yamlpath and yamlpatch bumped to 1.25.2, and the `serde_yaml` cargo rename was replaced with the real `yaml_serde` crate name across all six member manifests (~199 source references), so the manifest, source code, and compiler errors agree about which crate is in use.
* **GitHub Actions (PRs #111, #120):** taiki-e/install-action 2.75.28 -> 2.77.3, github/codeql-action 4.35.2 -> 4.35.4, sigstore/cosign-installer 4.1.1 -> 4.1.2.
* **Dependabot config (PR #114):** added a second cargo ecosystem entry pointed at `/fuzz` with the same weekly schedule and patch group as the root entry, so the fuzz workspace's lockfile no longer drifts and bleeds into unrelated PRs.
* **Architecture diagrams:** the ASCII diagram in `README.md` and the Mermaid diagram in `assets/architecture.mmd` were refreshed to reflect Dynamic Sigma Pipelines (v0.10.0), the matcher optimizer and prefilters (v0.11.0), DLQ as a sink target, broadened hot-reload over rules + pipelines, builtin pipelines (`ecs_windows`, `sysmon`), and the directory-style modules from the v0.9.0 modularization. A legend now explains feature-gated components (`*` for feature-gated and `**` for `daachorse-index`).
* **README:** install and build instructions corrected; eval prefilters mentioned in the prose; fifth blog article and BlackNoise newsletter mention added.

[v0.11.0...v0.12.0](https://github.com/timescale/rsigma/compare/v0.11.0...v0.12.0)

## [0.11.0] - 2026-05-14

**TL;DR**
RSigma v0.11.0 is the "eval performance" release:
* Matcher optimizer: batches `|contains` lists into Aho-Corasick automata, groups sibling regex matchers into RegexSet DFAs, and eliminates redundant `to_lowercase()` calls via shared case-folding groups.
* Opt-in bloom filter pre-filtering for substring matchers, skipping entire detection items when trigrams cannot match.
* Opt-in cross-rule Aho-Corasick prefilter via daachorse (behind the `daachorse-index` feature flag), pruning entire rules before evaluation with up to ~100x speedup on substring-heavy workloads.
* Security hardening for dynamic pipeline sources: 10 MB body/payload caps on HTTP, command stdout, and NATS; 30-second command execution timeout; 1-second refresh interval floor. Closes all v0.10.0 Known Limitations.
* Parser fix: the unsupported `|not` modifier is now rejected with guidance toward condition-level negation.
* Dependency bumps: criterion 0.5.1 to 0.8.2, jsonschema 0.42.2 to 0.46.3.

### Matcher optimizer (PRs #99, #100, #101, #105)

The compiler now includes an optimization pass that restructures `AnyOf` matcher trees for better runtime performance. The optimizer is always on and preserves evaluation semantics exactly. Three transformations are applied in order:

**Aho-Corasick batching.** When an `AnyOf` node contains 8 or more plain `|contains` children with the same case sensitivity, they are collapsed into a single Aho-Corasick automaton (`AhoCorasickSet`). Instead of N sequential substring scans, the engine makes one linear pass over the haystack. The threshold of 8 was chosen empirically from a benchmark sweep: below 8 patterns, sequential `str::contains` with SIMD acceleration (memchr / Two-Way) is faster; at 8 and above, throughput flattens because the AC automaton scans once regardless of pattern count.

| Patterns | h=100 B | h=1 KB | h=8 KB | h=64 KB |
|---------:|---------|--------|--------|---------|
| 1  | 13.0 Melem/s | 7.77 Melem/s | 1.85 Melem/s | 248 Kelem/s |
| 4  | 9.08 Melem/s | 2.03 Melem/s | 293 Kelem/s | 35.6 Kelem/s |
| **8**  | **5.17 Melem/s** | **620 Kelem/s** | **79.0 Kelem/s** | **9.76 Kelem/s** |
| 16 | 5.19 Melem/s | 628 Kelem/s | 78.6 Kelem/s | 9.67 Kelem/s |
| 32 | 4.99 Melem/s | 607 Kelem/s | 76.4 Kelem/s | 8.88 Kelem/s |

**RegexSet batching.** When an `AnyOf` node contains 3 or more `|re` children, they are collapsed into a single `RegexSet` DFA. One DFA pass replaces N independent regex evaluations. Falls back to individual matchers if set construction fails.

**Case-insensitive grouping.** After AC and RegexSet restructuring, if 2 or more surviving children are all case-insensitive and "pre-lowerable," they are wrapped in a `CaseInsensitiveGroup`. The haystack is lowered once via `ascii_lowercase_cow` (borrow-if-already-lower fast path), and all children use `matches_pre_lowered` against the shared lowered string, eliminating repeated allocation.

The optimizer only applies to `AnyOf` (OR) groups, never to `AllOf` (AND). This is a correctness constraint: collapsing AND-of-contains into AC with any-match semantics would change the logic.

**Correctness guarantee.** A new differential fuzz target (`fuzz_eval_matcher_diff`) asserts that `optimize_any_of(matchers)` produces identical match results to `AnyOf(matchers)` for arbitrary needle sets, haystacks, and case sensitivity.

### Bloom filter pre-filtering (PRs #102, #104)

An opt-in trigram-based bloom index that can skip expensive substring matching before it starts. The bloom filter operates at the detection-item level, inside `evaluate_rule`.

**How it works.** At rule load time, the engine extracts positive substring needles (`|contains`, `|startswith`, `|endswith`, and `AhoCorasickSet` needles) from all compiled rules and inserts every 3-byte trigram into a per-field bloom filter (double hashing from AHash-derived pairs). At eval time, for each string field value, the engine slides trigrams over the lowered haystack; if no trigram from any pattern is present in the bloom, the item returns `DefinitelyNoMatch` and the matcher is skipped entirely.

**One-sided correctness.** The bloom filter has no false negatives for "definitely no match." If it says `MaybeMatch`, the full matcher runs as usual. Negated branches, non-string fields, and short/huge values conservatively return `MaybeMatch`.

**Memory budget.** Default total budget is 1 MiB (`DEFAULT_MAX_TOTAL_BYTES`), with a 64 KiB per-field cap. If the total exceeds the budget, fields with the worst bits-per-pattern density are dropped first. The budget is configurable via `Engine::set_bloom_max_bytes`.

**CLI flags.**

```
rsigma eval -r rules/ -e @events.json --bloom-prefilter
rsigma eval -r rules/ -e @events.json --bloom-prefilter --bloom-max-bytes 131072

rsigma daemon -r rules/ --bloom-prefilter
rsigma daemon -r rules/ --bloom-prefilter --bloom-max-bytes 2097152
```

**When to enable.** The bloom index adds approximately 1 microsecond of per-event trigram probing overhead. It pays off when you have many substring-heavy rules and most events do not match (the common case for threat intel feeds against high-volume telemetry). Benchmark with your own data before enabling in production.

### Cross-rule Aho-Corasick prefilter (PR #106)

An opt-in whole-rule prefilter that prunes entire rules before `evaluate_rule` runs. This is distinct from the per-item matcher optimizer and the per-item bloom filter: it operates at the rule level.

**How it works.** At index build time, the engine collects all positive substring needles (lowered) from every rule and builds one `DoubleArrayAhoCorasick<u32>` automaton per field using the daachorse crate. Pattern IDs map back to rule indices. At eval time, for each indexed field with a string value, one overlapping scan on the lowered haystack marks which rules had at least one pattern hit. Rules that are "AC-prunable" (all detections consist exclusively of positive substring matchers, no negation in conditions, no field-less keywords) and received zero hits are skipped entirely.

**Benchmark results.** 200 non-matching events against N pure-substring rules (best-case workload):

| Rules  | Off (default)            | On (`--cross-rule-ac`)           | Speedup     |
|-------:|--------------------------|----------------------------------|-------------|
| 1,000  | 17.34 ms (11.5 Kelem/s)  | 253.0 us (790 Kelem/s)           | **~68x**    |
| 5,000  | 85.51 ms (2.34 Kelem/s)  | 883.0 us (226 Kelem/s)           | **~97x**    |
| 10,000 | 173.37 ms (1.15 Kelem/s) | 1.71 ms (117 Kelem/s)            | **~101x**   |

The cross-rule index turns O(rules x patterns) per event into O(haystack_length) for the AC scan, so throughput is essentially constant in rule count.

**Feature flag.** The daachorse dependency is optional and gated behind the `daachorse-index` Cargo feature. Build with:

```
cargo install rsigma --features daachorse-index
# or
cargo build --release --features daachorse-index
```

**CLI flags.**

```
rsigma eval -r rules/ -e @events.json --cross-rule-ac
rsigma daemon -r rules/ --cross-rule-ac
```

**When to enable.** This is off by default. For typical mixed workloads (substring + exact + regex rules, events that hit multiple fields, smaller rule sets), the index adds build-time and lookup overhead with smaller wins or none, and can cause a slowdown. Enable for large (5K+ rules), substring-heavy, shared-pattern packs where most events do not match. Always benchmark against representative data first.

**Composition.** The three prefilter layers stack: the rule index narrows by exact field values, the cross-rule AC narrows by substring patterns, and the bloom filter skips individual detection items. All three can be enabled simultaneously; regression tests assert that the combined output matches the no-prefilter baseline.

### Security hardening for dynamic pipeline sources (PR #96)

This release closes all four items listed under "Known Limitations" in the v0.10.0 release notes. Dynamic pipeline sources that fetch from HTTP, command, or NATS now enforce resource limits.

**HTTP response body size limit.** Responses are capped at 10 MB (`MAX_SOURCE_RESPONSE_BYTES`). If the server advertises a `Content-Length` exceeding the limit, the response is rejected without buffering the body. During streaming, if the accumulated body exceeds the limit, the connection is dropped. A 30-second client timeout is also enforced.

**Command execution timeout and stdout size limit.** Command sources are killed after 30 seconds (`DEFAULT_COMMAND_TIMEOUT`). Stdout is read in 8 KB chunks and capped at 10 MB; exceeding the limit kills the child process. Stderr is separately capped at 64 KB to prevent a chatty failing command from exhausting memory.

**NATS message payload size limit.** NATS messages exceeding 10 MB are rejected before parsing.

**Refresh interval floor.** Source refresh intervals below 1 second are clamped to 1 second with a structured warning log. This prevents config mistakes or hostile configs from causing tight polling loops.

All limits use a new `SourceErrorKind::ResourceLimit` variant with descriptive messages. Integration tests validate timeout killing, stdout size rejection, and NATS payload rejection.

### Parser: reject `|not` modifier (PR #103)

Writing `field|not: value` in a Sigma rule is a common mistake. The `not` keyword is a condition-level operator, not a value modifier. Previously this would produce a generic "unknown modifier" error. Now the parser returns a dedicated `NotIsNotAModifier` error with guidance:

> `not` is not a value modifier in Sigma; express negation in the condition (e.g. `not selection`) or move the inverted check into a separate detection used as a filter (e.g. `selection and not other`)

### Regression test suite (PRs #105, #106)

A new `regression_eval.rs` test file (459 lines) locks down optimizer and prefilter correctness with differential tests:

| Test | What it validates |
|------|-------------------|
| `baseline_contains_heavy_corpus` | Multi-rule contains-heavy corpus produces expected match sets |
| `allof_contains_semantics_preserved` | `\|contains\|all` requires all needles (not collapsed to AC with OR semantics) |
| `keyword_aho_corasick_path_correct` | Field-less `keywords:` block with enough terms to hit AC path |
| `bloom_prefilter_preserves_match_results` | Bloom on vs off produces identical results |
| `bloom_prefilter_handles_condition_negation` | `not other` with `\|contains` under bloom short-circuit |
| `optimizer_runs_after_pipeline_transformation` | Pipeline maps field names before optimizer runs |
| `cross_rule_ac_preserves_match_results` | Cross-rule AC on vs off produces identical results |
| `cross_rule_ac_handles_condition_negation` | `not other` with cross-rule AC |
| `cross_rule_ac_composes_with_bloom` | All three prefilters enabled together match the baseline |

### Benchmarks (PRs #105, #106)

Five new Criterion benchmark groups with dedicated data generators:

| Group | What it measures |
|-------|------------------|
| `eval_contains_heavy` | 1-200 `\|contains` patterns per rule, 1000 events |
| `eval_ac_threshold_sweep` | Pattern counts 1-32 across haystack lengths 100 B to 64 KB |
| `eval_regex_set_heavy` | 3-50 wildcard patterns per rule via RegexSet |
| `eval_bloom_rejection` | 100-5000 substring-only rules with guaranteed non-matching events, bloom on vs off |
| `eval_cross_rule_ac` | 1K-10K substring-only rules with non-matching events, cross-rule AC on vs off |

Results are recorded in `BENCHMARKS.md`.

### Other changes

* **Stale warning fix (PR #98):** replaced the Phase 1 placeholder warning for dynamic pipelines with the correct message now that the feature is complete.
* **Rustdoc (PR #106):** surfaced `Engine::set_bloom_prefilter`, `Engine::set_bloom_max_bytes`, `Engine::set_cross_rule_ac`, and `SigmaParserError::NotIsNotAModifier` in public documentation.
* **criterion migration (PR #95):** bumped criterion from 0.5.1 to 0.8.2; replaced deprecated `criterion::black_box` with `std::hint::black_box` across all benchmark files.
* **jsonschema bump (PR #94):** bumped jsonschema from 0.42.2 to 0.46.3.
* **VS Code extension (PR #97):** bumped fast-uri from 3.1.0 to 3.1.2 (Dependabot).
* **README link:** added link to the fourth blog article.

[v0.10.0...v0.11.0](https://github.com/timescale/rsigma/compare/v0.10.0...v0.11.0)

## [0.10.0] - 2026-05-08

**TL;DR**
RSigma v0.10.0 is the "dynamic pipelines" release:
* Dynamic Sigma Pipelines: declare HTTP, command, file, and NATS sources inside pipeline YAML, with template expansion, include directives, TTL caching, background refresh, and three extract languages (jq, JSONPath, CEL).
* A new `rsigma resolve` CLI command and full daemon integration with Prometheus instrumentation.
* Native EVTX input: evaluate Sigma rules directly against Windows Event Log binary files.
* Pipeline hot-reload: the daemon now watches pipeline files alongside rules.
* Builtin pipelines: `ecs_windows` and `sysmon` embedded at compile time.
* Comprehensive fuzz testing: 14 cargo-fuzz harnesses covering all untrusted input surfaces.
* Security hardening: SQL injection prevention, recursion limits, condition DoS caps, SIGTERM handler, and event size limits.
* CI and supply chain: MSRV enforcement, cargo-deny, serde_yaml migration, Dependabot, SECURITY.md, and CONTRIBUTING.md.

### Dynamic Sigma Pipelines (PRs #86-#93)

Pipelines can now declare external data sources that are resolved at runtime and injected into pipeline fields via template expansion. This is a capability unique to RSigma: no other Sigma engine supports dynamic processing pipelines.

**Four source types.** A new `sources` section in pipeline YAML declares named data sources:

```yaml
sources:
  threat_intel:
    type: http
    url: https://feeds.example.com/iocs.json
    format: json
    extract:
      expr: ".indicators[].value"
      type: jsonpath
    refresh:
      interval: 300
    on_error: use_cached
    required: false
```

| Source type | Description |
| --- | --- |
| `http` | Fetch from a URL (GET/POST) with optional headers |
| `command` | Execute a local command and capture stdout |
| `file` | Read from a local file path |
| `nats` | Subscribe to a NATS subject for push-based updates |

**Template expansion.** Pipeline field values reference resolved source data via `${source.threat_intel}` syntax. Templates are expanded after all sources resolve, before the pipeline is applied to rules.

**Three extract languages.** Source responses can be filtered before injection:

| Type | Engine | Example |
| --- | --- | --- |
| `jq` (default) | jaq | `.records[] \| .ip` |
| `jsonpath` | jsonpath-rust | `$.indicators[*].value` |
| `cel` | cel-interpreter | `data.filter(x, x.severity > 3)` |

**Include directives.** Pipelines can include other pipeline fragments via `include` sources, with a recursive depth limit of 1. Remote includes (HTTP, NATS) require the `--allow-remote-include` daemon flag.

**TTL-based caching.** Resolved source data is cached in SQLite with configurable TTL. A cache invalidation API allows on-demand refresh without waiting for expiry.

**Background refresh.** After startup, sources refresh on their configured interval in the background. Failures for non-required sources do not block the pipeline; the last cached value is used (configurable via `on_error: use_cached | fail | ignore`).

**SIGHUP re-resolution.** Sending SIGHUP to the daemon triggers both a rule reload and a full source re-resolution cycle.

**NATS control subject.** A NATS message on a configurable control subject triggers source re-resolution, enabling external orchestration of pipeline updates.

**`rsigma resolve` command (PR #88).** A new CLI subcommand resolves dynamic sources and prints results:

```
rsigma resolve -p pipelines/dynamic_threat_intel.yml
rsigma resolve -p pipelines/dynamic_threat_intel.yml -s threat_intel --pretty
rsigma resolve -p pipelines/dynamic_threat_intel.yml --dry-run
```

**`rsigma validate --resolve-sources` (PR #88).** Validate that pipeline sources can be resolved successfully alongside rule validation.

**Prometheus metrics (PR #88).** Five new metrics track source resolution in the daemon:

| Metric | Labels | Description |
| --- | --- | --- |
| `rsigma_source_resolves_total` | `source_id`, `source_type` | Total source resolution attempts |
| `rsigma_source_resolve_errors_total` | `source_id`, `error_kind` | Resolution errors by kind (Fetch, Parse, Extract, Timeout) |
| `rsigma_source_resolve_seconds` | | Resolution latency histogram |
| `rsigma_source_cache_hits_total` | | Cache hit counter |
| `rsigma_source_last_resolved_timestamp` | `source_id` | Unix timestamp of last successful resolution |

**`/api/v1/status` extension (PR #88).** The status endpoint now includes a `dynamic_sources` summary when sources are configured:

```json
{
  "status": "running",
  "dynamic_sources": {
    "total": 3,
    "resolves_total": 42,
    "errors_total": 1,
    "cache_hits": 38
  }
}
```

**Full test coverage.** Integration and E2E tests validate the entire dynamic pipeline lifecycle against real daemon instances (PR #90). Criterion benchmarks measure resolution throughput and template expansion overhead (PR #91). Seven dedicated fuzz targets cover source YAML parsing, template expansion, extract expressions, include parsing, and HTTP response handling (PR #92). SigmaHQ corpus regression validates that dynamic pipelines do not regress existing static pipeline behavior (PR #93).

### EVTX input adapter (PR #85)

RSigma can now evaluate Sigma rules directly against Windows Event Log binary files (`.evtx`). The adapter uses the `evtx` crate to parse the binary format and yield JSON records that feed directly into the detection engine.

```
rsigma eval -r rules/windows/ -e @Security.evtx
rsigma eval -r rules/ -p sysmon -e @Microsoft-Windows-Sysmon%4Operational.evtx
```

Auto-detection is extension-based: any `@path` argument ending in `.evtx` (case-insensitive) is routed through the EVTX parser. The feature is compile-time gated behind the `evtx` feature flag (included in default features).

### Pipeline hot-reload (PR #68)

The daemon file watcher now monitors pipeline YAML files alongside the rules directory. Changes to any referenced pipeline file trigger the same debounced reload cycle as rule changes:

1. **Filesystem events** on watched `.yml`/`.yaml` files (500 ms debounce)
2. **SIGHUP** signal (Unix)
3. **`POST /api/v1/reload`** endpoint

If a pipeline file fails to parse during reload, the old engine configuration is preserved and `rsigma_reloads_failed_total` is incremented.

Builtin pipelines (`ecs_windows`, `sysmon`) are embedded at compile time and excluded from the file watcher.

### Bundled pipelines (PR #69)

Two processing pipelines are now embedded in the binary via `include_str!()`:

| Name | Description |
| --- | --- |
| `ecs_windows` | Sigma/Sysmon field names to Elastic Common Schema (process creation, network, file, registry, DNS, pipe, driver, remote thread, process access) |
| `sysmon` | Adds EventID conditions for logsource-to-Sysmon-event routing |

Reference them by name instead of a file path:

```
rsigma eval -r rules/ -p ecs_windows -e @events.json
rsigma daemon -r rules/ -p sysmon
rsigma convert -r rules/ -t postgres -p ecs_windows
```

### Fuzz testing (PR #70, PR #92)

Fourteen cargo-fuzz harnesses now cover every untrusted input surface:

| Target | Surface |
| --- | --- |
| `fuzz_parse_yaml` | Sigma YAML parser |
| `fuzz_condition` | Condition expression parser |
| `fuzz_field_modifiers` | Field modifier parsing |
| `fuzz_eval_matching` | Event evaluation engine |
| `fuzz_regex_compile` | Regex pattern compilation |
| `fuzz_pipeline_yaml` | Pipeline YAML parsing |
| `fuzz_input_formats` | Input format auto-detection (JSON, syslog, logfmt, CEF) |
| `fuzz_pipeline_sources_yaml` | Dynamic source YAML parsing |
| `fuzz_extract_jq` | jq extract expression evaluation |
| `fuzz_extract_jsonpath` | JSONPath extract expression evaluation |
| `fuzz_extract_cel` | CEL extract expression evaluation |
| `fuzz_template_expand` | Template `${source.*}` expansion |
| `fuzz_include_parse` | Include directive parsing |
| `fuzz_http_response` | HTTP response body handling |

Seed corpora include real SigmaHQ rules, handcrafted adversarial inputs, and valid pipeline examples. A weekly scheduled CI job runs all targets with per-target `--max_len` limits. Crashes upload as artifacts.

### Security hardening (PRs #71-#76)

Six PRs address security, robustness, and code quality:

**SQL injection prevention (PR #71).** The PostgreSQL backend now validates all identifiers (table, schema, field segments) against `^[A-Za-z_][A-Za-z0-9_$]*$` before embedding them in SQL. Malicious inputs are rejected with `ConvertError::InvalidIdentifier` instead of being interpolated.

**Unbounded recursion limits (PR #71).** YAML deep-merge is capped at 64 levels (`MAX_DEPTH`). Exceeding the limit returns `SigmaParserError::MergeTooDeep`.

**Condition DoS caps (PR #71).** Condition expressions are limited to 64 KiB (`MAX_CONDITION_LEN`) and 64 nesting levels (`MAX_CONDITION_DEPTH`). Both limits return descriptive parse errors instead of stack overflow.

**SIGTERM handler (PR #74).** The daemon now handles `SIGTERM` with the same graceful shutdown path as `Ctrl+C`: drain the pipeline within `--drain-timeout`, persist correlation state, and exit cleanly.

**parking_lot mutexes (PR #74).** Internal mutexes migrated from `std::sync::Mutex` to `parking_lot::Mutex` for fairer scheduling and no poisoning.

**Event size cap (PR #74).** HTTP ingestion rejects individual lines exceeding 1 MiB with `413 Payload Too Large`.

**Code quality (PR #75).** `KEY_CACHE` completeness test ensures all modifier keys are cached. `partial_cmp` replaced with `total_cmp` for deterministic float comparisons.

**Testing gaps (PR #76).** Runtime integration tests and parser AST snapshot tests added to cover previously untested paths.

### CI and supply chain (PRs #72-#73)

**MSRV enforcement.** A dedicated CI job runs `cargo check --workspace --all-features --locked` on the declared MSRV (1.88.0).

**cargo-deny.** Advisory database checking and license scanning via `cargo-deny` in CI. Known advisory `RUSTSEC-2021-0153` (evtx transitive dep on `encoding`) is documented and allow-listed.

**serde_yaml migration.** All crates migrated from the unmaintained `serde_yaml` to `yaml_serde` 0.10.4 via Cargo package renaming, with zero source-level changes required.

**Dependabot (PR #84).** Automated dependency updates enabled; all flagged dependencies bumped in a single batch.

**SECURITY.md and CONTRIBUTING.md (PR #73).** Security disclosure policy and contribution guidelines added to the repository root.

### Other changes

* **`--dry-run` for `rsigma resolve`**: inspect source metadata (type, refresh policy, required flag) without performing actual resolution.
* **Cross-platform command source tests**: Windows-compatible assertions for command-type dynamic sources.
* **MSRV 1.88.0 type inference fix**: explicit type annotations for `prometheus` `with_label_values` calls to satisfy the minimum supported Rust version.
* **CI: removed semver-checks job**: semver compatibility checking removed from the CI pipeline (was producing false positives on internal API changes).
* **Benchmark documentation**: full Criterion benchmark results recorded across all crates.
* **README updates**: dynamic pipelines documented across root, rsigma-cli, and rsigma-runtime READMEs.

### Known Limitations

Dynamic pipeline sources that fetch from HTTP, NATS, or command execution do not yet enforce resource limits on response size, execution timeout, or refresh interval. Specifically:
- HTTP responses are read to completion without a body size cap
- Command sources inherit the daemon process timeout but lack a per-source timeout enforcement
- NATS push sources do not cap payload size
- No minimum floor on refresh interval (a very short interval could cause excessive load)

These hardening items are tracked as a roadmap item and will either ship in v0.10.1 or in v0.11.0. The feature is opt-in (sources must be explicitly declared in pipeline YAML by the operator), and the critical injection/recursion/DoS vectors are already addressed in this release.

[v0.9.0...v0.10.0](https://github.com/timescale/rsigma/compare/v0.9.0...v0.10.0)

## [0.9.0] - 2026-05-04

**TL;DR**
RSigma v0.9.0 is one of the largest releases yet:
* Production-grade NATS JetStream with at-least-once delivery, authentication and TLS, dead-letter queues, replay from offset or timestamp, consumer groups, and sequence-aware correlation state restoration
* Native OpenTelemetry log ingestion over HTTP (protobuf + JSON) and gRPC
* A new LynxDB conversion backend for SPL2-compatible queries
* The `rsigma fields` field catalog
* Structured exit codes for CI/CD scripting
* Per-rule Prometheus metric labels
* The entire codebase restructured into directory-based modules
* And a comprehensive E2E test suite validating every I/O path against real Postgres and NATS instances via testcontainers

### NATS production hardening (PR #59)

Five features bring the NATS pipeline from development-grade to production-ready.

**At-least-once delivery with deferred ack.** The streaming pipeline has been refactored from at-most-once to at-least-once delivery. Messages are now held in an `AckToken` until the sink confirms delivery. A new `RawEvent` struct bundles each payload with its ack token, and a dedicated ack task resolves tokens after sink confirmation. If the daemon crashes before ack, NATS redelivers the message after `ack_wait` expires. The `EventSource` trait now returns `Option<RawEvent>` instead of `Option<String>`, and `NatsSink` has been upgraded from core NATS publish to JetStream publish with server-confirmed persistence.

**Authentication and TLS.** A new `NatsConnectConfig` struct supports credentials file, token, username/password, NKey, mutual TLS (client cert + key), and require-TLS. Auth methods are mutually exclusive; the first configured one wins. Sensitive values can also be read from environment variables.

| CLI flag | Environment variable | Description |
| --- | --- | --- |
| `--nats-creds` | `NATS_CREDS` | Credentials file path |
| `--nats-token` | `NATS_TOKEN` | Authentication token |
| `--nats-user` / `--nats-password` | `NATS_USER` / `NATS_PASSWORD` | Username and password |
| `--nats-nkey` | `NATS_NKEY` | NKey seed |
| `--nats-tls-cert` / `--nats-tls-key` | | Client certificate and key for mutual TLS |
| `--nats-require-tls` | | Require TLS on the connection |

**Dead-letter queue.** Events that fail processing are routed to a configurable DLQ instead of being silently discarded. The `--dlq` flag accepts the same URL schemes as `--output` (`stdout://`, `file://`, `nats://`). Each DLQ entry is a JSON object containing `original_event`, `error`, and `timestamp`. Integration points: parse errors detected before engine processing and sink delivery failures. A new `rsigma_dlq_events_total` Prometheus counter tracks DLQ volume.

```
rsigma daemon -r rules/ --input nats://localhost:4222/events.> --dlq file:///var/log/rsigma-dlq.ndjson
rsigma daemon -r rules/ --input nats://localhost:4222/events.> --dlq nats://localhost:4222/dlq.rsigma
```

**Replay from offset or timestamp.** A `ReplayPolicy` enum (`Resume`, `FromSequence`, `FromTime`, `Latest`) controls the JetStream consumer's starting position. Three mutually exclusive CLI flags set the policy. Correlation state restoration is handled intelligently based on the replay direction (see "Smart correlation state restoration" below).

```
rsigma daemon -r rules/ --input nats://localhost:4222/events.> --replay-from-sequence 42
rsigma daemon -r rules/ --input nats://localhost:4222/events.> --replay-from-time 2026-04-30T00:00:00Z
rsigma daemon -r rules/ --input nats://localhost:4222/events.> --replay-from-latest
```

**Consumer groups for horizontal scaling.** The `--consumer-group` flag sets a shared durable consumer name across multiple daemon instances. All instances using the same group name pull from a single JetStream consumer, and NATS automatically distributes messages for load balancing. When not specified, the consumer name is auto-derived from the subject (existing behavior).

```
rsigma daemon -r rules/ --input nats://localhost:4222/events.> --consumer-group detection-workers
```

### Smart correlation state restoration (PR #61)

The daemon now makes intelligent decisions about whether to restore correlation state from SQLite when restarting with a replay flag. Previously, any non-`Resume` replay policy unconditionally cleared correlation state to avoid double-counting. This was correct for forensic replay but overly conservative for forward catch-up scenarios where the daemon shuts down and restarts with `--replay-from-sequence` pointing after the last processed event.

**Sequence-aware auto-restore.** The daemon now tracks the NATS JetStream stream sequence and published timestamp of the last acknowledged message. This `SourcePosition` is stored alongside the correlation snapshot in SQLite (two new columns added via automatic schema migration). On restart, the `decide_state_restore` function compares the replay start point against the stored position: if the replay starts after the stored position (forward catch-up), state is restored safely; if at or before (backward replay), state is cleared to prevent double-counting.

**Explicit overrides.** Two new mutually exclusive CLI flags give operators direct control when the automatic decision is not appropriate:

| Flag | Behavior |
| --- | --- |
| `--keep-state` | Always restore correlation state, regardless of replay policy |
| `--clear-state` | Always clear correlation state and start fresh |
| _(neither)_ | Automatic decision based on replay direction and stored position |

```
rsigma daemon -r rules/ --input nats://localhost:4222/events.> --replay-from-sequence 1001 --state-db state.db
rsigma daemon -r rules/ --input nats://localhost:4222/events.> --replay-from-sequence 1 --state-db state.db
rsigma daemon -r rules/ --input nats://localhost:4222/events.> --replay-from-sequence 1 --state-db state.db --keep-state
```

**Timestamp fallback control.** A new `--timestamp-fallback` flag (`wallclock` or `skip`) controls how correlation windows handle events without parseable timestamp fields. The default `wallclock` substitutes the current time (existing behavior). The new `skip` mode causes detections to still fire but omits the event from correlation state updates, preventing wall-clock times from corrupting temporal windows during forensic replay of historical logs.

```
rsigma daemon -r rules/ --input nats://localhost:4222/events.> --timestamp-fallback skip
```

**Automatic schema migration.** Existing SQLite state databases are transparently migrated on first open. The migration adds the `source_sequence` and `source_timestamp` columns without losing the existing correlation snapshot.

### Codebase modularization (PRs #46-#58)

Thirteen PRs systematically split 12 large single-file modules into directory-based module structures across all six crates, improving navigability and reducing merge conflicts. The refactoring is purely structural with no behavioral changes.

| PR | File | Result |
| --- | --- | --- |
| #46 | `lint.rs` (4,991 lines) | `lint/{mod,rules/{metadata,detection,correlation,filter,shared}}.rs` |
| #47 | `main.rs` (2,221 lines) | `commands/{parse,validate,lint,eval,convert}.rs` |
| #48 | `postgres.rs` (3,183 lines) | `postgres/{mod,correlation,tests}.rs` |
| #49 | `correlation_engine.rs` (4,395 lines) | `correlation_engine/{mod,types,tests}.rs` |
| #50 | `transformations.rs` (3,379 lines) | `pipeline/transformations/{mod,helpers,tests}.rs` |
| #51 | `parser.rs` (2,276 lines) | `parser/{mod,detection,correlation,filter,tests}.rs` |
| #52 | `pipeline/mod.rs` (2,235 lines) | `pipeline/{mod,parsing}.rs` |
| #53 | `compiler.rs` (1,824 lines) | `compiler/{mod,helpers,tests}.rs` |
| #54 | `correlation.rs` (1,781 lines) | `correlation/{mod,types,buffers,compiler,keys,window,tests}.rs` |
| #55 | `engine.rs` (1,656 lines) | `engine/{mod,filters,tests}.rs` |
| #56 | `matcher.rs` (1,118 lines) | `matcher/{mod,matching,helpers}.rs` |
| #57 | `event.rs` (758 lines) | `event/{mod,json,kv,plain,map}.rs` |
| #58 | `cli/tests/cli.rs` (1,745 lines) | `tests/{cli_parse,cli_validate,cli_lint,cli_eval,cli_daemon,common/mod}.rs` |

Additional cleanup: `is_valid_uuid` was de-duplicated across lint rule modules, and pipeline parsing logic was extracted from `mod.rs` into its own submodule.

### E2E test suite (PR #60)

A comprehensive end-to-end test suite validates every major I/O path against real infrastructure. All container-based tests use testcontainers and are automatically skipped when Docker is unavailable.

**PostgreSQL integration tests.** Convert Sigma rules to SQL and execute the generated queries against a real PostgreSQL instance. Uses the Okta cross-tenant impersonation scenario with JSONB schema, 6 sample events, and 4 SigmaHQ detection rules. Tests cover default format, `VIEW` creation, multi-rule conversion, `event_count` correlation, and the no-match case.

**NATS E2E tests (binary-level).** Spawn the `rsigma` daemon as a child process with `--input`/`--output` NATS URLs pointed at a testcontainers NATS instance. Four tests cover single detection, no-match silence, `event_count` correlation, and fan-out to multiple output subjects.

**NATS E2E tests (library-level).** Additional integration tests in `rsigma-runtime` covering JetStream publish/subscribe, detection routing, and the article scenarios from the companion blog series.

**HTTP daemon E2E tests.** Spawn the daemon with `--input http` and `--api-addr 127.0.0.1:0`, discover the ephemeral port from structured log output, and exercise all REST endpoints: `healthz`, `readyz`, `metrics`, `rules`, `status`, `reload`, and `POST /api/v1/events` with single and batch NDJSON payloads.

**Input format tests.** CLI-level tests for syslog, plain text, and auto-detect input formats on both the `daemon` and `eval` commands.

**Snapshot-based convert tests.** Integration tests for the `convert` subcommand that compare CLI output against expected snapshots.

The state restore feature adds 10 additional E2E tests (6 HTTP-based, 4 NATS-based with testcontainers) covering `--clear-state`, `--keep-state`, `--timestamp-fallback`, schema migration, and sequence-aware forward/backward replay.

In total, roughly 4,700 lines of integration tests across 10 new test files, plus 850 lines of NATS-specific tests in `rsigma-runtime`.

### OTLP log ingestion (PR #64)

Native OpenTelemetry Protocol (OTLP) log receiver for the daemon. Three transports feed into a shared conversion layer that flattens each OTLP `LogRecord` (merged with parent Resource and InstrumentationScope attributes) into a JSON event and routes it through the detection engine.

**OTLP/HTTP.** `POST /v1/logs` accepts both protobuf (`application/x-protobuf`) and JSON (`application/json`) encoding. When `Content-Encoding: gzip` is present, the body is decompressed before decoding. Protobuf is assumed when no `Content-Type` is provided, matching the OTLP/HTTP specification default.

**OTLP/gRPC.** `LogsService/Export` is registered via tonic and multiplexed with the existing Axum REST endpoints on the same `--api-addr` port using `accept_http1(true)`, so HTTP/1.1 REST clients and HTTP/2 gRPC clients share a single listener.

**Prometheus metrics.** Three new counters track OTLP traffic:

| Metric | Labels | Description |
| --- | --- | --- |
| `rsigma_otlp_requests_total` | `transport`, `encoding` | OTLP export requests received |
| `rsigma_otlp_log_records_total` | | Log records ingested via OTLP |
| `rsigma_otlp_errors_total` | `transport`, `reason` | OTLP request errors |

**Feature gating.** OTLP is compile-time gated behind the `daemon-otlp` feature flag (not in default features). Build with `cargo build --features daemon-otlp`. When enabled, OTLP endpoints are always active alongside any `--input` mode.

```
rsigma daemon -r rules/ --input http --api-addr 0.0.0.0:9090
```

Tests: 9 integration tests covering HTTP protobuf, JSON, gzip, error cases (415 unsupported content type, 400 malformed payload), end-to-end detection triggering, and metrics exposure. 7 unit tests for the LogRecord-to-JSON conversion.

### LynxDB backend (PR #62)

A new conversion backend for LynxDB, a Go-based log analytics engine with an SPL2-compatible query language. Translates Sigma detection rules into `FROM <index> | search <predicates>` queries with deferred `| where` clauses for features that require regex or CIDR evaluation.

| Sigma feature | LynxDB syntax |
| --- | --- |
| Field equality | `field=value`, `field="quoted value"` |
| Wildcard (`*`) | `field=prefix*`, `field=*contains*` |
| Wildcard (`?`) | Deferred: `\| where field =~ "regex"` |
| Regex (`\|re`) | Deferred: `\| where field =~ "pattern"` |
| CIDR (`\|cidr`) | Deferred: `\| where cidrmatch("cidr", field)` |
| Case-sensitive (`\|cased`) | `field=CASE(value)` |
| Boolean AND/OR/NOT | Explicit parenthesization for LynxDB's non-standard precedence (NOT > OR > AND) |
| IN-list | `field IN (val1, val2, ...)` |
| Keyword search | Bare value (matches `_raw`) |

Two output formats: `default` (`FROM main | search ...`) and `minimal` (search expression only, for API `q` parameters). Index selection from pipeline state, defaulting to `main`.

```
rsigma convert rules/suspicious_process.yml -t lynxdb
rsigma convert rules/ -t lynxdb -f minimal
```

Tests: 30+ unit tests and 9 golden test cases.

### `rsigma fields` subcommand (PR #65)

A new subcommand that extracts and lists every field name referenced by a set of Sigma rules. Useful for understanding field coverage, validating pipeline mappings, and auditing detection scope.

Field sources: detection item keys, correlation `group_by` and `condition` fields, correlation alias mapping values, filter detections, and rule `fields:` metadata. Each field is annotated with the source categories that reference it (`detection`, `correlation`, `filter`, `metadata`).

| Flag | Description |
| --- | --- |
| `-r` / `--rules` | Path to a rule file or directory (required) |
| `-p` / `--pipeline` | Pipeline YAML file(s) to apply; shows post-mapping field names |
| `--no-filters` | Exclude fields contributed by filter rules |
| `--json` | Output as JSON with summary stats and pipeline mapping details |

```
rsigma fields -r rules/
rsigma fields -r rules/ -p pipelines/ecs.yml --json
```

Table output sends data to stdout and stats to stderr, enabling clean piping. 16 integration tests with insta inline snapshots.

### Structured exit codes (PR #66)

All subcommands now return categorized exit codes instead of a blanket `exit(1)` on any failure, enabling reliable CI/CD scripting with `$?`.

| Exit code | Constant | Meaning |
| --- | --- | --- |
| 0 | `SUCCESS` | Operation completed successfully |
| 1 | `FINDINGS` | Detections fired (`eval`) or lint findings above threshold (`lint`) |
| 2 | `RULE_ERROR` | Rule syntax, parse, or compilation error |
| 3 | `CONFIG_ERROR` | Pipeline, configuration, or invalid argument error |

Two new flags control when a non-zero exit indicates "findings found":

- `eval --fail-on-detection`: exit 1 when any detection or correlation fires.
- `lint --fail-level <error|warning|info>`: configurable severity threshold; default `error` preserves backward compatibility.

```
rsigma eval -r rules/ events.json --fail-on-detection || exit 1
rsigma lint -r rules/ --fail-level warning
```

### Per-rule Prometheus metrics (PR #63)

Two new labeled `IntCounterVec` metrics alongside the existing aggregate counters enable per-rule alerting and dashboarding without parsing log output.

| Metric | Labels |
| --- | --- |
| `rsigma_detection_matches_by_rule_total` | `rule_title`, `level` |
| `rsigma_correlation_matches_by_rule_total` | `rule_title`, `level`, `correlation_type` |

```promql
rate(rsigma_detection_matches_by_rule_total{rule_title="Okta Cross-Tenant Impersonation"}[5m]) > 100
```

### Other changes

* **Daemon hang fix**: when the `daemon-otlp` feature was enabled with stdin or NATS input, the daemon could hang after the source completed because OTLP handler clones kept the event channel open. Fixed by signaling source completion via `tokio::sync::Notify` and draining the channel with `select!`.
* **CI hardening (PR #67 + follow-ups)**: added `cargo-llvm-cov` code coverage with native GitHub job summary report, `zizmor` workflow audit with pedantic persona and SARIF upload, concurrency groups on all workflows, and action pin fixes (`dtolnay/rust-toolchain` pinned to `v1` tag, `Swatinem/rust-cache` pinned to dereferenced commit SHA). Codecov was initially added and then replaced with the native job summary to eliminate the external service dependency.
* **README rewrite**: new Supported Features section, updated architecture diagrams, OTLP log ingestion documentation, and shield badges.
* **Test reliability**: fixed a flaky macOS test where FSEvents file watcher backpressure filled the bounded reload channel, causing a 429 on the reload endpoint. The test now retries with backoff.

[v0.8.1...v0.9.0](https://github.com/timescale/rsigma/compare/v0.8.1...v0.9.0)

## [0.8.1] - 2026-04-29

**TL;DR**
RSigma v0.8.1 is a patch release for the PostgreSQL backend. Dotted Sigma field names (like `securityContext.isProxy`) now generate correct chained JSONB operators when using `-O json_field=...`.

### Nested JSONB field paths ([#45](https://github.com/timescale/rsigma/pull/45))

When `json_field` is set (e.g. `-O json_field=data`), the PostgreSQL backend now generates chained `->` / `->>` operators for dotted Sigma field names instead of treating the entire dotted string as a single flat key.

**Before (v0.8.0):**

```sql
SELECT * FROM okta_events WHERE data->>'securityContext.isProxy' = 'true'
```

**After (v0.8.1):**

```sql
SELECT * FROM okta_events WHERE data->'securityContext'->>'isProxy' = 'true'
```

Deeply nested paths work as expected:

| Sigma field | Generated SQL |
|-------------|---------------|
| `eventType` | `data->>'eventType'` (unchanged) |
| `securityContext.isProxy` | `data->'securityContext'->>'isProxy'` |
| `actor.detail.sub.field` | `data->'actor'->'detail'->'sub'->>'field'` |

All intermediate segments use `->` (returns `jsonb`), and the final segment uses `->>` (returns `text`). Flat field names without dots are unaffected. NULL propagation works correctly for existence checks: `data->'nonexistent'->>'child'` returns NULL, so `IS NOT NULL` behaves as expected on nested paths.

This is particularly important for Okta System Log rules from SigmaHQ, where fields like `securityContext.isProxy` and `client.ipAddress` reference nested JSON objects.

[v0.8.0...v0.8.1](https://github.com/timescale/rsigma/compare/v0.8.0...v0.8.1)

## [0.8.0] - 2026-04-28

**TL;DR**
RSigma v0.8.0 is the "rule conversion" release. A new `rsigma-convert` crate transforms Sigma rules into backend-native query strings through a pluggable `Backend` trait. The first production backend targets PostgreSQL/TimescaleDB, a backend unique to RSigma and inspired by [pySigma-backend-sqlite](https://github.com/SigmaHQ/pySigma-backend-sqlite) and [pySigma-backend-athena](https://github.com/SigmaHQ/pySigma-backend-athena). The CLI gains `convert`, `list-targets`, and `list-formats` commands. Multi-arch Docker images are now published to GHCR on every release. Processing pipelines support one-to-many field name mapping, and filter rules reach full behavioral parity with pySigma.

Please test this (and RSigma in general) and provide feedback. Contributions are also very welcome.

### `rsigma-convert` crate ([#36](https://github.com/timescale/rsigma/pull/36))

A new library crate for converting parsed Sigma rules into backend-native queries (SQL, SPL, KQL, Lucene, etc.):

- **`Backend` trait** with ~30 methods covering condition dispatch, detection item conversion, field/value escaping, regex, CIDR, comparison operators, field existence, field references, keywords, IN-list optimization, deferred expressions, and query finalization.
- **`TextQueryConfig`** with ~90 configuration fields mirroring pySigma's `TextQueryBackend` class variables: precedence, boolean operators, wildcards, string/field quoting, match expressions (startswith/endswith/contains + case-sensitive variants), regex/CIDR templates, compare ops, IN-list optimization, unbound values, deferred parts, and query envelope.
- **Condition tree walker** that recursively converts `ConditionExpr` nodes into query strings with selector/quantifier support.
- **Orchestrator** via `convert_collection()`, which applies pipelines, converts each rule, and collects results and errors.
- **Deferred expressions** through the `DeferredExpression` trait and `DeferredTextExpression` for backends that need post-query appendages (e.g. Splunk `| regex`, `| where`).
- **Test backend** (`TextQueryTestBackend` and `MandatoryPipelineTestBackend`) for backend-neutral foundation testing.

### PostgreSQL/TimescaleDB backend ([#37](https://github.com/timescale/rsigma/pull/37), [#38](https://github.com/timescale/rsigma/pull/38), [#43](https://github.com/timescale/rsigma/pull/43), [#44](https://github.com/timescale/rsigma/pull/44))

The first production backend, and one that has no equivalent in the pySigma ecosystem. It is inspired by [pySigma-backend-sqlite](https://github.com/SigmaHQ/pySigma-backend-sqlite) and [pySigma-backend-athena](https://github.com/SigmaHQ/pySigma-backend-athena), targeting PostgreSQL natively and leveraging features that map cleanly to Sigma modifiers:

| Sigma Modifier | PostgreSQL SQL |
|----------------|---------------|
| `contains` | `ILIKE` (case-insensitive) |
| `startswith` / `endswith` | `ILIKE` |
| `cased` | `LIKE` (case-sensitive) |
| `re` | `~*` (case-insensitive regex) or `~` (with `cased`) |
| `cidr` | `field::inet <<= 'value'::cidr` |
| `exists` | `IS NOT NULL` / `IS NULL` |
| keywords | `to_tsvector() @@ plainto_tsquery()` |

Five output formats:

| Format | Description |
|--------|-------------|
| `default` | Plain `SELECT * FROM {table} WHERE ...` queries |
| `view` | `CREATE OR REPLACE VIEW sigma_{id} AS SELECT ...` |
| `timescaledb` | Queries with `time_bucket()` for TimescaleDB optimization |
| `continuous_aggregate` | `CREATE MATERIALIZED VIEW ... WITH (timescaledb.continuous)` |
| `sliding_window` | Correlation queries using window functions for per-row sliding detection |

Additional capabilities:

- **SELECT column selection** (inspired by pySigma-backend-athena): when a Sigma rule specifies `fields:`, the backend emits `SELECT field1, field2, ...` instead of `SELECT *`. Supports `field as alias` syntax and passthrough of function calls.
- **CLI backend options**: `-O key=value` flags are now wired through to the PostgreSQL backend. Recognized keys: `table`, `schema`, `database`, `timestamp_field`, `json_field`, `case_sensitive_re`.
- **Custom table/schema/database resolution** at three levels: rule-level `custom_attributes`, pipeline `set_state`, and backend defaults.
- **Multi-table temporal correlations**: when referenced detection rules target different tables (via per-logsource pipeline routing or custom attributes), the backend automatically generates a `UNION ALL` CTE. Single-table correlations use the simpler direct approach.
- **CTE-based correlation pre-filtering** (inspired by pySigma-backend-athena): non-temporal correlations wrap referenced rules' queries in a `WITH combined_events AS (q1 UNION ALL q2 ...)` CTE, so aggregations only count events matching the detection logic rather than scanning the entire table.
- **Sliding window correlations** (inspired by pySigma-backend-athena): the `sliding_window` output format uses SQL window functions (`COUNT(*) OVER (PARTITION BY ... ORDER BY ... RANGE BETWEEN INTERVAL ... PRECEDING AND CURRENT ROW)`) for `event_count` correlations. This produces a per-row sliding window that identifies every event crossing the threshold, complementing the default `GROUP BY` + `HAVING` approach for periodic polling.
- **OCSF processing pipelines**: two included pipelines for single-table (`ocsf_postgres.yml`) and per-logsource multi-table routing (`ocsf_postgres_multi_table.yml`).
- **Reference TimescaleDB schema** with hypertable setup, indexes (B-tree, GIN for full-text and JSONB), compression, retention policies, and an example continuous aggregate.
- **Correlation SQL generation** using `GROUP BY` / `HAVING` for aggregation types (`event_count`, `value_count`, `value_sum`, `value_avg`, `value_percentile`, `value_median`) and CTEs with window functions for temporal correlation.

### CLI: `convert`, `list-targets`, `list-formats`

```bash
rsigma convert -r rules/ -t postgres
rsigma convert -r rules/ -t postgres -p pipelines/ocsf_postgres.yml -f view
rsigma convert -r rules/ -t postgres -p pipelines/ocsf_postgres_multi_table.yml
rsigma convert -r rules/ -t postgres -p pipelines/ocsf_postgres.yml -f continuous_aggregate
rsigma convert -r rules/ -t postgres -O table=security_logs -O schema=public -O timestamp_field=created_at
rsigma convert -r rules/ -t postgres -f sliding_window
rsigma list-targets
rsigma list-formats postgres
```

Options include `-p` / `--pipeline` (repeatable), `-f` / `--format`, `-o` / `--output`, `--skip-unsupported`, `--without-pipeline`, and `-O` / `--option` for backend-specific key=value pairs.

### Multi-arch Docker image ([#39](https://github.com/timescale/rsigma/pull/39))

Multi-arch images (linux/amd64, linux/arm64) are published to GHCR on every release:

```bash
docker pull ghcr.io/timescale/rsigma:latest
docker run --rm ghcr.io/timescale/rsigma:latest --help
```

### One-to-many field name mapping ([#40](https://github.com/timescale/rsigma/pull/40), [#41](https://github.com/timescale/rsigma/pull/41))

Thanks to @fwosar, `FieldNameMapping` now supports mapping a single source field to multiple alternative field names. When more than one alternative is present, the matched detection item is replaced with an OR-conjunction (`AnyOf`) of items, one per alternative, preserving the rule's original AND structure across the rest of the items in the same selection via Cartesian expansion.

```yaml
transformations:
  - id: multi_field_mapping
    type: field_name_mapping
    mapping:
      CommandLine:
        - process.command_line
        - process.args
```

The expansion is capped at 4,096 combinations per detection to prevent runaway Cartesian products in rules with many multi-mapped fields. For correlation rules, `group_by` fields are expanded to include all alternatives, while `aliases` mapping values and threshold `field` reject one-to-many mappings with an error since those positions are inherently scalar.

### pySigma filter parity ([#42](https://github.com/timescale/rsigma/pull/42))

Filter rules now match pySigma semantics across parsing, application, and linting:

- `filter.rules` accepts `"any"` (string) and omission, both meaning "apply to all rules". The new `FilterRuleTarget` enum (`Any` | `Specific(Vec<String>)`) replaces the old `Vec<String>`.
- Filter condition expressions are rewritten with namespaced identifiers (`__filter_0_selection`) and applied as written, instead of hardcoding AND-NOT. Filters that exclude events must use `not selection` explicitly in their condition.
- Logsource matching changed from symmetric compatibility to asymmetric containment: every field the filter specifies must be present and equal in the rule, but fields the filter omits are treated as wildcards.
- `FilterRule` and `CorrelationRule` AST types now carry the full set of standard Sigma fields.

### Pipeline and eval changes

- **Pipeline finalizers**: new `pipeline/finalizers.rs` module for post-pipeline processing hooks used by the conversion path.
- **`QueryExpressionPlaceholders`**: this transformation now stores the expression template in pipeline state, enabling the conversion engine to apply query envelope templates.
- **`apply_field_name_transform`** now returns `Result<()>`, propagating errors from one-to-many expansion overflow.

### Breaking Changes

| Before (0.7.0) | After (0.8.0) |
|----------------|---------------|
| `FieldNameMapping { mapping: HashMap<String, String> }` | `FieldNameMapping { mapping: HashMap<String, Vec<String>> }` |
| `CorrelationCondition::Threshold { predicates, field: Option<String> }` | `CorrelationCondition::Threshold { predicates, field: Option<Vec<String>>, percentile: Option<u64> }` |
| `FilterRule { rules: Vec<String>, .. }` | `FilterRule { rules: FilterRuleTarget, .. }` |
| Filter conditions auto-negated (`AND NOT filter_cond`) | Filter conditions applied as written (use `not selection` explicitly) |

### Contributors

Thanks to @fwosar for the one-to-many field name mapping feature (#40).

[v0.7.0...v0.8.0](https://github.com/timescale/rsigma/compare/v0.7.0...v0.8.0)

## [0.7.0] - 2026-04-23

**TL;DR**
RSigma v0.7.0 is the "any log format" release. The evaluation engine now operates on a generic `Event` trait instead of raw JSON, a new `rsigma-runtime` library crate decouples the streaming pipeline from the CLI, and the daemon can ingest JSON, syslog (RFC 3164/5424), logfmt, CEF, and plain text, with auto-detection by default. Hand-rolled zero-dependency parsers for logfmt and CEF keep the dependency tree lean.

This release is inspired by [sigma_engine](https://github.com/SigmaHQ/sigma_engine), thanks to @thomaspatzke and [Sigma HQ](https://sigmahq.io/) folks.

### Generic Event trait (breaking)

The `rsigma-eval::Event` struct has been replaced by an `Event` trait with three concrete implementations:

- **`JsonEvent`**: wraps `serde_json::Value` (the previous behavior)
- **`KvEvent`**: key-value map for structured formats (syslog, logfmt, CEF)
- **`PlainEvent`**: raw text for keyword-only matching

An `EventValue` enum provides typed access to field values across all implementations. This is a breaking change: callers using `Event::new(value)` should switch to `JsonEvent::borrow(&value)` or `JsonEvent::owned(value)`.

### `rsigma-runtime` crate

The streaming pipeline has been extracted from the CLI daemon into a reusable library crate:

- **`RuntimeEngine`**: wraps `Engine` + `CorrelationEngine` with rule loading, hot-reload, and state management.
- **`LogProcessor`**: batch processing pipeline with `ArcSwap` for atomic engine swap, pluggable `MetricsHook`, and `EventFilter` for JSON payload extraction (e.g. `.records[]`).
- **Input format adapters** (`input/` module): JSON, syslog, logfmt, CEF, plain text, and auto-detect.
- **I/O primitives**: `EventSource` trait and `Sink` enum moved from the CLI.

### Multi-format input (`--input-format`)

The `daemon` and `eval` commands now accept `--input-format` and `--syslog-tz`:

```bash
rsigma daemon -r rules/
rsigma daemon -r rules/ --input-format syslog --syslog-tz +0530
rsigma eval -r rules/ --input-format logfmt < app.log
rsigma eval -r rules/ --input-format cef < arcsight.log
```

Auto-detect validates syslog parsing results (checks for facility/severity/hostname) before accepting and it won't misparse random text as syslog.

### Zero-dependency parsers

- **logfmt**: hand-rolled parser supporting quoted values with escape sequences, bare keys, and mixed whitespace. No external dependencies.
- **CEF (Common Event Format)**: hand-rolled parser for the full ArcSight CEF spec including 7-field pipe-delimited header + key=value extensions with `\=`, `\n`, `\\` escapes. Handles syslog-wrapped CEF via `find_cef_start()`.

Both are feature-gated (`logfmt`, `cef`) and thoroughly tested with real-world log samples.

### Examples and benchmarks

Baseline results (Apple M4 Pro, 100 rules):

| Format | Throughput |
|--------|-----------|
| Plain text | 5.5-10.9 Melem/s |
| Syslog | 1.26-1.40 Melem/s |
| JSON | 955 Kelem/s-1.15 Melem/s |
| Auto-detect | ~966 Kelem/s-1.09 Melem/s |

Rule-count scaling is near-flat from 100 to 1,000 rules thanks to logsource index pruning.

### Other changes

- **Custom attributes** (`custom_attributes`): propagate custom rule attributes through results, then unified across detection and correlation rules into a single `custom_attributes` field (breaking: `custom_rule_attributes` removed). Thanks to @fwosar (#26).
- **Lint `--exclude`**: glob patterns to skip files during linting, plus detection of deprecated aggregation syntax.
- **Line feeds in conditions**: fixed parsing of condition expressions containing line breaks. Thanks to @fwosar (#24).
- **Dependencies**: `notify` 7 -> 8.2, `rustls-webpki` -> 0.103.13.
- **`BENCHMARKS.md`**: documents all benchmark groups, baseline results, and the 5% regression threshold.

### Breaking Changes

| Before (0.6.0) | After (0.7.0) |
|----------------|---------------|
| `use rsigma_eval::Event;` (struct) | `use rsigma_eval::event::Event;` (trait) |
| `Event::new(value)` | `JsonEvent::borrow(&value)` or `JsonEvent::owned(value)` |
| `Event::from_value(v)` | `JsonEvent::borrow(&v)` |
| `result.custom_rule_attributes` | `result.custom_attributes` |

### Contributors

Thanks to @fwosar for their contributions to this release (#24, #26).

[v0.6.0...v0.7.0](https://github.com/timescale/rsigma/compare/v0.6.0...v0.7.0)

## [0.6.0] - 2026-04-17

**TL;DR**
RSigma grew up. v0.6.0 makes the daemon production-ready for streaming detection: plug it into NATS JetStream or HTTP, fan out to multiple sinks, and let rayon + an inverted index chew through rules **2-3x faster**. Stateful correlation still survives restarts via SQLite, stdin/stdout still works by default, and `cargo audit` is back to **zero vulnerabilities**.

This release resolves the "not meant for streaming logs" gap correctly identified in [Detection Engineering Weekly #149](https://www.detectionengineering.net/p/dew-149-roll-your-own-sigma-siem) by [Zack Allen](https://www.linkedin.com/in/zack-allen-12749a76/) and positions RSigma as a single-node streaming detection engine -- not just a CLI forensics tool. Three levels of work landed:

1. **Level 1**: pluggable I/O adapters (NATS, HTTP, file, fan-out)
2. **Level 2**: async pipeline hardening (backpressure, micro-batching, drain)
3. **Level 3**: inverted index + feature-gated rayon parallel batch evaluation

### Streaming I/O adapters (Level 1)

The daemon now speaks NATS JetStream, HTTP, and files and not just stdin/stdout.

```bash
rsigma daemon -r rules/ --input http
rsigma daemon -r rules/ --input nats://localhost:4222/events.> --output nats://localhost:4222/detections
rsigma daemon -r rules/ --output file:///var/log/detections.ndjson
rsigma daemon -r rules/ --output stdout --output file:///tmp/detections.ndjson
```

- **`EventSource` trait + `Sink` enum**: pluggable adapters with enum dispatch; async-friendly `Sink::FanOut(Vec<Sink>)` for multi-sink output.
- **`--input`/`--output` URL schemes**: `stdin://`, `http://`, `nats://`, `file://`, `stdout://`; multiple `--output` flags clone `ProcessResult` per sink via bounded mpsc channels.
- **`daemon-nats` feature flag**: gates `async-nats`; durable JetStream consumer with ACK, publisher sink.

### Async pipeline hardening (Level 2)

- **Fully async stdin** via `tokio::io::AsyncBufReadExt` (no more `spawn_blocking`).
- **Configurable back-pressure**: `--buffer-size` (default 10,000) sets bounded mpsc capacity for both source-to-engine and engine-to-sink queues.
- **Micro-batched evaluation**: `--batch-size` (default 1); engine collects up to N events per mutex acquisition via `try_recv()`.
- **Graceful drain on shutdown**: `--drain-timeout` (default 5s) lets in-flight events finish before state save; natural EOF drains without timeout.
- **5 new Prometheus metrics**: `rsigma_input_queue_depth`, `rsigma_output_queue_depth`, `rsigma_back_pressure_events_total`, `rsigma_pipeline_latency_seconds`, `rsigma_batch_size`.

### Performance: inverted index + parallel batch evaluation (Level 3)

- **Inverted index**: `RuleIndex` maps `(field, exact_value)` to rule indices at load time. `Engine::evaluate()` queries candidates instead of scanning all rules. Rules without exact-match items are marked unindexable and always evaluated (no false negatives).
- **Feature-gated rayon**: new `parallel` feature on `rsigma-eval` enables `Engine::evaluate_batch()` and `CorrelationEngine::process_batch()`. Parallel detection + sequential correlation via a borrow split.
- **Benchmark results** (5,000 rules, synthetic events):
  - Detection evaluation: **2.4-2.7x speedup** from indexing alone.
  - Correlation throughput: **~1.7x improvement** (indexed + sequential).
  - Batch evaluation scales with core count.

### New public APIs (`rsigma-eval`)

- `Engine::evaluate_batch(&self, events: &[&Event]) -> Vec<Vec<MatchResult>>`
- `CorrelationEngine::evaluate(&self, event: &Event) -> Vec<MatchResult>`
- `CorrelationEngine::process_with_detections(&mut self, event, detections, timestamp_secs) -> ProcessResult`
- `CorrelationEngine::process_batch(&mut self, events: &[&Event]) -> Vec<ProcessResult>`

### Pipeline parity

- **Named condition IDs** supported in `rule_cond_expression` (not just numeric indices).
- **Correlation rules** now apply processing pipelines consistently with detection rules.

### Dependencies and security

- `async-nats` 0.46 to 0.47 (drops pinned vulnerable `rustls-webpki 0.102.8`, `rustls-pemfile 2.2.0`, `rand 0.8.5`)
- `rustls-webpki` to 0.103.12 (RUSTSEC-2026-0049/-0098/-0099)
- `rand` to 0.9.4 (RUSTSEC-2026-0097)
- `lodash` override to 4.18.x in VS Code extension (devDependency-only)
- `cargo audit`: 0 vulnerabilities

[v0.5.0...v0.6.0](https://github.com/timescale/rsigma/compare/v0.5.0...v0.6.0)

## [0.5.0] - 2026-02-26

### Daemon mode (`rsigma daemon`)

rsigma can now run as a long-running service for real-time event processing, with hot-reload, health checks, metrics, and a REST API.

```bash
rsigma daemon -r rules/ -p ecs.yml --api-addr 127.0.0.1:8080
```

- **Hot-reload**: file watcher, SIGHUP, and `/api/v1/reload` endpoint. Correlation state is preserved across reloads.
- **Health endpoints**: `/healthz`, `/readyz`
- **Prometheus metrics**: events processed, detection/correlation matches, rules loaded, uptime, state entries
- **REST API**: `/api/v1/status`, `/api/v1/rules`, `/api/v1/reload`
- **Structured logging**: JSON via `tracing` with `RUST_LOG` control

### SQLite state persistence (`--state-db`)

Correlation state (windows, suppression timers, event buffers) now survives daemon restarts.

```bash
rsigma daemon -r rules/ -p ecs.yml --state-db ./rsigma-state.db --state-save-interval 10
```

- Periodic snapshots (configurable via `--state-save-interval`, default 30s)
- Graceful shutdown save
- Schema-versioned snapshots for forward compatibility
- Base64-encoded compressed event buffers for efficient storage
- State preserved across hot-reloads (export before engine swap, re-import after)

### CI

- All workflows now use `--all-features` to cover daemon-gated code

### Dependencies

- Removed `protobuf` transitive dependency (disabled `prometheus` default features) -- resolves RUSTSEC-2024-0437

[v0.4.0...v0.5.0](https://github.com/timescale/rsigma/compare/v0.4.0...v0.5.0)

## [0.4.0] - 2026-02-23

### Bug fixes

* **Filter name collision** -- Multiple filters sharing detection names (e.g. both using `selection`) no longer overwrite each other. Filter detections are now namespaced with a counter to prevent key collisions.
* **CVE-2026-26996** -- Upgraded `minimatch` to 10.2.1 in the VS Code extension.

### Validation improvements

* **`UnknownDetection` at compile time** -- Condition expressions referencing non-existent detections now fail eagerly during `compile_rule()` instead of silently at eval time.
* **`UnknownRuleRef` at load time** -- Correlation `rule_refs` are validated to resolve to known rules or correlations when calling `add_collection()`.

### Dependency upgrades

* `yamlpatch` 0.11 to 0.12, `yamlpath` 0.33 to 0.34 (Unicode-aware patching, empty-route `RewriteFragment` fix).
* `jsonschema` 0.29 to 0.42 (13 minor versions of improvements).
* `tower-lsp` 0.20 to `tower-lsp-server` 0.23 (actively maintained community fork; native async traits).
* 49 transitive crate updates via `cargo update`.

### Test coverage

* ~1,300 lines of new tests: end-to-end integration, correlation edge cases, parser/eval error paths, and pipeline error handling.

### Breaking changes

* Removed `EvalError::TimestampParse` variant (unused).

[v0.3.0...v0.4.0](https://github.com/timescale/rsigma/compare/v0.3.0...v0.4.0)

## [0.3.0] - 2026-02-19

### Auto-fix for Sigma lint rules

This release adds machine-applicable fix suggestions to the linter, exposed through both the CLI and the LSP server.

- **`rsigma lint --fix`** -- Apply safe fixes in-place. Uses format-preserving YAML editing (`yamlpath`/`yamlpatch`) so comments and formatting are retained.
- **LSP code actions** -- Quick-fix lightbulb in editors for all fixable lint warnings. Fixes are converted to `TextEdit`s and offered when the cursor overlaps the warning range.
- **Fix infrastructure** -- `Fix`, `FixDisposition` (Safe/Unsafe), and `FixPatch` (`ReplaceValue`, `ReplaceKey`, `Remove`) types in `rsigma-parser`. 13 lint rules carry safe fix suggestions.

### Improvements

- Improved parser error reporting with better span information.
- Expanded modifier validation and test coverage.

### Fixable lint rules

`invalid_status`, `invalid_level`, `non_lowercase_key`, `logsource_value_not_lowercase`, `unknown_key`, `duplicate_tags`, `duplicate_references`, `duplicate_fields`, `single_value_all_modifier`, `all_with_re`, `wildcard_only_value`, `filter_has_level`, `filter_has_status`

[v0.2.0...v0.3.0](https://github.com/timescale/rsigma/compare/v0.2.0...v0.3.0)

## [0.2.0] - 2026-02-17

### Linter, LSP, Processing Pipelines, and Correlation Engine

First release of rsigma -- a Sigma detection toolkit in Rust. Ships a parser, evaluation engine, 65-rule linter, LSP server, processing pipelines, correlation engine, and cross-platform CLI.

### New features

- **Parser** (`rsigma-parser`) -- Sigma YAML to strongly-typed AST via PEG grammar; 30 modifiers; multi-document YAML support.
- **Evaluation engine** (`rsigma-eval`) -- Compile-then-evaluate architecture for Sigma rules against JSON log events.
- **Linter** -- 65 built-in lint rules from the Sigma spec v2.1.0 with Error/Warning/Info/Hint severity, per-rule suppression (`rsigma-suppress`), and colored terminal output.
- **LSP server** (`rsigma-lsp`) -- Diagnostics, completions, hover, and document symbols; packaged as a VS Code extension with esbuild bundling.
- **Processing pipelines** -- All 26 pySigma transformation types for full pipeline parity (field mapping, value transforms, logsource rewriting, drop rules).
- **Correlation engine** -- All 7 Sigma correlation types plus `repeat`, `percentile`, and `range` conditions; configurable timestamp fallback; cycle detection; chain depth warnings; compressed event storage for `include_event` mode.
- **CLI** -- `parse`, `validate`, `eval`, `lint` subcommands; `@file` syntax for `--event`; `--jq`/`--jsonpath` event filters; alert suppression; `action-on-fire`; `generate` flag; NDJSON streaming.
- Binary release workflow for cross-platform builds (Linux, macOS, Windows).
- Trusted publishing workflow for crates.io.
- CI: tests on Linux/macOS/Windows, Sigma corpus regression job, `cargo-audit` security scanning.

### Fixes

- Hard cap on correlation state when time-based eviction is insufficient.
- Empty `AllOf`/`AnyOf` detections rejected at compile time.
- `|re` modifier is case-sensitive by default per Sigma spec.
- `windash` modifier includes all five Sigma spec characters.
- `Event::get_field` traverses arrays in dot-notation paths.
- Unicode-aware case folding for case-insensitive matching.
- Timestamp clamping in `process_event_at` to prevent overflow.
- Memory leak in linter.

### Performance

- Pre-compiled regex patterns in pipeline conditions.
- Eliminated hot-path cloning in correlation engine.
- Eliminated `Vec` and `String` allocations in keyword matching.

[v0.2.0](https://github.com/timescale/rsigma/commits/v0.2.0)

## [0.1.0] - 2026-02-17

Initial crates.io publish. Reserved the `rsigma` crate name with a minimal CLI binary (parser + evaluator only, no linter/LSP/pipelines/correlation). Superseded the same day by v0.2.0, which is the first feature-complete release.

[0.13.0]: https://github.com/timescale/rsigma/releases/tag/v0.13.0
[0.12.0]: https://github.com/timescale/rsigma/releases/tag/v0.12.0
[0.11.0]: https://github.com/timescale/rsigma/releases/tag/v0.11.0
[0.10.0]: https://github.com/timescale/rsigma/releases/tag/v0.10.0
[0.9.0]: https://github.com/timescale/rsigma/releases/tag/v0.9.0
[0.8.1]: https://github.com/timescale/rsigma/releases/tag/v0.8.1
[0.8.0]: https://github.com/timescale/rsigma/releases/tag/v0.8.0
[0.7.0]: https://github.com/timescale/rsigma/releases/tag/v0.7.0
[0.6.0]: https://github.com/timescale/rsigma/releases/tag/v0.6.0
[0.5.0]: https://github.com/timescale/rsigma/releases/tag/v0.5.0
[0.4.0]: https://github.com/timescale/rsigma/releases/tag/v0.4.0
[0.3.0]: https://github.com/timescale/rsigma/releases/tag/v0.3.0
[0.2.0]: https://github.com/timescale/rsigma/releases/tag/v0.2.0
[0.1.0]: https://crates.io/crates/rsigma/0.1.0
