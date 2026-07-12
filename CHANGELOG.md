# Changelog

All notable changes to RSigma are documented in this file. Each entry corresponds to a [GitHub Release](https://github.com/timescale/rsigma/releases).

## [Unreleased]

### rstix Validation Pipeline: conformance corpus and diagnostic coverage (`validate` feature) (#315)

Closes Validation Pipeline conformance work for phases 1–4:

* **Per-code coverage** — `tests/validate_diagnostic_coverage.rs` asserts one integration case per `DiagnosticCode::ALL` entry (39 codes).
* **Conformance corpus** — `validate_conformance.rs` gates `conformance/` plus `validation/bundle-*.json` negatives under `interop_strict`.
* **Parse bridge** — all `ParseError` variants and mapped `ModelError` messages emit structured diagnostics; model invariants use tagged serde payloads (`model/serde_error.rs`) so validation never downgrades to `STIX-E0001` (reserved for JSON syntax/EOF).
* **Wire-format validators** — lightweight checks at parse; strict IDNA / RFC 5322 / WHATWG checks gated behind `validate` (optional `idna`, `email_address`, `url` deps) as pipeline `STIX-I0002` findings.
* **Model mapping** — exhaustive `ModelError` → `STIX-E/W/I/H` code mapping in `validate/model_mapping.rs`.

### Docmd site branding (#314)

The docmd plugin copies `assets/rsigma-logo.png` into the published site at build time, trims transparent padding with sharp, and writes a square favicon PNG. The sidebar shows the trimmed mark with an RSigma text label styled for light and dark themes.

### Docs site search on rsigma.io (#313)

Build the docmd site with base `/` and canonical URL `https://rsigma.io/` so the search client loads `search-index.json` from the site root. The previous `/rsigma/` base matched the old GitHub Pages project path but broke search after the custom domain went live.

### Documentation site migrated to docmd (#312)

Replaces MkDocs Material with [docmd](https://docs.docmd.io/) for the published docs at `https://timescale.github.io/rsigma/`. The whole docmd project is self-contained under `docs/` (config, `package.json`, local plugin, assets, and Markdown under `docs/content/`). `docs/docmd.config.js` carries the reorganized navigation (User Guide grouped into Author/Test, Deploy/Detect, Alert/Respond, Measure/Hunt, Operate, and Integrate sub-categories; Benchmarks under Reference; Editors/Ecosystem under Integrations; Release Notes/Contributing/Security under Project) and defaults to dark mode. A local `docmd-plugin-rsigma` plugin preserves Cargo.toml-synced version, MSRV, and lint-count macros and the inlining of root CHANGELOG/CONTRIBUTING/BENCHMARKS/SECURITY, and strips docmd's site-root `<base>` tag so the project subpath resolves correctly. MkDocs-specific syntax (`!!!` admonitions, Material grid cards) is converted to docmd callouts and card grids. CI builds from `docs/` with `npm run docs:build` and `npm run docs:validate` via SHA-pinned first-party GitHub Actions.

### Disposition source recipes (docs) (#311)

A new [Disposition Source Recipes](https://timescale.github.io/rsigma/guide/disposition-recipes/) guide with copy-paste `--disposition-source` configs that pull analyst verdicts from TheHive, Jira, and GitHub Issues into the triage feedback loop. Each recipe is one HTTP dynamic source with a jq `extract` that reshapes the case system's API response into disposition records, plus its verdict mapping, `${ENV_VAR}` auth, and the identity round-trip and idempotency reasoning. The three sources files are committed as test fixtures and their extracts run against canned API responses in CI, so the documented recipes cannot silently drift from what the ingest path accepts. Docs-only beyond the fixture test; no engine or daemon change.

### Request body for `http` dynamic sources (#310)

The `http` dynamic-source type gains an optional `body` field, sent verbatim after `${VAR}` environment expansion, so a source can poll a query API that requires a request body (GraphQL, an Elasticsearch/OpenSearch `_search`, TheHive 5's `/api/v1/query`). A source with a `body` and no explicit `method` defaults to `POST`; an explicit `method` still wins. `Content-Type` is not inferred and should be set in `headers`. The reference documentation for `headers` is also corrected: `${VAR}` references have always been expanded from the environment at fetch time, which the field table previously said was unimplemented.

### Dependency bumps (#308)

Rolls up five open Dependabot PRs into a single merge. Rust (workspace `Cargo.lock`): `tower-http` 0.6.11 to 0.7.0 (#299), `cel` 0.13.0 to 0.14.0 (#300), `rmcp` 1.8.0 to 2.1.0 (#301), and `phf` 0.13.1 to 0.14.0 (#303); `rsigma-mcp` is migrated to the rmcp 2.x API (`Resource`, `ContentBlock`). CI (all repinned by commit SHA, batched via the `actions-updates` group, #302): `taiki-e/install-action` v2.82.4 to v2.82.7, `docker/setup-buildx-action` v4.1.0 to v4.2.0, `docker/login-action` v4.2.0 to v4.3.0, `docker/build-push-action` v7.2.0 to v7.3.0, `github/codeql-action/upload-sarif` v4.36.2 to v4.36.3, `docker/metadata-action` v6.1.0 to v6.2.0, and `actions/attest-build-provenance` v4.1.0 to v4.1.1. The `rusqlite` 0.39 to 0.40.1 bump (#234) stays held back on MSRV 1.88.

### Control-plane API audit trail (#307)

Adds an append-only audit log for control-plane mutating daemon API calls (who, what, when, outcome), persisted in the existing SQLite state database when `--state-db` is configured. Auto-enabled with a state database; optional `daemon.api.audit` config tunes retention, optional sink emission, or disables the trail. Each record stores method, matched route pattern, token name, HTTP status, timestamp, and a SHA-256 hex digest of the request body (never the body itself). Data-plane ingest and OTLP are excluded. `GET /api/v1/audit` (`audit:read`) serves paginated entries; bodies over `max_body_bytes` (default 64 KiB) get `413` and the rejected attempt is recorded. New metrics: `rsigma_audit_records_total`, `rsigma_audit_write_errors_total`.

### WASM ABI contract and build compatibility (#306)

Documents ABI version 1 for future direct `wasm32-unknown-unknown` hosts, including the linear-memory ownership model, packed status/result values, result descriptors, stable JSON error envelopes, and compatibility rules. CI builds `rsigma-parser` and `rsigma-eval` for `wasm32-unknown-unknown` with default features disabled, then instantiates a module linking them in a JavaScript-free runtime (Wasmtime) to prove it runs and carries no JavaScript imports.

- `rsigma-parser` gains a default-on `fix` feature around the source-preserving `yamlpath`/`yamlpatch` auto-fix implementation. Parsing, validation, lint diagnostics, and fix metadata remain available without it.
- `rsigma-eval` disables `rsigma-parser` default features because evaluation does not use the auto-fix implementation, uses compile-time AHash seeding only on `wasm32-unknown-unknown`, and drops `chrono`'s `wasmbind` feature on that target so the module stays host-neutral (no `wasm-bindgen`/`js-sys` imports). Native targets retain runtime-randomized hashing and the default `chrono` behavior.
- The first-party `rsigma-wasm` guest crate and published `.wasm` artifact do not ship in this change.

### De-flaked the daemon schema-observer E2E test on Windows (#305)

`SchemaObserver::observe` bumped its `events_observed` counter before recording the classification result, so the `/api/v1/schemas` snapshot (served on a different thread than event ingestion) could report `events_observed == N` while the Nth event's `classified`/`unknown` increment had not yet landed. A reader that waited on `events_observed` then read a torn snapshot with `unknown` short by one, which surfaced as a Windows CI failure in `schemas_endpoint_reports_per_schema_and_unknown_counts`. `events_observed` is now derived as `classified + unknown` inside the snapshot, so every snapshot is internally consistent regardless of thread interleaving.

### Daemon API authentication (bearer tokens + granular RBAC) (#304)

Adds opt-in bearer-token authentication with `resource:action` permissions to the daemon API. Off by default: without configuration the routes stay open as before, and `GET /healthz` / `GET /readyz` are always unauthenticated so liveness probes never need secrets.

- **Two ways to enable.** `--api-token-env <ENV_VAR>` names an environment variable holding a single full-`admin` token (the secret never appears on the command line or in YAML), or the `daemon.api.auth` config block declares named roles and per-token role assignment. The flag and the block are mutually exclusive.
- **Granular RBAC.** Every route maps to a `resource:action` permission (`silences:write`, `reload:execute`, `tap:read`, `events:ingest`, ...); the mapping fails closed, so an unmapped route requires the full `*` grant. Roles are permission sets with `*` wildcards: built-in `reader` (`*:read`), `operator` (`*:read` plus control-plane writes except reload), `ingest` (`events:ingest` only, so a log shipper's token cannot create silences), and `admin` (`*`), plus operator-defined roles (or inline per-token `permissions`).
- **Anonymous permissions.** `anonymous_permissions` grants a permission set to requests without an `Authorization` header: `["metrics:read"]` keeps Prometheus scraping token-free, `["*:read"]` protects only the mutating endpoints. A presented-but-unrecognized token is always rejected, never downgraded to the anonymous grants.
- **Secret posture.** Each token's `token_env` names an environment variable resolved once at startup (the webhook `secret_env` posture); a missing or empty variable, a duplicate token name or secret, an unknown or redefined built-in role, or a malformed permission string fails startup with a clear message. Comparison is constant-time per candidate token.
- **Failure semantics.** Missing or invalid credentials get `401` with `WWW-Authenticate: Bearer`; a recognized token without the required permission gets `403` naming the missing permission. OTLP/gRPC clients authenticate with the same `authorization` metadata and receive `UNAUTHENTICATED`/`PERMISSION_DENIED` status codes. Rejections increment the new `rsigma_api_auth_failures_total{reason}` counter and log at warn with the token name, never the secret. The established identity is attached to the request for handlers to attribute the call.
- **Docs.** New Authentication sections in the HTTP API reference (per-endpoint permission table), the security reference, and the `engine daemon` CLI page; the config template and configuration reference cover the `daemon.api.auth` block.

### rstix Validation Pipeline: all twelve checks (`validate` feature) (#298)

Implements the full validation check set behind `validate`:

* **All twelve checks** — schema, ID structure, property types, open vocabulary, pattern parse/semantic, references, cross-object semantics, extension resolution, and TLP marking computation are wired through the dispatcher (no `STIX-I0020` stubs).
* **Shared helpers** — `model_bridge`, `object_validate`, `semantic`, and `wire` modules map `ModelError` / wire JSON to pipeline diagnostics; overlapping `Bundle::validate()` findings migrate to `STIX-E/W/I` codes per DD-VP-001.
* **Pattern split** — `Pattern::parse_ast` and `Pattern::type_check_ast` expose parse-only vs type-check phases for `STIX-E0010` / `STIX-E0011`.
* **Integration tests** — validation fixtures assert `STIX-W0031`, `STIX-E0024`, `STIX-I0002`, and `STIX-W0010` through `Validator::consumer_strict()`.
* **Conformance harness hardening** — conformance tests are locked to bundled in-repo fixtures for deterministic CI (no external env override path).

### rstix Validation Pipeline scaffold (`validate` feature) (#297)

Adds the profile-based **Validation Pipeline** module behind the optional `validate` feature (implies `serde` + `pattern`):

* **`Validator` / `ValidatorBuilder`** — four named profiles (`consumer_permissive`, `consumer_strict`, `producer_strict`, `interop_strict`) and custom check selection.
* **`Diagnostic` / `DiagnosticCode` / `Severity`** — structured `STIX-E/W/I/H` taxonomy with `ValidationReport::is_valid()` (no Error-severity diagnostics).
* **Raw JSON entry** — `validate_json_str` / `validate_json_value` emit `STIX-E0001` on malformed JSON (line/column span) instead of panicking or failing only at deserialize.
* **Check dispatcher** — all twelve `ValidationPhase` variants wired; remaining check implementations follow in a later release.
* **Leniency** — `ValidationReport::is_valid()` respects profile policy (`Standard` vs `Zero` for interop); `STIX-H0001` hint taxonomy wired.
* **Type discrimination scaffold** — non-bundle JSON roots emit `STIX-E0002` with `property_path` / `fix_suggestion`; `ValidatorBuilder::with_allow_custom` and `with_parse_options` expose parse policy.
* **Stub visibility** — not-yet-implemented checks emit informational `STIX-I0020`; profile rustdoc and [`Validator::implemented_phases`] document current coverage.
* **DD-VP-001** — documents the boundary between advisory `Bundle::validate()` (`model::ValidationReport`) and `validate::Validator`.
* **`fuzz_rstix_validate_json`** — libFuzzer target over `Validator::validate_json_str`; seeds in `fuzz/seeds/fuzz_rstix_validate_json/`.

### rstix Pattern Engine: canonical printer, Indicator wiring, and pattern semantics (#296)

Adds the remaining `pattern` feature pieces for STIX indicator patterns and closes §9.6.1 evaluation semantics:

* **`Pattern::canonical` / `Display`** — AST → canonical STIX pattern string; parse → print → parse preserves semantics (§9.8 fixture round-trips).
* **`IndicatorPattern::Stix { parsed }`** — STIX indicators deserialize with `Pattern::parse(raw)` when `pattern` is enabled; invalid patterns fail at deserialize time.
* **`IndicatorPattern::evaluate` / `evaluate_observed_data`** — delegate to the parsed pattern for STIX indicators; `NonStixPattern` for YARA/Snort/etc.
* **`IndicatorBuilder`** — fluent programmatic construction of indicators (`stix_pattern`, `external_pattern`, `valid_from`, kill-chain phases); STIX patterns parse and type-check at `build()` when `pattern` is enabled; runs [`Indicator::validate`]. Design decision [DD-PE-001](docs/library/rstix.md#dd-pe-001--indicatorbuilder-validates-at-build-not-in-setters) documents why validation runs at `build()` rather than in setters.
* **`fuzz_stix_pattern`** — libFuzzer target over parse + canonical print; seeds in `fuzz/seeds/fuzz_stix_pattern/` (§9.8 fixture lines).
* **`LIKE` / `MATCHES` NFC normalization** — pattern constants and string property haystacks NFC-normalized before comparison.
* **`MATCHES` PCRE DOTALL** — regex compilation enables `.` across newlines per §9.6.1.
* **`evaluate()` with `at: None`** — non-temporal patterns accept observations without timestamps; temporal patterns still return `MissingTimestamp`.
* **Absent optional `_ref` properties** — comparisons do not match; `EXISTS` is false; dangling or non-SCO targets still return `RefResolution`.

### De-flaked the TLS misconfiguration E2E tests on macOS (#295)

`spawn_expect_failure` in the CLI test harness raced the daemon's exit against its stderr: the collection loop broke as soon as `try_wait()` saw the process gone, so when a misconfigured daemon failed fast (as `encrypted_key_password_is_rejected_with_guidance` does, the encrypted-key check being the first thing TLS init runs), the reader thread could still be holding the error line and the test asserted against empty stderr. The helper now drains the channel after reaping the child; closing the pipe ends the reader thread, so the drain terminates deterministically.

### Removed pipeline-embedded `sources:` blocks (#293)

Dynamic source declarations no longer live inside pipeline files. A pipeline that still declares an inline `sources:` block is now rejected with a hard parse error that points at `rsigma rule migrate-sources`; source declarations come exclusively from standalone `--source` files, and a pipeline only references them with `${source.<id>}`. This completes the deprecation cycle started in v0.12.0 (#135, visible-deprecated) and continued in v0.13.0 (#136, hidden from docs).

- **Library API.** `rsigma_eval::Pipeline` drops its `sources` field; `Pipeline::is_dynamic()` is now driven purely by `${source.*}` references, and `validate_source_refs` no longer takes a pipeline-local declaration set. `parse_sources` is now exported for tooling that reads a raw `sources:` block. The runtime `RuntimeEngine` gains `set_external_sources`, resolving and expanding references against the external declarations (carried across hot-reload), and `expand_includes` takes the external sources for its remote-include check.
- **Reference detection fix.** List-valued pipeline `vars` (the common `value_placeholders` shape, e.g. `malicious_commands: ["${source.cmd_list}"]`) are now correctly recognized as dynamic source references; previously only scalar var values were scanned, which the removed inline `sources:` block had masked.
- **`rule migrate-sources`** reads the inline `sources:` block directly (rather than through the now-rejecting pipeline parser) so it keeps working as the migration path.
- **Docs and tests** move to the external-only model throughout; the runtime `pipeline_deprecation` module and its stderr warning are gone.

### Removed the deprecated flat CLI aliases (#292)

The twelve flat top-level subcommands (`eval`, `daemon`, `parse`, `validate`, `lint`, `fields`, `condition`, `stdin`, `convert`, `list-targets`, `list-formats`, `resolve`) are removed. They shipped as visible-deprecated forwarders in v0.12.0 (#124), were hidden from `rsigma --help` in v0.13.0 (#125), and reach end-of-life here. Invoking a removed alias now fails with clap's `unrecognized subcommand` error and lists the available command groups. Use the noun-led groups instead: `engine eval`, `engine daemon`, `rule parse`, `rule validate`, `rule lint`, `rule fields`, `rule condition`, `rule stdin`, `backend convert`, `backend targets`, `backend formats`, and `pipeline resolve`. The per-alias forwarding dispatch and the stderr deprecation warning are gone; the group enums remain the single source of truth for every argument.

### Benchmark refresh and two new suites (#291)

Reran every benchmark suite on current main (Apple M4 Pro, 2026-07-05) and rewrote `BENCHMARKS.md` from the results, replacing the 0.9.0-era figures and their freshness disclaimer. The refreshed doc now also covers suites that existed but were never documented: the bloom prefilter rejection sweep, logsource pruning, and result serialization.

* **New `schema` bench (`rsigma-eval`)** measures per-event `SchemaClassifier::classify` cost against the built-in signature set (early match, mid-list match, full-scan unknown, and the ambiguity-aware variant): 216-548 ns per event, so `--schema-routing` and `--observe-schemas` are effectively free at pipeline throughputs.
* **New `enrichment` bench (`rsigma-runtime`)** measures the CPU-only floor of the post-evaluation enrichment pipeline with the `template` primitive over 1,000-result batches at one and four enrichers (~0.6-0.9 us per result per enricher).
* **New `array` bench (`rsigma-eval`)** measures the `sigma-version: 3` array-matching paths against a flat-field baseline: implicit any-member matching, `[any]`/`[all]` object scopes at varying lengths and match positions, and positional indexing. Cost is linear in member count (~35-60 ns/member non-firing, ~110-250 ns/member firing, since the fan-out collects every matching member); positional indexing is O(1).
* **New `routing` bench (`rsigma-eval`)** measures end-to-end `--schema-routing` dispatch (classify, route, evaluate on the per-schema engine) over a mixed ECS/Sysmon/unknown stream against a single unrouted engine, separating the sub-microsecond dispatch cost from the real matching work the pipeline-mapped engines do.
* **New `input_formats` bench (`rsigma-runtime`, `--features logfmt,cef,evtx`)** completes the format matrix: logfmt (631K events/s), CEF (527K events/s) through the `LogProcessor` pipeline, and `EvtxFileReader` binary parsing over the `security.evtx` fixture (195K records/s).
* **New `otlp` bench (`rsigma-runtime`, `--features otlp`)** measures `logs_request_to_raw_events`, the OTLP ingest-side flattening of an `ExportLogsServiceRequest` into engine events: a flat ~2.3 us per record independent of batch size.
* **New `runtime_observe_fields` group** in the `runtime_throughput` bench measures the `--observe-fields` hot-path overhead: ~0.3 us per event on seven-key JSON events.
* **Fixed the `dynamic_pipelines` bench**, which panicked since `load_rules` gained fail-closed dynamic-source re-resolution: the engine-build and reload benchmarks now run inside the tokio runtime context they require.

### MCP sigma-cli delegation: reach the pySigma backends from `convert_rules` (#290)

Extends the native-first sigma-cli delegation that `rsigma backend convert` gained in #241 to the MCP server: when `rsigma mcp serve` runs with the new `--allow-sigma-cli` flag (config key `mcp.allow_sigma_cli`), the `convert_rules` tool delegates any target without a native backend to an installed [sigma-cli](https://github.com/SigmaHQ/sigma-cli), so an agent can convert to `splunk`, `elasticsearch`, `kusto`, `qradar`, `loki`, and the rest of the pySigma backend set. The `rsigma_convert` library API stays native-only by design.

- **Off by default.** Delegation spawns a subprocess, a category change from the server's pure in-process posture, so it is opt-in for both stdio and HTTP. With delegation off, an unknown target keeps returning the structured error, now extended with a hint that `--allow-sigma-cli` unlocks the delegated targets.
- **Hardened.** Delegated `path` and file-based `pipelines` inputs are canonicalized and confined to `--rules-dir` when one is configured (a path that escapes it is refused), inline `yaml` is staged through a private temporary file, the subprocess is spawned with `kill_on_drop` under a 60-second timeout, and at most two delegations run concurrently.
- **Envelope.** A delegated result carries `engine: "sigma-cli"`, the per-line `queries` split the CLI's JSON envelope uses, a verbatim `raw` field (the faithful copy for multi-line output formats such as Loki `ruler`), and `warnings` with sigma-cli's zero-exit stderr. A missing sigma-cli returns `ok: false` with install guidance.
- **Discovery.** `list_backends` appends the installed sigma-cli targets (flagged `engine: "sigma-cli"`, shadowed native names excluded) when delegation is enabled, mirroring `backend targets` on the CLI; native entries gain a matching `engine: "native"` flag.
- **Shared helper (public API changes).** The delegation helper moved from `rsigma-cli` into a new feature-gated `rsigma_convert::sigma_cli` module (std-only, no new dependencies) with a `classify_output` outcome classifier, so the CLI and the MCP server share one flag mapping and cannot drift; CLI behavior is unchanged. `RsigmaMcp::new` gains a third `allow_sigma_cli: bool` parameter.

### Dependency bumps (#289)

Rolls up the open Dependabot PRs into a single merge, regenerating the lockfiles against current `main` rather than replaying stale lockfile bases, then refreshes everything else `cargo update`, `npm update`, and the docs pins had pending. Rust (workspace `Cargo.lock`): `similar` 2.7.0 to 3.1.1 (#282, a major bump also reflected in `crates/rsigma-cli/Cargo.toml`), `bytes` 1.11.1 to 1.12.0 (#283), `yamlpath` 1.25.2 to 1.26.1 (#284), `cmov` 0.5.3 to 0.5.4 (#288), and the `patch-updates` group (#281) `log` 0.4.33, `uuid` 1.23.4, `rustls` 0.23.41, `env_logger` 0.11.11 plus `time` and `jsonschema`; a follow-up full `cargo update` regenerates both the workspace and `fuzz/Cargo.lock` to the latest MSRV-compatible set, notably `aws-lc-rs` 1.17.1, `bitflags` 2.13.0, `dashmap` 6.2.1, `env_filter` 2.0.0, `jiff` 0.2.31, `jsonschema` 0.46.9, `rmcp` 1.8.0, `shlex` 2.0.1, `time` 0.3.53, `tree-sitter` 0.26.10, `zerocopy` 0.8.52, and the zizmor crate family (`subfeature`, `tree-sitter-iter`, `yamlpatch`, `yamlpath`) 1.26.1. CI (all repinned by commit SHA, batched via the `actions-updates` group, #280): `actions/cache` v5.0.5 to v6.1.0, `actions/setup-python` v6.2.0 to v6.3.0, `taiki-e/install-action` v2.82.0 to v2.82.4, and `zizmorcore/zizmor-action` v0.5.6 to v0.5.7. VS Code extension: `vscode-languageclient` 10.0.0 to 10.0.1 (#278) and `@types/node` 25.9.3 to 26.0.1 (#279), then an `npm update` pass brings the lockfile to `vscode-languageclient` 10.1.0 and `@types/node` 26.1.0; `tsconfig.json` gains an explicit `"types": ["node"]` because TypeScript 6 no longer resolves the Node globals implicitly with this configuration. Docs build (`docs/requirements.txt`): `pymdown-extensions` 11.0.1, `mkdocs-section-index` 0.3.12, `mkdocs-git-revision-date-localized-plugin` 1.5.3, `mkdocs-rss-plugin` 1.19.0, `mkdocs-llmstxt` 0.5.0, and `mkdocs-redirects` 1.2.3, verified with `mkdocs build --strict`. The `rusqlite` 0.39 to 0.40.1 bump (#234) stays held back: it still pulls `libsqlite3-sys` 0.38.1, whose build script needs the `cfg_select!` macro that is unavailable on the pinned MSRV (1.88.0).

### Rule drafting from logs (#286)

Turns exemplar events into a complete draft Sigma rule, the detection-authoring sibling of schema signature discovery: feed the malicious or noteworthy events (optionally contrasted against a baseline corpus of normal traffic) and get back paste-ready standard Sigma YAML to review, edit, and commit. The tool proposes, a human decides; metadata stays as explicit `TODO` placeholders.

* **Drafting core** — a new `rsigma_eval::rule_draft` module profiles every field across the exemplars, drops volatile fields (timestamp-shaped names and values, UUID/GUID shapes, per-event counters, high-entropy unique values), scores the survivors by value stability times baseline rarity, infers a value form and modifier per field (plain equals, OR value list, `endswith`/`startswith` from a shared path tail/prefix, `contains`/`contains|all` from shared tokens with a minimum token length and baseline-generic rejection), escapes literal Sigma wildcards in observed values, splits exemplar variants into `selection_*` groups with `1 of selection_*` when the split is earned, and infers the logsource from the built-in schema classifier (a shared Sysmon EventID maps to its Sigma category). The core is pure and deterministic: the rule `id` is caller-supplied and repeated runs are byte-identical.
* **Verified before emitted** — the draft is parsed and compiled through the real evaluation engine and must match every exemplar (fields that break the match are dropped, bounded by a minimum-field floor; below it the command errors instead of emitting an over-broad rule), the lint catalogue runs over the YAML with findings surfaced as warnings, and the baseline hit count and rate are reported as the estimated false-positive rate.
* **`rule draft`** — the offline command: exemplars via inline JSON, `@file` NDJSON, `@file.evtx` (with the `evtx` feature), or stdin, plus `--baseline @file`. Flags: `--max-fields`, `--min-prevalence`, `--include-field`/`--exclude-field`, `--logsource-category`/`--logsource-product`/`--logsource-service`, `--title`, `--skip-baseline-eval`, and `--emit yaml|report` (default `yaml` prints the rule with the field report on stderr; `report` renders the full analysis through the global output formats). The UUIDv4 `id` is generated at the CLI layer.
* **Docs** — a new `rule draft` CLI page and a Drafting Rules from Logs guide, including the schema-native note: the draft uses the exemplars' native field names, so evaluate it without a mapping pipeline.

### Schema signature discovery (#285)

Turns the unknown-schema signal the schema tooling surfaces into ranked candidate declarative signatures, so operators stop hand-writing every signature from scratch. Pure-Rust, glass-box mining (clustering plus discriminative feature selection); the output is the same `schemas:` YAML the classifier already consumes, so every proposed predicate is human-readable and reviewable. Additive and opt-in throughout; no black-box model, and nothing is applied automatically.

* **Mining core** — a new `rsigma_eval::schema_discovery` module clusters unrecognized events by field-key shape, selects the fields (and low-cardinality, non-sensitive values) that discriminate each cluster with a value-based diversity guard and cardinality-weighted scoring, validates proposals against the built-ins, and renders a paste-ready `schemas:` block that round-trips through `parse_schema_signatures`.
* **`engine discover-schemas`** — an offline command that mines a JSON/NDJSON corpus (excluding events an existing built-in or `--schema-config` signature already recognizes) and prints ranked candidates plus the YAML. Flags: `--schema-config`, `--min-support`, `--similarity`, `--max-candidates`, `--max-predicates`, `--no-value-markers`, `--emit yaml|report`, and `--dry-run` (reclassify the corpus with the proposals loaded and report the before/after per-schema counts).
* **Live daemon surface** — a new `--discover-schemas` flag (implies `--observe-schemas`) enables a separate, redacted, keys-only sampler of unrecognized events, and `GET /api/v1/schemas/suggestions` mines it into presence-only candidate signatures. A new `rsigma_unknown_schema_clusters` gauge tracks how many distinct schemas discovery would propose, refreshed cheaply via a clustering-only count so `/metrics` and `GET /api/v1/schemas` never re-run the full mining pipeline. `DELETE /api/v1/schemas` resets the observer and refreshes the capped discovery sample without a restart. The shipped `unknown_shapes` semantics are unchanged.
* **Docs** — a new `engine discover-schemas` CLI page and schema-routing guide section, plus updates to the daemon CLI, HTTP API, and metrics references.

### Docs

* Added [Rustinel](https://github.com/Karib0u/rustinel), an open-source cross-platform endpoint detection engine, to the `Built with RSigma` section on the docs home page. Rustinel ships RSigma as an opt-in Sigma backend alongside its built-in matcher.

### Schema and logsource routing v2 (#277)

Extends the shipped schema routing and logsource-aware evaluation with richer signatures, schema-derived logsource correctness, authoring tooling, and hardening. All additive and opt-in; existing schema configs and `--logsource-*` invocations behave identically.

* **Schema-derived logsource pruning** — a recognized schema now supplies an event's logsource for conflict-based pruning even when the event carries no explicit `product`/`service`/`category` field, so a Sysmon-classified event prunes Cisco/Linux rules instead of false-positive matching on a mapped field. Built-in implied logsources for the platform-locked `sysmon`, `windows_eventlog`, `ecs_windows`, and `ecs_linux` schemas, overridable per binding with a `logsource:` block. Resolved per event in `SchemaRouter` (explicit fields, then the schema's implied logsource) and fed to a new conflict-based `Engine::evaluate_pruned`.
* **ECS platform specializations and schema aliases** — built-in `ecs_windows`/`ecs_linux` signatures recognize ECS events carrying a platform marker and carry the platform for pruning, while aliasing to `ecs` so existing `ecs` bindings still match them. A general `routing.aliases` map lets an event classified as one schema route as another, so one binding covers a family of related schemas.
* **Richer signature predicates** — numeric comparisons (`gt`/`gte`/`lt`/`lte`), set membership (`in`), cross-field equality (`field_equals_field`), and recursive boolean groups (`not`/`any`/`all`) so a signature can express OR/NOT and value ranges, not only AND of string/presence forms.
* **Custom logsource dimensions** — `logsource_compatible` and `LogSourceExtractor` handle arbitrary `LogSource.custom` dimensions; the `--logsource-field-map` / `--event-logsource` flags and config block accept `custom.<name>=...` entries.
* **`engine classify` tooling** — `--explain` shows per-predicate pass/fail for the matched signature (or the closest near-miss for an unknown event), `--check` statically validates a schema config (unreachable signatures, unknown or duplicate bindings, missing pipeline files) and exits non-zero on findings, and a routing section triggers a per-event routing dry-run.
* **Hardening and visibility** — ambiguous classifications (two different-name signatures tied at the winning specificity) are surfaced in `engine classify` and the `rsigma_events_ambiguous_schema_total` counter; the schema observer samples bounded, redacted field-key shapes of unknown events; `GET /api/v1/schemas` gains `unknown_shapes` and a per-schema `routing_pruning` summary; and new `rsigma_schema_rules_eligible{schema}` / `rsigma_schema_rules_pruned{schema}` gauges plus an `engine eval` end-of-run summary report per-schema pruning.
* **Per-schema rule partitioning (gated, opt-in)** — `--schema-partition-rules` (or `schema.partition_rules`) compiles each platform-locked per-schema engine with only the rules whose product can apply, cutting the N-copies memory cost. Conservative and safe by construction: the default set and any set reachable by a cross-platform schema or whose pipelines rewrite product keep the full ruleset. Off by default; validate against your corpus before enabling.
* **Docs** — a new Schema Signatures reference enumerating every predicate form and its semantics, plus updates across the schema-routing and logsource-routing guides, the classify page, and the configuration, metrics, HTTP API, and library references.

### rstix Pattern Engine: evaluation (Levels 1–3) (#276)

Adds STIX pattern evaluation to the `pattern` feature:

* **`Pattern::evaluate`** — match a parsed pattern against timestamped observations (Levels 2–3: `AND`, `OR`, `FOLLOWEDBY`, `WITHIN`, `REPEATS`, `START`/`STOP`).
* **`Pattern::matches_single`** — Level 1 shortcut for a single top-level observation against one SCO.
* **`Pattern::evaluate_observed_data`** — build `ObservationContext` from `observed-data.object_refs` and evaluate against a bundle.
* **`ObservationContext` / `TimestampedObservation`** — evaluation context with optional bundle for `_ref` dereference.
* **`Pattern::matches_single_with_bundle`** — Level 1 evaluation with optional bundle for `_ref` dereference.
* **`CustomSco`** — vendor/custom SCO types deserialize and evaluate (e.g. `x-usb-device` paths).
* **`TimestampedObservation::at`** — `Option<StixTimestamp>`; temporal patterns return `MissingTimestamp` when any observation lacks a timestamp.
* **Object-path resolver** — full §9.8 paths: extension `sections[*].entropy`, ref lists `resolves_to_refs[*].value`, `body_multipart[*].body_raw_ref.name`, `dst_ref.type`/`value`, binary `payload_bin`, `EXISTS` on registry `values`, nested custom properties.
* **`pattern::security`** — regex compile size limit (1 MiB) enforced during `MATCHES` evaluation.
* **Observed-data** — embedded SRO members in deprecated `objects` are skipped (not an error).
* **Tests** — manifest-driven SCO field coverage (`tests/pattern_eval_sco_fields.rs`, 276 cases), per-operator eval (`tests/pattern_eval_operators.rs`), every `PatternMatchError` path (`tests/pattern_eval_errors.rs`), §9.8 spec eval (`tests/pattern_spec_eval.rs`); 447 tests pass with `pattern,serde`.

Canonical printer, `IndicatorPattern::Stix { ast }` serde wiring, and `fuzz_stix_pattern` remain in the next Pattern Engine slice.

## [0.18.0] - 2026-07-01

**TL;DR**
RSigma v0.18.0 is the "post-engine alerting and detection lifecycle" release: the daemon grows an Alertmanager-style processing stage and an entity risk layer, the toolkit gains the triage, hygiene, and ADS pieces that close the detection lifecycle, content-based schema and logsource routing lands, a data-aware diagnostics toolkit ships, and `rstix` completes its STIX 2.1 data model and gains a pattern engine.
* Post-engine alert processing: an alert pipeline adds deduplication, silencing, inhibition, and incident grouping to the daemon sink path (#255); risk-based alerting scores entities and emits a risk-incident layer (#264); the webhook sink can HMAC-sign every request (#266).
* Detection lifecycle: a triage feedback loop turns analyst dispositions into a live per-rule false-positive ratio (#263); a rule hygiene report surfaces retirement and clean-up candidates (#262); optional ADS metadata gains linter enforcement and an authoring command (#261).
* Schema and logsource routing: content-based schema recognition (#245) and per-schema pipeline routing (#246), plus opt-in conflict-based logsource pruning in the evaluator (#249).
* Diagnostics: an explain-and-introspect toolkit adds detection explain, pipeline transform diff, and correlation window introspection (#270).
* Daemon transport: Unix domain socket support for the input source, output sink, and API listener (#273).
* `rstix` (threat-intel library, not yet independently releasable): completes the STIX 2.1 data model and serialization (#248, #254, #265, #268) and adds a pattern engine that parses and type-checks STIX patterning Levels 1-3 (#272), thanks to @SecurityEnthusiast.
* Fixes, security, and dependencies: jq `halt`/`halt_error` can no longer terminate the process (#247); a transitive `anyhow` bump clears RUSTSEC-2026-0190 (#271); a rolled-up dependency bump (#257); and the CI/CD guide documents `rsigma-action` (#260).

### rstix Pattern Engine: parse and type-check (Levels 1–3) (#272)

Adds the `pattern` feature to `rstix` with a hand-written lexer, recursive-descent parser for STIX patterning Levels 1–3, and an SCO schema type-checker for all 18 cyber-observable types:

* **`Pattern::parse`** — lex, parse, and type-check a pattern string; returns `PatternError` with byte offset (lex/parse) or path (type-check).
* **Grammar** — single observations, top-level `AND` / `OR` / `FOLLOWEDBY`, and Level 3 `WITHIN`, `REPEATS`, and `START`/`STOP` qualifiers.
* **Type-checker** — validates property paths (including `extensions.'…'`, `_ref.type`, dictionary dot keys, custom SCO types), comparison operators, and constant types against per-SCO schemas.
* **Tests** — STIX §9.8 fixture files under `tests/fixtures/pattern/`, acceptance test modules, gap-table regression coverage.

Evaluation, canonical printer, and `IndicatorPattern` AST wiring are **deferred** to later Pattern Engine work (documented in `crates/rstix/README.md` and `docs/library/rstix.md`).

### Unix domain socket support for the daemon (input source, output sink, API listener) (#273)

The daemon now speaks `unix://` on three surfaces (Unix targets only; gated behind the new runtime `uds` feature, which the `daemon` feature enables):

* **`--input unix:///path/to.sock`** ingests newline-delimited events over a Unix domain socket, so co-located log shippers (rsyslog `omuxsock`, syslog-ng `unix-stream`, Vector, Fluent Bit) can feed the daemon without a TCP port or the HTTP-ingest overhead. One reader task per connection feeds the bounded event channel (the same back-pressure model as stdin), with a 1 MiB per-line cap so an unterminated line cannot exhaust memory.
* **`--output unix:///path/to.sock`** (also accepted by `--dlq`) writes NDJSON detections and incidents to a collector listening on a local socket, reconnecting once on a transient write failure before routing to the DLQ.
* **`--api-addr unix:///path/to.sock`** serves the health, metrics, and `/api/v1/*` API (plus OTLP ingestion when built with `daemon-otlp`) over a permission-gated local socket. The socket is created `0600` and unlinked on clean shutdown, and a stale socket left by a crashed run is reclaimed on the next start. TLS terminates on TCP only, so `--tls-cert`/`--tls-key` combined with a `unix://` address is rejected at startup, and a `unix://` address is exempt from the non-loopback plaintext-bind refusal (the socket file is the trust boundary).

On non-Unix targets `unix://` is rejected with the existing unsupported-scheme config error.

### Security: transitive `anyhow` bump for RUSTSEC-2026-0190 (#271)

`cargo deny` flagged [RUSTSEC-2026-0190](https://rustsec.org/advisories/RUSTSEC-2026-0190), an unsoundness in `anyhow`'s `Error::downcast_mut()` where adding context via `Error::context` and then calling `downcast_mut` on the returned error violates borrow rules and triggers undefined behavior. It reaches the tree transitively. A targeted `cargo update -p anyhow` moves the workspace lockfile from 1.0.102 to the fixed 1.0.103 with no other dependency changes.

### Explain and introspect toolkit: detection explain, pipeline diff, correlation introspection (#270)

A data-aware diagnostics suite that answers questions static tooling structurally cannot. Validation, linting, and the LSP operate on rule files with no event data, so they answer "is this rule well-formed?" A rule can be valid and still silently fail to match the event it was written for. This toolkit answers the orthogonal question: given this rule, this event, this pipeline, and this correlation state, why did I get this result? It ships in three independent tiers, all additive with no hot-path change.

* **Detection explain.** A new `rsigma engine explain --rules <path> --event <json|@file|->` runs a non-short-circuiting, bloom-free recording evaluator over one rule and one event and reports, for every condition node and field, whether it matched and why not (field absent, value mismatch with the actual value, case mismatch, existence, no keyword match). The default is an indented human tree with pass/fail markers and a one-line reason per failed leaf; `--output-format json|ndjson` serializes the full trace and `csv|tsv` emit a flat per-leaf table. Optional `-p/--pipeline`, `--rule-id`, and `--show-pipeline` flags mirror the eval surface. The verdict is computed from the same eval primitives the engine uses, so it can never disagree with `engine eval` (pinned by a property test). The new public `rsigma_eval::explain_rule` plus the `RuleExplanation`/`ConditionTrace`/`DetectionTrace`/`ItemTrace`/`MatchReason` model expose the same trace as a library API, reusing the `CompiledMatcher::describe()` helper from match-detail (#186).
* **Pipeline transform diff.** A new `rsigma pipeline diff --rules <path> -p <pipeline>` serializes the rule AST before and after `apply_pipelines_with_state`, prints a unified diff, and lists the applied transformation ids, so a field rename or an `AllOf` to `AnyOf` expansion that a pipeline performs is visible before evaluation. `--output-format json` emits `{ before, after, applied_items, changed }`. The same transformation summary prints before each trace under `engine explain --show-pipeline`. The `pipeline` command group no longer requires the `daemon` feature; only `pipeline resolve` stays gated.
* **Correlation window introspection.** A new read-only `CorrelationEngine::introspect()` (and an id/group filtered variant) projects, per correlation and group, the current aggregate versus the threshold (the gap made explicit), the window contents, the last alert and remaining suppression, and the seconds until the next eviction. It is surfaced offline by `engine eval --dump-correlation-state` (print the final snapshot after replaying an NDJSON file, to stderr so stdout stays machine consumable) and live by two read-only daemon endpoints, `GET /api/v1/correlations` (compiled correlation list with per-group counts) and `GET /api/v1/correlations/state` (per-group window snapshot, filterable by `?id=` and `?group=`). Both compose with schema routing through the shared correlation store.

### Complete rstix Data Model + Serialization phase (#268)

Closes the **Data Model + Serialization** phase for `rstix` with semantic validation, spec-audit alignment on MUST vs SHOULD rules, and remaining model gaps:

* **`Bundle::validate()`** — returns `ValidationReport` with advisory warnings: STIX-W0031 (TLP v1 encoding), SCO deterministic id mismatch, granular-marking selector semantics, language-content field/type/list-length checks, ISO 3166-1 alpha-2 country codes, region open vocabulary, CAPEC/CVE external references, relationship endpoint matrix, and encryption-algorithm closed vocabulary. Parse remains permissive for these SHOULD-level rules.
* **Removed `Bundle::raw_object()`** — unmodeled properties round-trip via `extra_properties` and `common.extra` only.
* **`ObservedDataEmbeddedObject`** — deprecated observed-data `objects` map accepts embedded SCO or SRO members.
* **`common.extra`** on `SdoSroCommonProps` / `ScoCommonProps` — captures unknown top-level keys on standalone leaf deserialize; drained into bundle `extra_properties` during bundle parse.
* **`email-message`** — added `subject_enc` and `body_enc` fields (STIX §6.6.2).
* **Tests:** `tests/validation.rs` with negative fixtures under `tests/fixtures/validation/`.

### STIX domain objects, bundle parse, and reference validation (`rstix`) (#265)

The **Data Model + Serialization** phase adds the full STIX 2.1 domain-object layer and bundle ingestion to `rstix`:

* **19 SDO types** under `model::sdo` with `SdoObject` enum dispatch, per-field rustdoc, `IndicatorPattern` and `ObservedDataForm` enums, typed ref unions, and strict `"type"` deserialize on every leaf type.
* **`StixObject`** top-level enum (SDO / SCO / SRO / Meta / Custom) with `QueryableStixObject` delegation and `x_*` top-level property capture during bundle parse.
* **`Bundle::parse`** / `parse_bundle()` — typed bundle container, duplicate-id rejection, bundle-scoped reference existence and kind checks, relationship matrix validation, `x_*` merge on serialize, bundle id/`spec_version` rules (STIX §8), and `extra_properties()` for vendor extensions.
* **`model/validate.rs`** — shared validators for common props, ref kinds, relationship endpoints (55 STIX 2.1 matrix entries), CAPEC/CVE external refs, and SCO format checks.
* **Fixtures and tests:** rich spec-based fixtures for all 19 SDOs, bundle integration tests, 304 crate tests with `roundtrip_strict` coverage.

Spec-audit alignment: removed stricter-than-spec empty-name and empty-collection checks; added missing ref-kind, meta-object, extension, and bundle rules documented in the crate README invariant table.

### Webhook HMAC request signing (#266)

The webhook sink can now HMAC-sign every outbound request so a receiving endpoint can verify the delivery's authenticity and integrity, and reject replays. Signing is opt-in per webhook through a `signing:` block and is computed over the exact rendered body bytes. It is most useful for the custom and internal relay endpoints an operator controls; the public chat and paging services do not verify a sender HMAC, so it complements the existing per-webhook TLS and bearer-token options rather than replacing them.

* The default `standard` scheme follows the cross-industry Standard Webhooks convention, emitting `webhook-id`, `webhook-timestamp`, and `webhook-signature: v1,<base64 HMAC-SHA256 of "{id}.{timestamp}.{body}">`. A `github` scheme emits `X-Hub-Signature-256: sha256=<hex>` over the body, and a `custom` scheme exposes the header name, algorithm (`sha256`/`sha512`), encoding (`hex`/`base64`), value format, and signed-payload template for receivers like Stripe.
* The HMAC key is read from the environment (`signing.secret_env`), resolved once at startup so a missing key fails the daemon at boot, and is never stored in the webhook YAML. `secret_encoding: base64` decodes a svix-issued `whsec_` secret, and `rotate_secret_env` emits a second signature for the duration of a key rollover (the `standard` and `custom` schemes).
* The id, timestamp, and signature are minted once per delivery and reused on every retry, so a receiver dedupes redeliveries on `webhook-id` and enforces a replay window on `webhook-timestamp`. This rides on a new per-delivery `DeliveryContext` threaded through the shared sink delivery layer (a `DeliverySink::deliver` signature change).

### Risk-based alerting: per-entity risk scoring and a risk-incident layer (#264)

A new optional post-engine daemon capability that shifts the unit of alerting from the individual detection to the entity it touches, modeled on Splunk RBA and Entity Risk Scoring. It runs in the sink path after enrichment and before the alert pipeline, so the evaluation hot path is untouched, and it is off until `--risk <path>` (or `daemon.risk`) is set.

* Stage one annotates every in-scope firing with an integer risk score and one or more risk objects (entities such as `user`, `host`, `src_ip`). The score follows a documented precedence: the `rsigma.risk_score` custom attribute, then a `tag_scores` map (exact tag or a `prefix.*` wildcard, reduced by `sum` or `max`), then a `level_scores` map, then `default_score`. Risk objects are extracted with the shared field-selector namespace (`rule`, `level`, `event.<path>`, `match.<field>`, `enrichment.<path>`, `correlation.group_key.<field>`), so one firing can raise risk on several entities and enrichers can supply entity context. The score and objects are injected into `header.enrichments` under the reserved `risk.score` / `risk.objects` keys.
* With `emit_risk_events: true`, the layer also emits a compact risk event per `(detection, risk object)` pair, disambiguated on the wire by a `risk_event` key and optionally routed to a dedicated NATS subject. `event.<path>` selectors require a retained event, with the same `strip_event` escape hatch as the alert pipeline.
* Stage two (the `incident` block) runs a per-entity sliding-window accumulator that sums risk and tracks the distinct ATT&CK tactic count (from `attack.<tactic>` tags) and the distinct contributing-source count. A `RiskIncidentResult` fires when an entity crosses `score_threshold` or `tactic_count_threshold` over the window, subject to a per-entity `cooldown`. The incident is one flat NDJSON object disambiguated by a `risk_incident_id` (UUIDv4), carrying the entity, the window score, the contributing tactics and sources, the window bounds, the `trigger`, and the top contributing detections (`include: refs | results`); it is delivered through the existing incident sink path with an optional dedicated subject. The accumulator is bounded by `max_open_entities`, `max_sources_per_entity`, and `max_results_per_incident` with eviction accounting, and ages entries out on the sink-task tick.
* Config hot-reloads on `SIGHUP`, file-watcher changes, and `POST /api/v1/reload`, keeping the previous config on a failed reload; in-flight accumulators survive the swap. Open entities are readable at `GET /api/v1/risk`.
* State persists across restarts when `--state-db` is set: a versioned `RiskStateSnapshot` is saved to the SQLite store in its own `rsigma_risk_state` table on the periodic and shutdown hooks beside the correlation and alert-pipeline snapshots, and restored on boot with window-aware pruning. `--clear-state` skips the restore; a version mismatch starts fresh with a warning.
* Nine pre-registered Prometheus metrics: `rsigma_risk_annotations_total{action}`, `rsigma_risk_annotation_score`, `rsigma_risk_objects_total`, `rsigma_risk_entities_open`, `rsigma_risk_state_entries`, `rsigma_risk_evictions_total`, `rsigma_risk_incidents_emitted_total{trigger}`, `rsigma_risk_incident_results_total`, and `rsigma_risk_layer_duration_seconds`.
* The field-selector resolver moved to a shared crate-level `rsigma_runtime::selector` module so the alert pipeline and the risk layer share one implementation; `rsigma_runtime::Selector` and `rsigma_runtime::alert_pipeline::Selector` are unchanged.

### Triage feedback loop: analyst dispositions and a per-rule false-positive ratio (#263)

A new opt-in daemon capability that captures analyst verdicts on the alerts a ruleset produces and turns them into a live per-rule false-positive ratio, the canonical SOC detection-quality metric. It is a measurement loop, not a case manager: it ingests a verdict and emits a ratio. Enabled with `--enable-dispositions` or `daemon.dispositions.enabled: true`; off by default, so existing deployments are unchanged.

* A disposition is one JSON object: `rule_id` (required, with the title fallback the per-rule metrics use), `verdict` (`true_positive`, `false_positive`, or `benign_true_positive`), an optional `scope` (`detection` default or `incident`), optional `fingerprint` and `incident_id` alert identities, an optional RFC 3339 `timestamp` (default ingest time), and optional `analyst` and `note` for traceability. An `incident`-scoped verdict with no `rule_id` resolves to the incident's contributing rules through the live alert-pipeline incident map.
* `POST /api/v1/dispositions` accepts a single object, a JSON array, or NDJSON, and returns an ingest summary (`accepted`, `duplicate`, `rejected`, plus per-record errors). `GET /api/v1/dispositions` returns the per-rule view (counts and the ratio) plus the active window, numerator, and minimum sample.
* The ratio per rule is `false_positive / total_dispositioned` over a rolling window (daily buckets, default 30 days), suppressed until the rule reaches `daemon.dispositions.min_sample` (default 5) so a single false positive cannot publish a misleading 100%. Whether `benign_true_positive` counts toward the numerator is the `daemon.dispositions.numerator` knob (`fp_only` default, or `fp_and_btp`).
* Two ingestion paths: the `POST` endpoint, and an optional pull source (`--disposition-source`, or `daemon.dispositions.source`) that reads a dynamic-source file (file, HTTP, or NATS) whose payload is the disposition records, refreshed per the source's policy. Redelivery is idempotent: dispositions dedup on `(fingerprint or incident_id, verdict)`, falling back to `(rule_id, timestamp, analyst)` when no alert identity is carried, so a file re-read, a NATS redelivery, or an HTTP re-poll never double counts.
* Four Prometheus metrics: `rsigma_rule_false_positive_ratio{rule_title}` (gauge, absent until the minimum sample), `rsigma_dispositions_total{rule_title,verdict}`, `rsigma_disposition_ingest_total{source,result}`, and `rsigma_disposition_ingest_errors_total{reason}`.
* State persists across restarts when `--state-db` is set: a versioned `DispositionSnapshot` is saved to the SQLite store in its own `rsigma_disposition_state` table on the periodic and shutdown hooks beside the correlation and alert-pipeline snapshots, and restored on boot with window-aware pruning (buckets past the window are dropped). `--clear-state` skips the restore; a version mismatch starts fresh with a warning.
* The same ratio feeds the `rule scorecard` command: the `GET /api/v1/dispositions` view deserializes directly as the scorecard's `--triage` input (a `rules` array keyed by `rule_id` carrying the true/false-positive counts and the derived `fp_ratio`), the schema this loop owns and finalizes.
* The store is orthogonal to the eval and sink paths (fed only by its ingestion paths), so it cannot affect detection throughput. Config lives under `daemon.dispositions` (`enabled`, `source`, `window`, `numerator`, `min_sample`).

### Rule hygiene and retirement report (#262)

A new `rsigma rule hygiene` subcommand assembles the signals rsigma already produces into one report of retirement and clean-up candidates, the detection-lifecycle phase the toolkit did not yet touch. It runs no evaluation: the static signals read off the parsed rules, the data-driven signals join optional snapshots. The feature is additive and ships with no new dependencies.

* **Signals.** Seven, in one report: never-fired (silence) and noisy (a robust median-plus-MAD outlier test, with an absolute `--noisy-threshold` override) over a Prometheus snapshot or endpoint window; untagged (the same `attack.*` notion `rule coverage` uses, via a shared extractor); no-owner (from a `custom_attributes` `owner` key or the `author` field); incomplete-ads (a `stable` detection rule missing required ADS sections, mirroring the lint default bar); broken-fields (a rule whose referenced fields are all in a field-observability snapshot's never-seen set); and deprecated/stale (`status: deprecated`/`unsupported`, or a `modified`/`date` older than `--stale-threshold`).
* **Command.** `rsigma rule hygiene --rules <PATH>... [--metrics <FILE|URL>] [--metrics-window <DUR>] [--corpus <PATH>] [--fields <FILE>] [--silent-threshold <DUR>] [--stale-threshold <DUR>] [--noisy-threshold <N>] [--report <FILE>] [--fail-on <COND>]...`, under the `rule` group. Only `--rules` is required; the static signals need nothing else, and `--corpus` is the offline alternative to `--metrics` for the silence and noisy signals. The report renders through the global output-format layer (TTY table, json/ndjson/csv/tsv) plus a `--report` JSON file, and a repeatable `--fail-on` (`silent`, `noisy`, `untagged`, `no-owner`, `incomplete-ads`, `broken-fields`, `deprecated`, or `any`) exits `1` under the house exit-code scheme. A `hygiene` config section carries the inputs, thresholds, and the gate default.
* **Internals.** The ATT&CK tag extraction and the Prometheus exposition reader plus metrics loader were lifted into shared `crate::rule_meta` and `crate::metrics_source` modules that `rule coverage` and `rule scorecard` now consume, so the commands cannot drift on what "untagged" means or on how the per-rule counters are parsed. Behavior-neutral; the existing coverage and scorecard tests (and the promtext fuzz target) are unchanged.

### ADS detection-strategy metadata and lint (#261)

Optional [Palantir Alerting and Detection Strategy (ADS)](https://github.com/palantir/alerting-detection-strategy-framework) metadata on Sigma rules, with enforcement in the linter and a new authoring command. The whole feature is additive metadata plus reads over it: no engine, eval, or hot-path changes, and no new dependencies.

* **Schema.** The nine ADS sections map onto a rule's existing fields where they fit (goal from `description`, categorization from `attack.*` `tags`, false positives from `falsepositives`, priority from `level`) and carry the rest under a new `rsigma.ads.*` custom-attribute namespace (`strategy`, `technical_context`, `blind_spots`, `validation`, `priority` rationale, `response`). Values are pure documentation the engine never interprets. A per-rule `rsigma.ads.exempt: true` opts a rule out of enforcement. A single source-of-truth catalogue lives in `rsigma-parser` (`ads::ads_catalogue()`), modeled on the lint catalogue.
* **Lint.** Eleven new lint rules in the built-in linter, opt-in via an `ads:` block in the layered `.rsigma-lint.yml` (`enforce_status`, `required`, `severity`): one `ads_missing_*` per section, `ads_empty_section` for a present-but-blank section, and `ads_unknown_section` for a typo under `rsigma.ads.*` (with a safe `--fix` rename). The checks fire only on detection rules whose `status` is in the configured enforce set (default `[stable]`) and reuse the existing catalogue, severity model, suppression, and `tag_namespaces` setting. The lint catalogue grows to 86 rules.
* **Command.** A new `rsigma rule doc` subcommand reports each rule's present and missing ADS sections through the global `--output-format` layer or as a canonical `--format markdown` document, with `--missing-only` for the CI view and `--scaffold`/`--in-place` to prefill the `rsigma.ads.*` sections. `--fail-on-missing` makes it a standalone CI gate under the house exit-code scheme; a `doc` config section carries the gate default.
* **MCP.** A new `author_ads` tool returns a rule's current and missing ADS sections plus a scaffold for an agent to complete, and a `rsigma://ads/schema` resource exposes the section catalogue alongside `rsigma://lint/catalogue`.

### Documentation: rsigma-action in the CI/CD guide (#260)

The [CI/CD guide](https://timescale.github.io/rsigma/guide/ci-cd/) and the README now document [`timescale/rsigma-action`](https://github.com/timescale/rsigma-action), the one-step GitHub Actions gate that wraps `rule lint`, `rule validate`, a merge-base fields-drift diff, `rule backtest`, and `rule coverage` into a single pull-request check with diff annotations, a sticky summary comment, and SLSA-attestation-verified cached binary installs. The manual multi-job workflow stays as the no-third-party-action and other-CI fallback.

### Alert pipeline (#255)

A new optional post-engine stage in the daemon sink path, between enrichment and the sinks, configured with `--alert-pipeline <path>` (or the `daemon.alert_pipeline` config key) and hot-reloaded on `SIGHUP`, file-watcher changes, and `POST /api/v1/reload`; a failed reload keeps the previous pipeline active. It deduplicates results by a configurable fingerprint, modeled on Alertmanager: the first fire passes through and opens an active alert, subsequent fires fold into it, the alert re-emits on `repeat_interval` carrying the accumulated fire count, and it emits a final `resolved` record after `resolve_timeout` and is evicted.

* Fingerprints are built from a shared field-selector namespace over `EvaluationResult`: `rule`, `level`, `event.<path>`, `match.<field>`, `enrichment.<path>`, and `correlation.group_key.<field>`. A malformed selector rejects the daemon at startup with an error naming the offending selector.
* `scope` (rules / tags / levels) restricts which results the layer acts on; out-of-scope results pass through untouched. `strip_event` retains the event for selector resolution then drops raw event payloads before delivery. `repeat_interval: 0` gives pure suppression with a single resolved summary on expiry.
* The active-alert store is bounded by `dedup.max_active_alerts` (default 100000): once full, a first-fire for a new fingerprint passes through un-deduped rather than growing the store, so a high-cardinality fingerprint cannot exhaust memory.
* Re-emit and resolved records ride the existing NDJSON wire shape, disambiguated by a `dedup_state` key in `enrichments` (alongside `dedup_fingerprint`, `dedup_fire_count`, `dedup_first_seen`, `dedup_last_seen`, and `dedup_fields`).
* The `Scope` filter moved to a shared crate-level `rsigma_runtime::scope` module; the `enrichment` module re-exports it, so `rsigma_runtime::Scope` and `rsigma_runtime::enrichment::Scope` are unchanged.

A second stage groups dedup survivors into incidents. It assigns each survivor to an incident, annotates the pass-through result with `incident_id` in `enrichments`, and emits a higher-level `IncidentResult` on the Alertmanager timers.

* Two modes: `group_by` (default) groups by equality on a selector list with a deterministic incident id stable across restarts; an opt-in `entity_graph` union-find merges incidents sharing an entity value, guarded against the giant-component failure by a `stop_values` list and a per-value `max_value_cardinality` ceiling.
* Incidents emit on `group_wait` (initial batch), `group_interval` (updates), and `repeat_interval` (re-emit), and emit a final `resolved` record after `resolve_timeout`. `include: refs | results` controls how much contributing detail is embedded, bounded by per-incident caps.
* `IncidentResult` is one flat NDJSON object disambiguated by an `incident_id` key, delivered via an additive `Sink::send_incident` across stdout/file/NATS (with an optional `nats_subject` override routing incidents to a dedicated subject); OTLP and webhook sinks do not receive incidents. Open incidents are readable at `GET /api/v1/incidents`.
* Nine Prometheus metrics across both stages: `rsigma_dedup_results_total{action}`, `rsigma_dedup_store_entries`, `rsigma_dedup_evictions_total`, `rsigma_dedup_summaries_emitted_total`, `rsigma_incidents_open`, `rsigma_incidents_emitted_total{trigger}`, `rsigma_incident_results_total`, `rsigma_incident_overmerge_total{guard}`, and `rsigma_alert_pipeline_duration_seconds`.

A silencing stage mutes results matching operator-defined matchers before dedup, modeled on Alertmanager silences.

* A matcher is `selector <op> value` over the field-selector namespace, with the `=`, `!=`, `=~`, `!~` operators (regex anchored); a matcher set is ANDed. The matcher engine is shared with the forthcoming inhibition stage.
* Silences carry a time window (optional RFC 3339 `starts_at`/`ends_at`), a derived `pending`/`active`/`expired` state, and an origin: `static` silences declared under `silences:` in the config (re-seeded on hot-reload) and `api` silences created at runtime over `POST /api/v1/silences`. Expired silences are garbage-collected.
* New endpoints: `GET`/`POST /api/v1/silences` and `DELETE /api/v1/silences/{id}`. A muted result is acked and dropped before dedup, so it neither emits nor opens an incident. Dynamic (API) silences are bounded by `max_silences` (default 1000); creation past the cap returns `429`.
* Two metrics: `rsigma_silenced_total` and `rsigma_silences_active`.

An inhibition stage mutes a target result while a matching source is active, modeled on Alertmanager `inhibit_rules`.

* Config-driven `inhibit_rules`, each `{ source_match, target_match, equal, duration }` reusing the matcher engine. While a result matching `source_match` has been seen within `duration`, any result matching `target_match` sharing the same `equal` selector values is muted.
* Carries Alertmanager's self-inhibition guard (a result matching both sides does not inhibit itself) and is non-transitive: a silenced source still inhibits its targets (the active-source index is updated from every non-inhibited result before silencing), but an inhibited target does not become a source.
* Two metrics: `rsigma_inhibited_total{rule}` and `rsigma_inhibit_sources_active`.

The alert pipeline persists its state across restarts when `--state-db` is set.

* A versioned `AlertPipelineSnapshot` (active dedup alerts, open incidents, dynamic silences, and the inhibition active-source index) is saved to the existing SQLite store in its own `rsigma_alert_pipeline_state` table, on the periodic and shutdown hooks beside the correlation snapshot, and restored on boot.
* Restore is window-aware: dedup alerts past `resolve_timeout`, incidents past their `resolve_timeout`, silences past `ends_at`, and inhibition sources past their rule's `duration` are pruned. Deterministic `group_by` incident ids survive the restart; a version mismatch starts fresh with a warning. `--clear-state` skips the restore and `--keep-state` forces it, matching the correlation-state flags.

### rstix: SCO per-field rustdoc (#254)

* Per-field documentation on all 18 SCO types, 12 predefined extensions, and nested public structs (`EmailMimePart`, `WindowsRegistryValue`, `X509V3Extensions`, PE header/section types, etc.).
* Removed `#![allow(missing_docs)]` from `model::sco` and `model::sco::extensions`; strict `cargo doc` now enforced for the SCO surface.
* Runnable `# Examples` on representative types using spec fixtures.

### rstix: STIX cyber-observable (SCO) model (#248)

All 18 STIX 2.1 cyber-observable types land in `model::sco` with strict fixture-backed round-trips:

* **Types:** `artifact`, `autonomous-system`, `directory`, `domain-name`, `email-addr`, `email-message`, `file`, `ipv4-addr`, `ipv6-addr`, `mac-addr`, `mutex`, `network-traffic`, `process`, `software`, `url`, `user-account`, `windows-registry-key`, `x509-certificate`.
* **Dispatch:** `ScoObject` (`#[non_exhaustive]`) delegates `QueryableStixObject`; `created()` / `modified()` always `None` for SCO arms.
* **Typed ref unions:** `DomainNameResolvesToRef`, `DirectoryContainsRef`, `NetworkTrafficEndpointRef`, `EmailMimeBodyRawRef` with cross-type negative fixtures.
* **Extensions:** 12 predefined SCO extensions under `model::sco::extensions` (`archive-ext`, `ntfs-ext`, `pdf-ext`, `raster-image-ext`, `windows-pebinary-ext`, `http-request-ext`, `icmp-ext`, `socket-ext`, `tcp-ext`, `unix-account-ext`, `windows-process-ext`, `windows-service-ext`) validated from parent `validate()`.
* **Invariants:** `ModelError` variants for enforced SCO rules; integration tests in `tests/spec.rs` use `roundtrip_strict`.


### Logsource-aware evaluation (#249)

Opt-in, conflict-based logsource pruning in the evaluation engine (`rsigma-eval`). `Engine::set_logsource_extractor` installs a `LogSourceExtractor` that derives each event's logsource from configurable fields (defaulting to `product`/`service`/`category`) plus optional static defaults, and the engine then skips any candidate rule whose logsource conflicts with the event's before matching. Disabled by default with the hot path unchanged, and fail-open: an event with no extractable logsource is evaluated against every rule.

* Conflict-based, not subset: a rule is skipped only when a dimension (`product`, `service`, or `category`) is set on both the rule and the event and the values differ, so an event tagged only `product: windows` skips `product: linux` rules while still evaluating Windows-category and logsource-less rules. This is distinct from the existing subset `logsource_matches`, which is unchanged.
* Backed by a product-partitioned rule index, so always-evaluated rules of a conflicting product are never iterated rather than filtered after matching; `service` and `category` remain a residual filter. Evaluation of a product-tagged event against a ruleset split across products drops roughly in proportion to the conflicting fraction.
* `--logsource-routing` on `engine eval` and `engine daemon` enables pruning; `--logsource-field-map product=...,service=...,category=...` remaps the event field names each dimension is read from; `--event-logsource product=windows,...` sets a static logsource for a single-source pipeline. The same keys live under a `logsource_routing` block in the `daemon` and `eval` config sections, with the usual CLI > env > file precedence. Schema routing and logsource pruning compose: each routed per-schema engine prunes its own candidates.
* EVTX-only format default: `engine eval -e @file.evtx` supplies `product: windows` when no explicit or static product is configured. Ambiguous wire formats (JSON, syslog, logfmt, CEF, OTLP) never infer a product, so a conflict-based misprune cannot silently drop rules.
* Two Prometheus counters on the daemon: `rsigma_rules_pruned_by_logsource_total` and `rsigma_events_without_logsource_total` (fail-open visibility).
* Correlation inherits the pruning, since `CorrelationEngine` evaluates through the same engine; hot-reload carries the extractor across engine swaps.

### Schema-aware routing (#246)

`--schema-routing` on `engine eval` and `engine daemon` classifies each event and routes it to the pipeline-set bound to its schema, instead of applying one pipeline set to every event. Bindings come from the `routing:` section of `--schema-config` (`bindings`, `default_pipelines`, `on_unknown`); `--on-unknown` overrides the unknown-handling policy (`warn`, `drop`, `passthrough`, `error`).

* Multi-engine dispatch: one detection engine is built per distinct pipeline-set; each event is classified, then evaluated against the engine for its schema's bound pipelines, with a default-set fallback for known-but-unbound and unknown schemas. Batch detection across events runs in parallel (under the `parallel` feature); correlation stays sequential.
* Unified cross-schema correlation: detections from every per-schema engine feed one shared correlation store, and group-by extraction is schema-aware, so the same entity (a user, host, or IP) correlates across schemas even when each schema names the field differently (for example ECS `user.name` versus `User`).
* Hot-reload rebuilds the per-schema engines and carries the shared correlation state across the swap. Dynamic (`${source.*}`) pipelines bound to a schema are resolved at load time and on hot-reload, with the same fail-closed policy as non-routing pipelines.
* Config-file support: the schema flags map to a `schema` block under both `daemon` (`observe`, `routing`, `config`, `on_unknown`) and `eval` (`routing`, `config`, `on_unknown`) in the layered config, a flag always winning over the file.

### Schema-aware log source recognition (#245)

Content-based schema classification that recognizes the structure of each event from its marker fields and values rather than its wire format, so a mixed JSON stream of ECS, flat Sysmon, rendered Windows Event Log, CEF, and OCSF events can be told apart.

* `engine classify`: a diagnostic that reads a single event, an NDJSON file, or stdin and reports the recognized schema (or `unknown`) per event plus a per-schema summary, rendered through the global output-format layer. `--schema-config` merges user-defined signatures over the built-ins.
* Daemon schema observability: `--observe-schemas` classifies every event and exposes the per-schema breakdown and unknown rate over `GET /api/v1/schemas` and the `rsigma_events_by_schema_total{schema}` and `rsigma_events_unknown_schema_total` metrics. An optional `--schema-config` merges user signatures over the built-ins.
* Declarative signatures (field present/absent, any-of, equals, regex) live in `rsigma-eval`; built-ins cover ECS, OCSF, rendered Windows Event Log, Sysmon, CEF, and a low-specificity `generic_json` fallback. An event matching no signature is reported as `unknown`, the signal for an unsupported schema.

### Fixed

* jq extract expressions can no longer terminate the process. The `halt` and `halt_error` filters are implemented in `jaq-std` with `std::process::exit`, so a single source or enrichment expression could take the whole engine down; both are now removed from the supported filter surface and surface as an ordinary expression error instead (#247).

### Dependency bumps (#257)

Rolls up the open Dependabot PRs into a single merge, regenerating the lockfiles against current `main` rather than replaying stale lockfile bases. Rust (workspace `Cargo.lock`): `opentelemetry_sdk` 0.32.0 to 0.32.1 (#256), `jaq-core` 3.0.0 to 3.1.0 (#235), `jaq-json` 2.0.0 to 2.0.1 and `jaq-std` 3.0.0 to 3.0.1 (#258), `insta` 1.47.2 to 1.48.0 (#233), `evtx` 0.11 to 0.12.2 (#232), and the `patch-updates` group (#253) `regex` 1.12.3 to 1.12.4, `daachorse` 3.0.1 to 3.0.2, `time` 0.3.47 to 0.3.49, `prost` 0.14.3 to 0.14.4, `getrandom` 0.4.2 to 0.4.3, and `uuid` 1.23.2 to 1.23.3 (the `getrandom` bump drops the `wit-bindgen`/`wasi` build toolchain 0.4.2 pulled in); `regex` 1.12.3 to 1.12.4 in `fuzz/Cargo.lock` (#229). CI (all repinned by commit SHA, batched via the `actions-updates` group, #252): `actions/checkout` v6.0.3 to v7.0.0, `taiki-e/install-action` v2.81.4 to v2.82.0, and `rust-lang/crates-io-auth-action` v1.0.4 to v1.0.5. VS Code extension: `@types/node` 25.9.1 to 25.9.3 and `@types/vscode` 1.120.0 to 1.125.0 (#251), plus the transitive `form-data` 4.0.5 to 4.0.6 (#224), `js-yaml` 4.1.1 to 4.2.0 (#225), `markdown-it` 14.1.1 to 14.2.0 (#226), and `undici` 7.25.0 to 7.28.0 (#236). The `rusqlite` 0.39 to 0.40.1 bump (#234) is held back: it pulls `libsqlite3-sys` 0.38.1, whose build script needs the `cfg_select!` macro that is unavailable on the pinned MSRV (1.88.0).

[v0.17.0...v0.18.0](https://github.com/timescale/rsigma/compare/v0.17.0...v0.18.0)

## [0.17.0] - 2026-06-23

**TL;DR**
RSigma v0.17.0 is the "detection-engineering toolkit" release: the rule-side reporting suite that closes the program loop, plus the daemon output-delivery layer and live daemon introspection.
* Detection-engineering reports: `rule backtest` replays an event corpus against a ruleset and diffs per-rule fire counts against declared expectations (#216); `rule coverage` maps a ruleset onto MITRE ATT&CK, exports a Navigator layer, and reports coverage gaps (#221); `rule visibility` turns the field-observability signal into a DeTT&CT administration pair and a visibility Navigator layer (#242); `rule scorecard` fuses backtest precision/recall, coverage, and fire volume into per-rule keep/tune/retire verdicts (#243).
* Output delivery: detection results now flow through a per-sink async delivery layer with bounded queues, retry/backoff, batching, and an at-least-once ack-join across fan-out (#222); an OTLP output sink exports detections over OTLP/HTTP and OTLP/gRPC (#223); a generic, template-driven webhook sink delivers to Slack, Teams, Discord, PagerDuty, or any HTTP endpoint (#227).
* Daemon introspection: `engine status` queries a running daemon from the command line (#237), `engine tap` records a redactable, replayable live event fixture (#238), and `engine tail` streams live detections to the terminal (#239).
* Conversion reach: `backend convert` resolves targets native-first and delegates anything without a native backend to an installed sigma-cli, reaching the full pySigma backend ecosystem with no new dependency (#241).
* `rstix`: Phase 2 adds STIX meta objects (#213) and relationship/sighting objects (#220), thanks to @SecurityEnthusiast; the crate is not releasable on its own yet.
* Fibratus conversion fixes: emit the required `version` field so converted rules load (#219), and map `file_access`/`file_event`/`create_remote_thread` to their idiomatic macros (#217), thanks to @rabbitstack.
* Faster NATS and daemon integration tests: deterministic waits replace fixed sleeps and long-poll timeouts, cutting each suite's runtime by roughly 7x with no production code changes (#240).
* Security: bump the transitive `quinn-proto` (via `reqwest`) to 0.11.15 to clear RUSTSEC-2026-0185, a high-severity remote memory exhaustion advisory.

### `rule scorecard`: fuse the rule-side reports into per-rule keep/tune/retire verdicts (#243)

A new `rsigma rule scorecard` subcommand fuses the toolkit's existing rule-side outputs into the per-rule keep/tune/retire verdict table a detection program reviews on a cadence. It reads JSON the toolkit already emits, so it adds no new collection or evaluation: it is an offline fusion-and-verdict layer over already-aggregated reports.

- **Inputs and the join.** Joins the `rule backtest` report (precision proxy, recall, the corpus false-positive signal, per-rule fire counts) and the `rule coverage` report (per-rule ATT&CK mapping and the per-technique rule count for sole-coverage analysis), both required, into a per-rule record keyed by `rule_id`. Optionally enriches it with a Prometheus production-volume snapshot or `/metrics` endpoint (`--metrics`, joined by `rule_title` with colliding titles summed and flagged), a Prometheus query-API range window (`--metrics-window`) for last-fired, and a triage disposition feed (`--triage`) for the live false-positive ratio and MTTD/MTTR. Every cell records which input supplied it, and a missing optional input degrades the verdict rather than blocking it.
- **Verdict model.** Bands default to the SOC quality-metrics thresholds and are configurable through flags and the `scorecard` config section: retire on a precision proxy below the retire floor (`0.10`) or zero volume across the corpus and the metrics window (a dead rule), tune on the review band or a live false-positive ratio over the ceiling (`0.50`), keep on a healthy precision proxy (`0.80`) with enough volume and a recent fire. A retire candidate that is the sole coverage for an ATT&CK technique is downgraded to tune with a coverage-risk note, so the program never silently drops coverage.
- **Output and CI.** Renders through the global `--output-format` layer (table on a TTY, json/ndjson/csv/tsv) plus a `--report` markdown or HTML program artifact grouped by verdict (extension dispatch, `--report-format` override). `--fail-on <none|tune|retire>` turns it into a CI gate. Exit codes follow the house scheme: `0` success or under policy, `1` verdicts hit `--fail-on`, `2` an input is missing or unfetchable, `3` a bad flag or a malformed/version-mismatched report.
- **Config.** A `scorecard` config section follows the layered-config conventions: the verdict thresholds carry single-source defaults (pinned to the clap flags by a drift-guard test), and every input (including the two required reports, `scorecard.backtest`/`scorecard.coverage`) and the report path can be supplied from the config file. Relatedly, `rule coverage` now also accepts its rule paths from `coverage.rules`.
- **No new dependencies.** The Prometheus exposition-snapshot parser is hand-rolled (the single new untrusted-input surface, fuzzed by `fuzz_scorecard_promtext`); the query-API path reuses the existing `ureq` client. The backtest and coverage reports deserialize through structs shared with their producers, so the consumer and producers cannot drift.

### `rule visibility`: DeTT&CT export and a visibility Navigator layer (#242)

A new `rsigma rule visibility` subcommand turns the shipped field-observability signal into the two artifacts blue teams consume for data-source maturity: a [DeTT&CT](https://github.com/rabobank-cdc/DeTTECT) administration pair and a visibility ATT&CK Navigator layer. Where `rule coverage` reports the detection axis ("which techniques your rules detect"), `rule visibility` reports the data axis ("which fields and logsources you actually see"), and the two Navigator layers stack to expose data-without-detection and detection-without-data cells.

- **Inputs and the join.** Joins the rule logsource inventory and rule field set (from `--rules`) with the observed field signal (`--observed <file|->`: the `engine eval --observe-fields` JSON, a saved `GET /api/v1/fields` snapshot, or stdin; or `--addr` for a live daemon) through a bundled, overridable mapping table (`--mapping[=<path|url>]`). With no observed signal the command reports the rule-expected baseline.
- **Mapping table.** A curated `logsource/field -> ATT&CK data source/data component/technique` table ships in-repo so the default invocation needs no network; `--mapping` reads a local JSON table or fetches a URL through the same 7-day cache the lint schema download uses. Rule logsources the table does not recognize are surfaced as a hygiene list.
- **Scoring.** Visibility rides DeTT&CT's 0-to-4 scale, derived from the fraction of a data source's mapped rule fields that were observed. A data source whose mapped fields are all unobserved is a blind spot; an observed source no rule consumes is untapped. Scores are conservative seeds marked for analyst review, with `data_quality` dimensions carrying the seed value rather than fabricated precision.
- **Outputs.** Writes a DeTT&CT data-source administration YAML (`--dettect-data-sources`), a technique-administration YAML (`--dettect-techniques`, visibility axis only), and a format 4.5 visibility Navigator layer (`--navigator`, scored 0-4). The report renders through the global `--output-format` layer (table/json/ndjson/csv/tsv).
- **CI signal.** `--fail-on-blind-spots` exits `1` when a rule-expected data source has no observed telemetry. A `visibility` config section (`mapping`, `fail_on_blind_spots`) follows the layered-config conventions.

### Reuse pySigma backends through sigma-cli delegation (#241)

`rsigma backend convert` now resolves targets native-first: it uses a native rsigma backend when one exists and otherwise delegates the conversion to an external [sigma-cli](https://github.com/SigmaHQ/sigma-cli) when one is installed, so the full pySigma backend ecosystem (`splunk`, `elasticsearch`, `kusto`, `qradar`, `loki`, `crowdstrike`, and 30+ more) is reachable from the same command. It is a light subprocess wrapper with no new dependencies; no Python runtime is required unless a delegated target is actually used.

- **Native-first dispatch.** `postgres`/`postgresql`/`pg`, `lynxdb`, and `fibratus` keep converting natively and always win; any other target is delegated. A future native backend transparently supersedes its delegated path.
- **Discovery.** sigma-cli is found via the `RSIGMA_SIGMA_CLI` path override or a bare `sigma` on `PATH`. When a target has no native backend and sigma-cli is absent, the command exits `3` with install guidance (`pipx install sigma-cli`, `sigma plugin install <target>`).
- **Flag mapping.** `-t`, `-f`, `-p`, `--without-pipeline`, `-s`, and `-O key=value` pass through to `sigma convert` verbatim; `-O correlation_method=<m>` maps to sigma-cli's `-c/--correlation-method`. The original rule files are handed to sigma-cli, which parses, pipelines, and converts them.
- **Output.** sigma-cli stdout is relayed through the normal output handling (stdout, `-o <file>`, and the `--output-format json` envelope). A non-zero sigma-cli exit maps to `2` with its stderr relayed; a missing binary or a directory `--output` in delegated mode maps to `3`.
- **Listing.** `backend targets` appends the installed sigma-cli targets, and `backend formats <target>` shows a delegated target's formats.
- **Scope.** CLI `backend convert` only; the MCP `convert` tool and the `rsigma_convert` library API convert with native backends. rsigma builtin pipeline names (`ecs_windows`, `sysmon`) are not translated; pass sigma-cli pipeline names or YAML paths in delegated mode.

### Faster NATS and daemon integration tests (#240)

The `nats_integration`, `cli_daemon_nats`, and `cli_daemon_dynamic` suites spent most of their wall time waiting on fixed sleeps and long-poll timeouts rather than doing real work. Replacing those with deterministic waits cuts each suite's runtime by roughly 7x (30.7s to ~2.7s, 15.1s to ~4.4s, and 4.2s to ~1.9s) with no production code changes.

- **Shared-consumer NATS test.** The first consumer's `messages()` pull stream prefetches the whole batch, so the second consumer in the shared group starved and its `recv()` blocked for the full ~30s pull-consumer expiry, which alone took the entire suite. Each receive is now bounded with a short timeout while still asserting that a consumer in the group receives a message.
- **NATS daemon state tests.** The state-restore tests poll the SQLite state DB until the source position is persisted instead of sleeping a fixed 3s, the backward-replay test collects only the message it inspects (it was blocking the full timeout waiting for a second message a clean run never emits), and the no-output check uses an ordered canary detection rather than a fixed wait window.
- **Dynamic-pipeline tests.** Event ingestion, `/api/v1/reload`, and `/api/v1/sources/resolve` are all asynchronous, so the tests now poll `/api/v1/status` for the observable counters and re-post events until the rebuilt engine takes effect, replacing the 500ms-to-3s sleeps that previously padded each step.

### `engine tail`: stream live detections to the terminal (#239)

A new `rsigma engine tail` subcommand (and the `GET /api/v1/detections/stream` endpoint behind it) streams a running daemon's live detections, the detections-out counterpart to `engine tap`. Each result is the same `EvaluationResult` shape the sinks emit, captured after post-evaluation enrichment and regardless of which sinks are configured, so `engine tail` and a saved sink file are the same format.

- **Server-side filters.** `--level <severity>` (minimum severity) and `--rule <substring>` (case-insensitive title/id match) are applied at the sink, so filtered-out results never cross the wire. `--duration` and `--limit` bound the stream; with neither, it streams until interrupted.
- **Lossy by design.** Each session owns a bounded buffer and drops detections (counted) when full, so a slow tail client can never backpressure the sink task or stall the at-least-once ack-join. A dropped client connection tears the session down automatically. A trailing summary record reports `{streamed, dropped}`.
- **Opt-in.** Disabled by default; enable with `--enable-tail` or `daemon.tail.enabled: true`. The config-file-only `daemon.tail` keys tune `buffer_events` (8192) and `max_sessions` (2); the endpoint returns `503` when disabled, `409` at the session cap, and `400` for a bad `level`.
- **Output.** Rendered through the global `--output-format` layer (NDJSON when piped, pretty JSON on a TTY, plus `csv`/`tsv`/`table`). The client uses the synchronous `ureq` transport, so it builds without the `daemon` feature.
- **New metrics.** `rsigma_tail_active_sessions` and `rsigma_tail_detections_dropped_total`.

### `engine tap`: record the live event stream to a replayable fixture (#238)

A new `rsigma engine tap` subcommand (and the `GET /api/v1/tap` endpoint behind it) records a bounded window of a running daemon's live event stream as an NDJSON fixture, closing the "reproduce a missed detection locally" loop: capture what the daemon is actually seeing, optionally redact sensitive fields, then replay it against candidate rules with `engine eval -e @fixture.ndjson`.

- **Two capture stages.** `--stage decoded` (the default) records what the engine evaluated (post-parse, post-event-filter), so the fixture is always valid NDJSON and replays without repeating the daemon's input flags. `--stage raw` records the input line as received, for debugging the parse/filter step.
- **Server-side redaction.** `--redact-fields user.email,src_ip` redacts named dotted paths before the data leaves the daemon; raw values never cross the wire. Redaction is deterministic per-session salted hashing (`rsigma:redacted:<hex>`), so equal values map to equal tokens within a capture (correlation cardinality survives replay) while the per-session salt blocks dictionary reversal and cross-fixture linkage. A non-numeric path segment meeting an array fans out to every element (fail-closed).
- **Bounded and lossy by design.** The capture can never apply backpressure to detection: each session owns a bounded buffer and drops events (counted) when full. `--duration` and `--limit` bound the window, a trailing summary record reports `{captured, dropped, duration_ms, stage}`, and a dropped client connection tears the session down automatically. The hook rides the same `ArcSwap` observer pattern as `--observe-fields`, so the idle hot-path cost is one load per batch.
- **Config and limits.** Opt-in: disabled by default (it exfiltrates raw events), enabled with `--enable-tap` or `daemon.tap.enabled: true`; the endpoint returns `503` when disabled. The config-file-only `daemon.tap` keys tune `buffer_events` (8192), `max_sessions` (2), and `max_duration` (5m); the endpoint returns `409` at the session cap and `400` over `max_duration`.
- **New metrics.** `rsigma_tap_sessions_total`, `rsigma_tap_active_sessions`, `rsigma_tap_events_streamed_total`, and `rsigma_tap_events_dropped_total`.
- **Security.** The tap exfiltrates raw events, so it inherits the admin surface's TLS/mTLS protections, ships with a kill switch for hardened deployments, and keeps redacted fields off the wire entirely. The client uses the synchronous `ureq` transport, so it builds without the `daemon` feature.

### `engine status`: query a running daemon from the command line (#237)

A new `rsigma engine status` subcommand fetches a running daemon's `/api/v1/status` snapshot and renders it through the shared output layer, so checking a daemon no longer requires `curl`.

- **Address resolution.** `--addr` takes a `host:port` or full URL and defaults to `daemon.api.addr` from the resolved config; wildcard binds (`0.0.0.0`, `[::]`) map to loopback, and `https://` URLs work for TLS deployments. It shares this convention with `config reload`.
- **Output.** Rendered through the global `--output-format` layer: a TTY-aware default (pretty `json` on a terminal, `ndjson` when piped) plus a `METRIC | VALUE` `table` view and `csv`/`tsv`. The snapshot covers rules loaded, events processed, detections and correlations fired, correlation state entries, uptime, and the dynamic-source summary when configured.
- **No daemon feature required.** The command uses the synchronous `ureq` client, so a build without the `daemon` feature can still inspect a remote daemon. It exits `3` when the daemon is unreachable or returns an error.

### Webhook output sink: deliver detections to Slack, Teams, Discord, PagerDuty, or any HTTP endpoint (#227)

A generic, template-driven webhook sink turns a detection or correlation into a templated HTTP request. It is one configurable sink rather than a set of bespoke integrations: Slack, Microsoft Teams, Discord, and PagerDuty ship as field-parametric YAML recipes in the [webhooks guide](https://timescale.github.io/rsigma/guide/webhooks/), while the engine stays service-agnostic.

- **Config.** `--webhook <FILE_OR_DIR>` (repeatable) and the `daemon.output.webhooks` config key declare `webhooks:` entries, each with an `id`, `kind: detection | correlation`, a `url`, optional `headers`/`body` templates, and optional `timeout`, `retry`, `rate_limit`, `scope`, and `queue_size`. Validated at startup with field-scoped errors.
- **Templating.** `url`, header values, and `body` are rendered per result with the same engine as enrichers (`${detection.*}`/`${correlation.*}` plus `${ENV_VAR}` for secrets). The body is JSON-string-escaped so an attacker-influenced rule title or event field cannot break the payload.
- **Best-effort by design.** Webhooks run as lossy (`on_full=drop`) leaves on the async delivery layer, so a third-party endpoint never blocks the at-least-once token release for durable sinks; anything undeliverable lands in the `--dlq`. Connection/timeout errors, `429` (honoring a capped `Retry-After`), and `5xx` retry; other `4xx` route straight to the DLQ.
- **Rate limiting and isolation.** An optional per-entry token bucket spaces requests; each webhook runs its own bounded queue and worker, so a slow webhook cannot stall other sinks.
- **TLS to internal endpoints.** A per-webhook `tls:` block adds a custom CA bundle (for a relay served by a private CA) and a client cert/key for mutual TLS toward the endpoint. Public endpoints use the system roots with no extra config.
- **Observability.** `rsigma_webhook_requests_total{webhook_id,outcome}` and `rsigma_webhook_request_duration_seconds{webhook_id}`; queue depth, retries, drops, and DLQ routing read from the shared per-sink series keyed by the webhook id.
- **Egress and secrets.** Webhooks use the daemon's egress-filtered HTTP client (`--egress-policy`); keep secrets in the environment and reference them with `${ENV_VAR}`.

### OTLP output sink: export detections over OTLP/HTTP and OTLP/gRPC (#223)

The daemon can now emit detection and correlation results to an OpenTelemetry collector, completing OTLP transport symmetry with the existing OTLP receiver.

- **Two transports.** `--output otlp://host:4317` exports over OTLP/gRPC; `--output otlphttp://host:4318` exports over OTLP/HTTP (protobuf, posted to `/v1/logs`). Append `?compression=gzip` for gzip on the wire. Both require a `daemon-otlp` build.
- **TLS.** The `otlps://` (gRPC) and `otlphttps://` (HTTP) schemes enable TLS, verifying the collector against the bundled public roots by default. `?ca=` verifies against a private CA, `?client_cert=`/`?client_key=` enable mutual TLS, and `?tls_domain=` overrides the verified server name.
- **Mapping.** Each result becomes one OTLP `LogRecord` under an `rsigma` resource and instrumentation scope: the Sigma `level` maps to the OTLP severity (critical to FATAL, high to ERROR, medium to WARN, low to INFO, informational to DEBUG), the rule title is the log body, and the full serialized result is attached as structured attributes.
- **Delivery.** The OTLP sink rides the async delivery layer: batched export with bounded retry and backoff, and terminal failures routed to the DLQ.

### Async sink delivery layer: per-sink workers, retry/backoff, and isolation (#222)

Detection output now flows through a per-sink delivery layer instead of a single inline sink writer. Each `--output` sink runs its own bounded queue and worker task, so a slow or flaky network sink no longer immediately head-of-line blocks the others, and transient failures are retried instead of being dropped to the dead-letter queue on the first error.

- **Per-sink workers.** Each sink drains its own bounded queue, batches opportunistically, retries with capped exponential backoff, and routes a result to the DLQ only after exhausting retries. Fan-out across `--output` sinks is isolated up to each sink's queue depth; a slow durable sink eventually applies backpressure, the honest cost of at-least-once.
- **At-least-once preserved.** An ack-join releases a source's acknowledgment only once every sink has committed the result (delivered or DLQ-parked), so the NATS at-least-once contract survives fan-out. Results still in a worker queue at shutdown are left unacked and redelivered on restart.
- **Per-sink lossy mode.** Append `?on_full=drop` to an `--output` sink to drop results when its queue is full instead of applying backpressure, trading durability for never stalling. The default (`?on_full=block`) keeps at-least-once for durable sinks.
- **Tunable.** `--sink-retry-max`, `--sink-backoff-base-ms`, `--sink-backoff-max-ms`, `--sink-batch-max`, and `--sink-batch-flush-ms` (and their `daemon.output.*` config keys) tune the shared delivery behavior; the per-sink queue depth follows `buffer_size`.
- **New metrics.** `rsigma_sink_queue_depth`, `rsigma_sink_retries_total`, `rsigma_sink_dropped_total`, and `rsigma_sink_delivery_failures_total`, all labeled by `sink`.
- **Input-source metric parity.** The HTTP (`POST /api/v1/events`) and OTLP (HTTP and gRPC) push receivers now feed `rsigma_input_queue_depth` and `rsigma_back_pressure_events_total`, which previously tracked only the stdin and NATS pull sources.

### `rule coverage`: ATT&CK Navigator export and coverage-gap analysis (#221)

A new `rsigma rule coverage` subcommand maps a rule set onto MITRE ATT&CK. It reads the `attack.*` tags off every detection and correlation rule, exports an ATT&CK Navigator layer, and reports coverage gaps against external references, the companion to `rule backtest` in a detection-as-code pipeline.

- **Navigator export.** `--navigator <FILE>` writes an ATT&CK Navigator layer (format 4.5) scored by rule count per technique, the same "score function count" semantics SigmaHQ uses, so a rsigma layer overlays cleanly on the SigmaHQ baseline. Sub-technique scores are kept exact.
- **Cross-references.** `--atomics` diffs against the Atomic Red Team index (techniques with atomics but no rule, and rules whose technique has no atomic), `--baseline` diffs against a baseline Navigator layer (the SigmaHQ heatmap by default), and `--targets` diffs against a plain-text technique list. Bare `--atomics`/`--baseline` fetch their upstream defaults over HTTP with a 7-day on-disk cache and stale-cache fallback; both also accept a local path or an atomic-red-team `atomics/` directory.
- **Sub-technique roll-up.** A rule on `attack.t1059.001` covers a `T1059` target (reported as `covered_via_subtechnique`); a parent rule does not vouch for a specific sub-technique target.
- **Output and exit codes.** The report renders through the shared output layer (`table`, `json`, `ndjson`/`csv`/`tsv` per-technique rows). `--fail-on-gaps` exits `1` when any requested cross-reference reports uncovered techniques; `2` for unreadable rules, `3` for an unfetchable cross-reference input.
- **Config.** A `coverage` section (`atomics`, `baseline`, `targets`, `fail_on_gaps`) flows through `rsigma config init/validate/show/schema`, the `RSIGMA_COVERAGE__*` environment layer, `--config`, and `--dry-run`.
- **Internal.** The multi-path rule loader shared with `backend convert` moved into a crate-level helper so the two commands cannot drift on rule loading.

### `rstix`: Phase 2 — STIX relationship and sighting objects (#220)

Phase 2 adds typed STIX relationship and sighting objects (not releasable on its own until `StixObject` dispatch and `Bundle` parsing land).

- **`model::sro`:** `Relationship` (STIX §5.1 — common properties via `SdoSroCommonProps` plus `relationship_type`, `source_ref`, `target_ref`, optional `description`, `start_time`, `stop_time`; `RelSourceRef` / `RelTargetRef` type aliases; charset and `stop_time` later than `start_time` enforced at deserialize), `Sighting` (STIX §5.2 — common properties plus sighting-specific fields including `description`, `first_seen`, `last_seen`, `count`, `summary`, `sighting_of_ref`, `ObservedDataId` for `observed_data_refs`, and `WhereSightedRef` for identity or location in `where_sighted_refs`; `SightingOfRef` type alias; `Sighting::COUNT_MAX`; count range and `last_seen` ≥ `first_seen` enforced at deserialize), and the `SroObject` enum (`#[non_exhaustive]`). Reference-target rules for `source_ref`, `target_ref`, and `sighting_of_ref` are documented in rustdoc and deferred until bundle-level typed parsing.
- **Deserialize:** `model::type_check` hoisted from `model::meta` for shared `"type"` validation; each SRO type rejects mismatched JSON `"type"` in a single serde pass (`ModelError::UnexpectedObjectType`); no intermediate `serde_json::Value` parse. Leaf SRO and `model::meta` types require JSON `"type"` — a missing `"type"` field is a serde error, not silently defaulted.
- **`QueryableStixObject`:** `QueryValue::Id` added; `get_field` exposes reference fields on SRO and meta types (for example `source_ref`, `sighting_of_ref`, `created_by_ref`).
- **Tests:** `roundtrip_strict` minimal and rich fixtures under `tests/fixtures/spec/sro/`; negative fixtures for relationship type charset, time ordering, sighting count range, `where_sighted_refs` typing, cross-type `"type"` rejects, and missing `"type"`; unit coverage for `SroObject` and `MetaObject` `QueryableStixObject` delegation.
- **Docs:** SRO invariant decisions in `crates/rstix/README.md` and `docs/library/rstix.md`.

### Fibratus conversion: emit the required `version` field (#219)

Fibratus rules require a top-level `version` attribute (the rule content version, distinct from `min-engine-version`); the loader rejects a rule that omits it. The converted YAML envelope never emitted it, so every converted rule failed to load. Reported by @rabbitstack.

- The envelope now emits `version:` right after `id` for both detection and correlation rules, regardless of `emit_metadata`. It defaults to `1.0.0` and is overridable with `-O version=<value>`.

### Fibratus conversion: file and remote-thread macro fixes (#217)

Three Fibratus conversion bugs reported by @rabbitstack are fixed, so the converted rules now use the idiomatic macros the upstream loader expects instead of raw or unmapped predicates.

- **`file_access` rules now map to the `open_file` macro.** The `fibratus_windows` pipeline had no `file_access` handler, so file open rules (Microsoft-Windows-Kernel-File ETW provider) emitted the raw Sigma fields `FileName`/`Image` with no event scope, which the loader rejects. The pipeline now renames `FileName -> file.path` and `Image -> ps.exe` and injects the `open_file` discriminator triple (`evt.name = 'CreateFile' and file.operation = 'OPEN' and file.status = 'Success'`).
- **`file_event` rules now collapse to the `create_file` macro.** The disposition guard was appended after the rule body and lacked the success-status clause, so the run never matched the macro and left a raw `evt.name = 'CreateFile' ... and not (file.operation ~= 'OPEN')` body. The full `create_file` triple is now injected contiguously and in macro order.
- **`create_remote_thread` rules now use the `create_remote_thread` macro** instead of degrading to the bare `create_thread`. The pipeline injects the cross-process guards (`evt.pid != 4`, `evt.pid != thread.pid`) the macro requires.
- **Recognizer.** The macro recognizer now accepts the De Morgan negated-equality form (`not (field ~= 'x')`) as equivalent to a macro's `field != 'x'` clause, so disposition and cross-process guards injected through the pipeline fold back into their macros. `use_macros=false` still emits the raw expansion.
- **Pipelines.** The `add_condition` transformation gained an optional `field_refs` map that injects field-to-field comparisons (lowered through the `fieldref` modifier) rather than literals.

### `rule backtest`: corpus replay with per-rule expectations (#216)

A new `rsigma rule backtest` subcommand replays an event corpus against a ruleset and diffs the per-rule fire counts against declared expectations, the per-rule fixture harness that `engine eval --fail-on-detection` could not provide (that check is corpus-global and passes when any rule fires).

- **Corpus replay.** `--corpus` takes a file or a directory walked recursively, with extension dispatch (`.ndjson`/`.jsonl` as NDJSON, `.evtx` via the evtx feature, everything else through `--input-format`). Correlation state is reset per corpus file so each file is an independent time slice.
- **Expectations.** An optional `--expectations` YAML asserts per rule (by id or title): `at_least`, `at_most`, or `exactly`, optionally scoped to one corpus file. A rule that fires with no covering expectation is surfaced as a potential false positive, governed by `--unexpected` (`fail`/`warn`/`ignore`).
- **Reports.** The report renders through the shared output layer (`table`, `json`, `ndjson`/`csv`/`tsv` per-rule rows) and can be written to `--report` (JSON) and `--junit` (a hand-rolled JUnit XML, no new dependency). It carries per-rule fires, a per-corpus-file breakdown, the unexpected-fire set, and a per-logsource false-positive-density rollup.
- **Exit codes** follow the house scheme: `0` all expectations met, `1` a failed expectation or a policy-failing unexpected fire, `2` unreadable rules, `3` a bad expectations file or corpus path.
- **Config.** A `backtest` section (`rules`, `corpus`, `expectations`, `unexpected`, `pipelines`, and the syslog input knobs) flows through `rsigma config init/validate/show/schema`, the `RSIGMA_BACKTEST__*` environment layer, `--config`, and `--dry-run`.
- **Internal.** The format-aware eval stream loop moved into a shared `commands::eval_stream` module so `engine eval` and `rule backtest` cannot drift on input parsing; eval behavior is unchanged.

### `rstix`: Phase 2 — STIX meta objects (#213)

Phase 2 adds STIX meta objects (not releasable on its own until `StixObject` dispatch and `Bundle` parsing land).

- **`model::meta`:** `MarkingDefinition` (STIX §7.2.1 optional common properties — `created_by_ref`, `external_references`, `object_marking_refs`, `granular_markings`; legacy TLP 1.x and current TLP 2.0 encodings; `IS_NON_VERSIONABLE` / `is_non_versionable()`; nine TLP UUID constants), `ExtensionDefinition` (`created_by_ref` required per §7.2.2), `LanguageContent` (`contents` as nested `BTreeMap` for stable JSON key order), and the `MetaObject` enum (`#[non_exhaustive]`).
- **Deserialize:** each meta type validates JSON `"type"` against `TYPE_NAME` in a single serde pass (`ModelError::UnexpectedObjectType`); no intermediate `serde_json::Value` parse.
- **Tests:** `roundtrip_strict` for complete types (meta objects, `ExternalReference`, `GranularMarking`, `ExtensionMap`); subset `roundtrip` for `SdoSroCommonProps` / `ScoCommonProps` fixtures that carry unmodeled SDO keys. Fixtures under `tests/fixtures/spec/meta/` include minimal TLP markings, a rich marking-def with common properties, and cross-type reject coverage. Unit pins for all nine TLP ids.
- **Docs:** STIX object model version vs TLP marking encoding in `crates/rstix/README.md` and `docs/library/rstix.md`.

### Security: transitive `quinn-proto` bump for RUSTSEC-2026-0185

`cargo audit` flagged [RUSTSEC-2026-0185](https://rustsec.org/advisories/RUSTSEC-2026-0185), a high-severity (7.5) remote memory exhaustion in `quinn-proto` from unbounded out-of-order stream reassembly, published 2026-06-22. It reaches the tree transitively through `reqwest -> quinn -> quinn-proto`. A targeted `cargo update -p quinn-proto --precise 0.11.15` moves the workspace and fuzz lockfiles from 0.11.14 to the fixed 0.11.15 with no other dependency changes.

[v0.16.0...v0.17.0](https://github.com/timescale/rsigma/compare/v0.16.0...v0.17.0)

## [0.16.0] - 2026-06-15

**TL;DR**
RSigma v0.16.0 is the "MCP server" release:
* MCP server: a new [Model Context Protocol](https://modelcontextprotocol.io) integration that exposes the Sigma toolchain to AI agents.
  * `rsigma-mcp` crate and `rsigma mcp serve` (opt-in `mcp` feature): typed tools (parse, lint, validate, evaluate, convert, fix) plus field/backend/pipeline introspection and reference resources, with enrichment-aware evaluation (#208).
  * Remote transport and config: Streamable HTTP (`rsigma mcp serve --http`), constant-time bearer-token auth, in-process TLS, and a new `mcp` config section wired through `rsigma config` and the environment layer (#209).
  * Smoke harness: `scripts/mcp-smoke.py` drives a built server end to end over stdio and HTTP across every tool and resource as a standard-library CI job (#210).
  * Prerequisite refactor: the auto-fix applier, modifier/MITRE reference data, and the 75-rule lint catalogue move into `rsigma-parser` so the CLI, the LSP, and the MCP server share one implementation, behavior unchanged (#207).
* `backend convert` per-rule file output: point `--output` at a directory to write one file per converted rule, named from the rule title with the backend's native extension (#205).
* Configurable correlation state caps: `--max-state-entries` exposes the global entry cap and a new `--max-group-entries` bounds a single group's window state, with matching config keys and a per-rule attribute (#200).
* Fibratus conversion fixes: corrected `process_creation`/`process_termination`/`create_remote_thread` field mappings and `registry_event` scoping against the Fibratus 3.0.0 vocabulary, thanks to @rabbitstack (#202).
* Correlation window-mode benchmarks: a throughput suite plus a non-Criterion peak-memory stress target for the `sliding`/`tumbling`/`session` modes shipped in v0.15.0 (#199).
* `rstix`: data-model skeleton and common property containers for the STIX 2.1 library, with leaf-type serde, thanks to @SecurityEnthusiast (not yet releasable on its own) (#201).
* Dependency and security bumps: rolls up six Dependabot PRs and patches three RustSec PostgreSQL advisories (#206).

### Developer tooling: MCP smoke harness (#210)

`scripts/mcp-smoke.py` drives a built `rsigma mcp serve` binary end to end over stdio and Streamable HTTP (with bearer auth), exercising all 11 tools and 3 resources as a post-build sanity check, and runs as the `MCP Smoke` CI job. Standard-library only.

### MCP server: Streamable HTTP transport, bearer auth, and `mcp` config keys (#209)

Adds a remote transport and configuration to the MCP server.

- **Streamable HTTP transport.** `rsigma mcp serve --http <addr>` serves the MCP endpoint at `/mcp` over HTTP (stdio stays the default). Built on rmcp's `StreamableHttpService` mounted on axum.
- **Bearer-token auth.** `--auth-token <token>` (or `RSIGMA_MCP_AUTH_TOKEN`) requires a static token on every request, compared in constant time; requests without it get `401`. The token is flag/env-only and never read from config files.
- **TLS.** `--tls-cert`/`--tls-key` terminate TLS in-process using the daemon's rustls loader (requires the `daemon-tls` feature). Plaintext binds on non-loopback addresses are refused unless `--allow-plaintext`.
- **Config keys.** A new `mcp` config section (`mcp.http_addr`, `mcp.lint_config`, `mcp.rules_dir`) is wired through `rsigma config init/validate/show/schema` and the `RSIGMA_MCP__*` environment layer. The auth token stays flag/env-only by design.

### MCP server: `rsigma mcp serve` and the `rsigma-mcp` crate (#208)

A new [Model Context Protocol](https://modelcontextprotocol.io) server exposes the rsigma Sigma toolchain to AI agents (Cursor, Claude Code, ...) as structured tools. Instead of scraping CLI text, an agent calls typed tools and gets back JSON: ASTs, lint findings with spans and fix availability, evaluation matches, backend queries, and field inventories.

- **`rsigma mcp serve`.** A new command group (`Commands::Mcp`) running the server over stdio, gated behind a new opt-in `mcp` Cargo feature (build with `--features mcp`; the prebuilt binaries and Docker image include it). Flags: `--lint-config` (applied by the lint tool) and `--rules-dir` (a default root for relative path-based tool calls).
- **`rsigma-mcp` crate.** A new library crate built on `rmcp` 1.7 with the `RsigmaMcp` handler and `serve_stdio`. Ten core tools: `parse_rule`, `parse_condition`, `lint_rules`, `validate_rules`, `evaluate_events`, `convert_rules`, `list_backends`, `list_fields`, `resolve_pipeline`, and `list_builtin_pipelines`. Every tool accepts inline content (`yaml`/`condition`/`events`) xor a file `path`; stdout is reserved for the transport and diagnostics go to stderr.
- **`fix_rules` tool.** Applies safe auto-fixes to Sigma YAML (lowercase keys, status/level typos, duplicate removal, ...) preserving comments and formatting, and returns the fixed YAML plus applied/failed/skipped-unsafe counts. Unsafe fixes are never auto-applied. `write: true` (only valid with a file `path`) persists the change to disk; an optional `lint_rules` filter restricts which lint rules are fixed.
- **MCP resources.** `rsigma://lint/catalogue` (the 75-rule catalogue as JSON), `rsigma://reference/modifiers`, and `rsigma://reference/mitre-tactics` let agents ground themselves on the exact lint vocabulary and modifier semantics without spending tool calls.
- **Enrichment-aware `evaluate_events`.** An optional `enrichers` (inline YAML/JSON) or `enrichers_path` parameter builds an enrichment pipeline and enriches results before returning; loader validation errors (including template-namespace checks) come back as structured errors, so the tool doubles as an enricher-config validator.
- **`rsigma_runtime::enrichment::config`.** The enrichers YAML loader (`load_enrichers_file`, `build_enrichers`, `build_enrichers_full`, `EnrichersFile`) moves from the CLI daemon into `rsigma-runtime` so the daemon and the MCP server share one loader. The daemon is rewired to the moved loader with behavior and error text unchanged.
- **Docs.** A new [MCP server guide](https://timescale.github.io/rsigma/guide/mcp-server/), the [`mcp serve` CLI page](https://timescale.github.io/rsigma/cli/mcp/serve/), an `rsigma-mcp` library page, and the `mcp` feature entry in the feature-flags reference.

### MCP server prerequisites: shared fix applier, reference data, and lint catalogue (#207)

Internal refactors that lift three pieces of lint and reference machinery into `rsigma-parser` so the CLI, the LSP, and the upcoming MCP server share one implementation. Behavior is unchanged for existing commands.

- **`rsigma_parser::lint::fix`.** The string-level auto-fix applier (`json_pointer_to_route`, `apply_single_fix_patch`, `apply_rename_key`) moves from `rsigma-cli` into the parser, with a new `apply_fixes_to_source(source, &[&LintWarning]) -> SourceFixOutcome` entry point that applies every safe fix to a YAML string and reports applied/failed counts. The `yamlpath`/`yamlpatch` dependencies move with it. `rsigma rule lint --fix` keeps its file-on-disk behavior through a thin wrapper.
- **`rsigma_parser::reference`.** The `MODIFIERS` and `MITRE_TACTICS` tables move out of the LSP binary (where they were unreachable cross-crate) into a public parser module; the LSP re-exports them so hover/completion are unchanged.
- **`rsigma_parser::lint::catalogue`.** A new `catalogue()` returns per-rule metadata (id, default severity, fix disposition, one-line description) for all 75 lint rules, generated from a single list whose exhaustive match makes adding a rule without a catalogue entry a compile error.

### `backend convert`: per-rule file output when `--output` is a directory (#205)

`rsigma backend convert` can now write one file per converted rule instead of a single concatenated stream. When `--output` points at a directory (an existing directory, or a path with a trailing separator that is created on demand), each rule is written to its own file named after a snake_case slug of the rule title, with the backend's native extension. This was prompted by Fibratus rule-deployment ergonomics: the engine loads one YAML rule per file from its `Rules/` directory, so the split output drops straight in without hand-separating the `---`-joined stream.

- **Naming.** File stems are a slug of the rule title (`Detect Whoami` becomes `detect_whoami`), falling back to the rule id and then a `rule` literal when the title slugifies to nothing. Colliding names get a numeric suffix (`same.yml`, `same_2.yml`) so two rules never overwrite each other. A rule that converts to several documents (for example a `temporal` correlation expanded with `-O temporal_permute=true`) keeps them together in its one file, finalized through the backend so the format-aware separators land inside.
- **Extensions.** A new `Backend::output_file_extension` hook picks the per-rule extension: `yml` for the Fibratus YAML envelope (`txt` for its bare-expression `expr` format), `sql` for PostgreSQL, and `txt` by default. Single-file and stdout output are unchanged.
- **Docs.** The Fibratus backend reference, the rule-conversion guide, and the README document the directory-output workflow (`rsigma backend convert rules/ -t fibratus -p fibratus_windows -o ./Rules/`).

### Fibratus conversion: corrected field mappings and registry event scoping (#202)

Three correctness fixes to the `fibratus_windows` pipeline shipped in #191, found while converting more of the upstream Fibratus rules library.

- **Process field coverage.** `process_creation` and `process_termination` gain the field mappings they were missing against the Fibratus 3.0.0 vocabulary: `OriginalFileName` -> `ps.pe.file.name`, `CurrentDirectory` -> `ps.cwd`, `ProcessGuid` -> `ps.uuid`, `ParentProcessGuid` -> `ps.parent.uuid`, `IntegrityLevel` -> `ps.token.integrity_level`, `Company` -> `ps.pe.company`, `Description` -> `ps.pe.description`, `Product` -> `ps.pe.product`, and `FileVersion` -> `process.pe.file.version`. `process_termination` additionally picks up the `CommandLine`, `User`, `LogonId`, and `Parent*` mappings it previously lacked entirely, so a process-exit rule that touches any of those fields now converts instead of failing.
- **Thread events.** `create_remote_thread` maps `TargetImage` -> `evt.arg[exe]`, so a rule that scopes the injected-into process converts rather than dropping the field.
- **Registry event scoping.** The `registry_event` logsource category now prepends an `evt.category = 'registry'` discriminator as its first condition, the same treatment the other categories already get. Fibratus rejects a rule at load time when it has no event-type scoping by name or category, so without this the converted `registry_event` rules would not load.

### `rstix`: Phase 2 — model skeleton and common properties (#201)

Phase 2 (Data Model + Serialization) adds the model skeleton and common property containers. This work is not releasable on its own.

- **`model` module:** `ModelError` and `model::common` property containers — `SdoSroCommonProps` (required `spec_version`, `created`, `modified`; `confidence` as `Option<Confidence>`), `ScoCommonProps` (SCO-only fields), `ExternalReference` (STIX §2.5.2: non-empty `source_name` plus at least one of `description`, `url`, or `external_id` enforced on construction and deserialization), `GranularMarking` (`marking_ref` XOR `lang`; non-empty `selectors`), and `ExtensionMap` / `ExtensionType`.
- **Leaf-type serde:** `serde_impls/` for `StixId`, timestamps, and `Confidence`; typed-ID serde in the `define_typed_id!` macro; inline `LanguageTag` serde.
- **Tests:** fixture-backed integration tests in `tests/spec.rs` (`tests/fixtures/spec/common/`); core serde unit tests in `src/core/`.

### Configurable correlation state caps: `--max-state-entries` and a new per-group entry cap (#200)

The correlation engine's memory bounds are now fully operator-configurable. Previously the global `(correlation, group-key)` entry cap (`max_state_entries`, default 100,000) was a library-only setting with no CLI surface, and nothing bounded the growth of a single group's window state, which grows with `timespan` x event rate on chatty groups.

- **`--max-state-entries <N>`** on `engine eval` and `engine daemon` (config key `daemon.correlation.max_state_entries`) exposes the existing global hard cap. When reached, the stalest entries are evicted down to 90% capacity and a warning is logged, as before. A drift-guard test pins the CLI default to the engine's `CorrelationConfig` default across the two crates.
- **`--max-group-entries <N>`** (config key `daemon.correlation.max_group_entries`, per-rule `rsigma.max_group_entries` custom attribute) is a new, opt-in cap on retained entries within a single group's window state: timestamps for `event_count`, `(timestamp, value)` pairs for `value_count` and the numeric aggregations, and per-referenced-rule hits for the temporal types. On overflow the oldest entries are dropped, which can only under-count (aggregates saturate; a correlation that needed the evicted entries may not fire). Session windows always keep their oldest entry as the span anchor, so truncation cannot silently extend the `timespan` cap. Unset means unbounded, the historical behavior, so existing deployments are unaffected.
- **API.** `CorrelationConfig` gains `max_group_entries: Option<usize>`, `CompiledCorrelation` gains the matching per-rule override, and `WindowState` gains `truncate_oldest(cap, preserve_front)`. The per-rule attribute follows the same resolution order as the other `rsigma.*` correlation attributes: rule override wins over the engine default.
- **Docs.** New flags documented on the `engine eval` and `engine daemon` CLI pages, the configuration file reference, the custom-attributes reference, the processing-pipelines attribute table, and the Performance Tuning guide's correlation-memory section (which also now states that the global cap bounds group count, not bytes within a group, and is global rather than per-rule).

### Correlation window-mode benchmarks: throughput and peak-memory stress suite (#199)

Two new benchmark surfaces for the correlation window modes shipped in #192, prompted by the [SEP #214](https://github.com/SigmaHQ/sigma-specification/issues/214) discussion on memory becoming the bottleneck in stateful window correlation (high-cardinality group keys, long-lived sessions).

- **`correlation_window_modes` Criterion group** (`cargo bench -p rsigma-eval --bench correlation -- correlation_window_modes`): sliding vs tumbling vs session on an identical `event_count` workload. All three modes run at ~1.4-1.5 Melem/s — the window decision in `apply_window_open` is O(1), so declaring `window: session` is free at evaluation time.
- **`correlation_memory` bench target** (`cargo bench -p rsigma-eval --bench correlation_memory`): not a Criterion suite — it installs a counting global allocator and reports peak/settled heap deltas, which Criterion cannot observe. Three scenario families: high-cardinality session keys against the `max_state_entries` cap (1M unique keys held to a 39.8 MiB peak by stalest-first eviction; ~256 B per live session group uncapped), long-lived chatty sessions (8 B per in-window `event_count` event; `value_count` with distinct strings costs ~92 B per event and drops to 63 Kelem/s at 1,800 distinct values per window because the distinct count is recomputed per event), and a three-mode comparison on identical load (identical memory and throughput).
- **Documentation**: results recorded in `BENCHMARKS.md` (new Window Modes and Window-Mode Memory Stress sections plus Key Observations); the Performance Tuning guide's correlation-memory section now documents what the cap does and does not bound, per-event state costs by correlation type, the `value_count` distinct-count hot spot, and the cardinality-flood eviction caveat — and fixes a long-standing inaccuracy (the `max_state_entries` cap is global across all correlation rules, not per rule). The streaming-detection guide links the window-mode semantics to the measured numbers, and the developer testing guide documents the non-Criterion bench target.

### Dependency and security bumps (#206)

Rolls up six open Dependabot PRs into a single merge and patches three RustSec advisories. Rust (workspace `Cargo.lock`), batched via the `patch-updates` group (#197): `log` 0.4.30 to 0.4.32, `chrono` 0.4.44 to 0.4.45, `daachorse` 3.0.0 to 3.0.1, `async-nats` 0.49.0 to 0.49.1, `hyper` 1.10.0 to 1.10.1, and `uuid` 1.23.1 to 1.23.2; `libfuzzer-sys` 0.4.12 to 0.4.13 in `fuzz/Cargo.lock` (#195). CI (all repinned by commit SHA, batched via the `actions-updates` group, #198): `actions/checkout` v6.0.2 to v6.0.3, `github/codeql-action` v4.36.0 to v4.36.2, and `taiki-e/install-action` v2.79.12 to v2.81.4. VS Code extension: `vscode-languageclient` 9.0.1 to 10.0.0 (#196), `@vscode/vsce` 3.9.1 to 3.9.2 (#194), and `esbuild` 0.28.0 to 0.28.1 (#203); the three all touched `editors/vscode/package.json` and `package-lock.json`, resolved by keeping the newest of each and regenerating the lockfile. Security: the transitive PostgreSQL client stack pulled in through `rsigma-convert` moves `postgres-protocol` 0.6.11 to 0.6.12 and `postgres-types` 0.2.13 to 0.2.14 (RUSTSEC-2026-0179, RUSTSEC-2026-0180) and `tokio-postgres` 0.7.17 to 0.7.18 (RUSTSEC-2026-0178), closing the three denial-of-service advisories published 2026-06-12.

[v0.15.0...v0.16.0](https://github.com/timescale/rsigma/compare/v0.15.0...v0.16.0)

## [0.15.0] - 2026-06-11

**TL;DR**
RSigma v0.15.0 is the "new conversion target and Sigma extensions" release:
* Fibratus conversion backend: convert Sigma rules into Fibratus rule YAML for the first endpoint-sensor target, with a `fibratus_windows` field-mapping pipeline, idiomatic macro recognition, ATT&CK label flattening, and sequence-DSL correlation lowering (#191).
* Array matching: `[any]`/`[all]`/`[all_or_empty]`/`[none]` object-scope blocks, implicit any-member matching, and positional indexing (`args[0]`, negative indices), evaluated in the engine and lowered to PostgreSQL JSONB (#159).
* Declarable correlation window modes: `sliding`/`tumbling`/`session` windows plus a session `gap`, end to end across the parser, runtime evaluator, and PostgreSQL conversion, with pySigma-style `correlation_method` selection at convert time (#192).
* `sigma-version`: an optional top-level spec-major attribute that gates breaking spec changes by the declared version (array matching now activates only at major `3`), plus cross-document reference lints (#188).
* `rstix`: a new STIX 2.1 + TAXII 2.1 library crate; Phase 1 lands the core foundation (validated typed IDs, timestamps, deterministic SCO IDs, controlled vocabularies) (#185), thanks to @SecurityEnthusiast.
* Gated match-detail enrichment: a new `MatchDetailLevel` (`off`/`summary`/`full`) that explains why each field matched, off by default so the default wire shape is byte-for-byte unchanged (#186).
* RFC 5424 syslog now strips a leading UTF-8 BOM by default, fixing corrupted `_raw` fields, broken anchored matchers, and BOM-blocked embedded-JSON detection (#187).
* Daemon shutdown fix: `SIGINT`/`SIGTERM` handlers are now installed before the API listener is announced, closing a startup race that could hard-kill the process instead of draining cleanly.

### Fixed

- **Daemon startup signal race.** The daemon now installs its `SIGINT`/`SIGTERM` handlers eagerly, before the API listener is announced and reachable, and reuses those same streams for the serve task's graceful shutdown. Previously the handlers were installed lazily on the serve task's first poll, so a signal arriving in the window between the socket becoming connectable (the kernel completes handshakes from the listen backlog) and that first poll hit the default disposition and killed the process instead of draining cleanly.

### Fibratus conversion backend (#191)

Convert Sigma rules into rule YAML for [Fibratus](https://github.com/rabbitstack/fibratus), an Apache-2.0 kernel-event detection and EDR engine. Fibratus is the first conversion target aimed at an endpoint sensor rather than a centralized log store; rules emitted by `rsigma backend convert -t fibratus` drop into a Fibratus installation's `Rules/` directory and load with the same parser as the upstream rules library.

**Output formats.** Four format names cover two output shapes. `default` (alias `yaml`, `rule`) emits a complete YAML rule document per Sigma rule (`name`, `id`, `description`, `labels`, `condition`, `min-engine-version`, optional `action`) with `---` separators between multi-rule output so the whole stream is a valid YAML document set. `expr` strips the envelope and emits the bare filter expression only, for piping into ad-hoc Fibratus commands.

**Modifier coverage.** Sigma's case-insensitive default flips to Fibratus's case-insensitive operators (`icontains`/`istartswith`/`iendswith`); the `|cased` modifier or `-O case_sensitive=true` flips to the bare forms. Plain literal equality (no wildcards) uses the dedicated string-equality operators `~=` (case-insensitive default) and `=` (`|cased`) rather than a wildcard match, which evaluates more efficiently and reads the way the upstream rules library writes literal equality; the `evt.name` event discriminator always uses the exact `=`. Wildcard-bearing values lower to `imatches`/`matches`. Multi-value OR lists collapse into a single Fibratus list-operator clause (`field iin ('a', 'b')`, `field imatches ('a*', 'b?')`, `field icontains ('a', 'b')`, ...); a `|all` list stays AND-joined because a list right-hand side is OR-only. Regex (`|re`) lowers to the [`regex(field, 'pat1', 'pat2', ...) = true`](https://www.fibratus.io/) filter function, with multi-value lists collapsing into a single call and negation expressed as a leading `not`; patterns that use lookarounds or backreferences are rejected with a structured `UnsupportedModifier` rather than emitting something Fibratus's RE2 engine would reject at load time. CIDR (`|cidr`) lowers to `cidr_contains(field, '...')`, with multi-value lists collapsing into a single variadic call. Numeric comparisons map to `<`/`<=`/`>`/`>=`. `exists` lowers to `field != false` / `field = false` and a `null` value to `field = ''` (Fibratus has no `null` token). Field references are native (`field1 = field2`). Keywords return `UnsupportedKeyword` because Sigma keywords have no bound field and Fibratus operators require one.

**Field naming.** A new `fibratus_windows` builtin pipeline (registered alongside `ecs_windows` and `sysmon`) maps Sigma's PascalCase Windows fields to the lowercase-dotted Fibratus vocabulary and adds the right `evt.name` discriminator per logsource category (`process_creation -> CreateProcess`, `network_connection -> Connect`, `dns_query -> QueryDns`, `registry_set -> RegSetValue`, ...). Most categories map `Image -> ps.exe`, `CommandLine -> ps.cmdline`, `TargetFilename -> file.path`, `TargetObject -> registry.path`, `DestinationIp -> net.dip`, `ImageLoaded -> module.path`, `QueryName -> dns.name`. Field names target the Fibratus 3.0.0 registry: DNS fields live under `dns.*`, loaded executables/DLLs under `module.*` (the legacy `image.*` namespace is deprecated), and Sigma fields with no 3.0.0 equivalent (`SignatureStatus`/`Hashes`/`Imphash` under `image_load`/`driver_load`, `DestinationHostname`/`Initiated` under `network_connection`) are intentionally unmapped so a dependent rule fails conversion instead of emitting a field the loader rejects. The `evt.name` discriminator is injected as the *first* condition (the new `add_condition` `prepend: true` option), so the emitted rule leads with the cheapest, most selective predicate and Fibratus short-circuits before the rule body. On a Fibratus 3.0.0 `process_creation` (`CreateProcess`) event `ps.*` is the *created* (child) process, so `Image`/`CommandLine`/`ProcessId`/`User` -> `ps.exe`/`ps.cmdline`/`ps.pid`/`ps.username` and the spawning process is `ParentImage`/`ParentCommandLine`/`ParentProcessId` -> `ps.parent.exe`/`ps.parent.cmdline`/`ps.parent.pid` (Fibratus 3.0.0 decommissioned the legacy `ps.sibling.*` namespace and unified process attributes under `ps.*`). For `process_access` (`OpenProcess`) the caller is `ps.*` and the opened process is exposed as event arguments, so `TargetImage`/`TargetProcessId` -> `evt.arg[exe]`/`evt.arg[pid]` (matching the upstream LSASS-access rule) and `GrantedAccess -> ps.access.mask.names`. `file_event` (file creation) excludes the `OPEN` disposition (the `create_file` macro semantics) so it does not fire on plain file access, and `registry_set`/`registry_event` map `Details -> registry.data`. The `pipe_created` logsource is intentionally not mapped because Fibratus has no named-pipe visibility without a kernel driver. Use it whenever you convert SigmaHQ Windows rules: `rsigma backend convert rules/windows/ -t fibratus -p fibratus_windows`. ATT&CK tags in `tags:` flatten into Fibratus's `labels:` block via a static MITRE lookup: `attack.<tactic_short_name>` -> `tactic.id`/`tactic.name`/`tactic.ref`, `attack.t<NNNN>` -> `technique.id`/`technique.ref`, and `attack.t<NNNN>.<sub>` -> `subtechnique.id`/`subtechnique.ref` (the base technique and sub-technique live in separate label namespaces matching the upstream Fibratus rules library convention). Unknown tags pass through as `tag.<original>: <original>`.

**Correlation.** Sigma correlation rules lower to Fibratus's inline `sequence ... maxspan ... by <fields> | stage | | stage |` DSL (the form Fibratus 1.10 introduced when it decommissioned `policy: sequence`). The `group-by` fields, shared across every referenced rule, are emitted once as a sequence-level `by field1, field2, ...` clause (the upstream rules-library style) instead of repeated per stage, so multi-field group-by needs no inline bindings. `temporal_ordered` and `temporal` (ordered fallback) emit one `|...|` stage per referenced rule; small-threshold `event_count` and `value_count` expand into N repeated or N distinct stages capped at `-O max_repeated_slots` (default 5), with `value_count` distinctness expressed via positional pattern bindings (`field != $1.field and field != $2.field and ...`). The four math-aggregate types (`value_sum`, `value_avg`, `value_percentile`, `value_median`), thresholds above the cap, range/equality predicates, and multi-rule `event_count`/`value_count` all return `UnsupportedCorrelation` with structured rationales the operator can act on; the coverage matrix in the new [Fibratus backend reference](docs/reference/backends/fibratus.md) is the source of truth.

**Backend options.** `-O action=kill,isolate` appends an `action:` block to every rule envelope. `-O min_engine=3.0.0` sets `min-engine-version:`. `-O emit_metadata=false` drops the `description:` and `labels:` blocks for a minimal envelope. `-O max_repeated_slots=N` raises the correlation cap. `-O case_sensitive=true` forces the bare operators globally. `-O temporal_permute=true` expands a `temporal` (any-order) correlation into one ordered sequence document per permutation of the referenced rules (capped at N <= 3, so 1/2/6 documents per correlation; each permutation gets distinct title and id suffixes), so any matching order alerts; larger correlations return `UnsupportedCorrelation`. `-O use_macros` (default `true`) walks top-level `and` clauses and replaces recognized runs with idiomatic Fibratus macro calls (`spawn_process`, `create_thread`, `write_file`, `read_file`, `open_file`, `create_file`, `set_value`, `open_process`, `open_thread`, ...), greedy-longest-match so a full three-clause `open_file` triple beats the standalone `evt.name = 'CreateFile'` prefix; each clause is matched against both the exact (`=`) and case-insensitive (`~=`) operator forms, so recognition is independent of `-O case_sensitive`, and clauses that match no macro pass through verbatim.

**Correlation window modes.** The backend honors the `rsigma.window` / `rsigma.gap` extension attributes the [Correlation window modes](#correlation-window-modes-declarable-slidingtumblingsession-windows-and-a-session-gap-192) entry above adds. The native `sequence ... maxspan` DSL is itself a sliding total-span constraint per stage, so `rsigma.window: sliding` (the default) is a faithful pass-through and adds no warnings. `rsigma.window: tumbling` returns `UnsupportedCorrelation` because Fibratus has no calendar-aligned bucket primitive. `rsigma.window: session` (the SEP's "should warn" degraded case) still emits a sliding sequence with the rule's `timespan` as `maxspan`, but pushes a warning to the conversion warnings channel noting that the requested per-step `rsigma.gap` is not enforced because Fibratus has no `maxpause`-style inactivity timeout. Two new `-O` options: `correlation_method` (`sliding`/`session`; pySigma-style override that takes precedence over the rule's own `rsigma.window`) and `gap` (default session gap for rules that do not declare their own `rsigma.gap`, used in the warning text). The backend advertises these via the new `Backend::correlation_methods` and `Backend::default_correlation_method` trait methods; `tumbling` is intentionally absent from the advertised list and a `-O correlation_method=tumbling` override is rejected up-front.

**CLI integration.** `rsigma backend targets` and `rsigma backend formats fibratus` list the new target and its formats. The CLI's per-rule output joining now defers to the backend's `finalize_output`, which fixes a latent bug for PostgreSQL's `view`/`continuous_aggregate` formats (they wanted `;\n\n` between statements but got `\n`) and is what makes the Fibratus `---` document separator land correctly on stdout.

### Correlation window modes: declarable `sliding`/`tumbling`/`session` windows and a session `gap` (#192)

rsigma correlation rules can now declare how their `timespan` is anchored to the event stream, via an optional `window` attribute, plus a `gap` field for dynamic session windows, end to end across the parser, runtime evaluator, and PostgreSQL conversion. This is an rsigma-specific extension: a portable-spec version was proposed upstream and declined ([sigma-specification #214](https://github.com/SigmaHQ/sigma-specification/issues/214)), on the grounds that the window strategy is a backend-and-deployment concern rather than portable detection logic. rsigma keeps the capability where it is reliable (a stateful streaming engine has no global transaction caps) and follows the upstream guidance: rule-level window/gap live in the `rsigma.*` extension namespace, and conversion exposes the choice to the converting user the way pySigma's `correlation_methods` do.

- **New `window` attribute** with three values: `sliding` (the default, equal to today's trailing per-event window, so no existing rule changes meaning), `tumbling` (fixed, boundary-aligned, non-overlapping buckets of size `timespan`), and `session` (a dynamic window that extends while consecutive in-group events stay within `gap`, capped by `timespan` as the maximum total span).
- **New `gap` attribute** reusing the existing `timespan` grammar (`Xs`/`Xm`/`Xh`/`Xd`/`Xw`/`XM`/`Xy`). It is required when `window: session` and rejected for the other modes. The parser errors on a session window without a gap, a gap without a session window, and an unknown window mode.
- **`rsigma.*` extension namespace.** `window`/`gap` are accepted both via the `rsigma.*` engine-extension keys (`rsigma.window`, `rsigma.gap`, alongside `rsigma.suppress` and friends), which is the primary spelling, and via the first-class `correlation.window`/`correlation.gap` keys, kept as aliases. The `rsigma.*` spelling wins when both are present. The parser and linter resolve either spelling.
- **Conversion method selection (pySigma-style).** The `Backend` trait gains `correlation_methods` and `default_correlation_method`. The PostgreSQL backend advertises `sliding`/`tumbling`/`session` (default `sliding`), and `rsigma backend convert -O correlation_method=NAME` lets the converting user pick the strategy per backend, overriding a rule's own `window` hint for that conversion. `-O gap=5m` supplies the default session gap for rules that declare none (a rule's own `gap` always wins), so `correlation_method=session` works across whole rulesets. Invalid methods and malformed gaps are rejected both up front in the CLI and per-rule in the backend; `rsigma backend formats <target>` lists the available methods.
- **Runtime evaluation.** The correlation engine honors all three modes: `sliding` keeps the existing trailing per-event window, `tumbling` resets per-group state on epoch-aligned bucket boundaries, and `session` keeps a window open while consecutive in-group events stay within `gap`, restarting after a gap of inactivity or once the total span would exceed `timespan`. A late arrival belonging to an earlier tumbling bucket is discarded rather than allowed to reset the active bucket, so out-of-order stragglers cannot wipe an accumulating count. Engine-level state eviction is window-mode aware: sliding state trims by the trailing cutoff as before, while tumbling/session groups are only dropped whole once stale (trimming their front would forget the bucket/session start and silently weaken the `timespan` cap). The same window logic applies to chained correlations and to event-inclusion buffers. Window bookkeeping is derived from the existing per-group timestamps, so persisted daemon state (snapshots) stays format-compatible and survives upgrades.
- **PostgreSQL conversion.** The backend renders the windowing strategy from the rule's `window`: `tumbling` emits boundary-aligned buckets (`time_bucket` on TimescaleDB, `date_bin` on plain PostgreSQL) sized to the rule's `timespan`, and `session` emits a gaps-and-islands query (`LAG` + a running session id) that honors the `gap` exactly and enforces the `timespan` cap as a post-aggregation filter (recorded as a warning). An absent or `sliding` window keeps the existing per-output_format SQL unchanged, so no existing query changes. Tumbling and session cover every correlation type, including `temporal`/`temporal_ordered`, which bucket or sessionize the combined detections and count distinct referenced rules (order is not enforced, matching the existing temporal path).
- **Conversion warnings channel.** `ConversionResult` gains a `warnings` field and `Backend::convert_correlation_rule_with_warnings`, so a backend can emit non-fatal "should warn" diagnostics (the closest faithful approximation) while still converting, distinct from a hard `ConvertError`. `rsigma backend convert` prints these to stderr.
- **Lint rules.** Four new checks: `invalid_window_mode`, `missing_session_gap`, `gap_without_session`, and `invalid_gap_format`. Both the parser and the linter treat a `window`/`gap` key set to a non-string value (e.g. an unquoted `gap: 300`) as a type error with a quoting hint, rather than silently reading it as absent. The lint catalogue now lists 74 built-in checks plus the 1 reserved enum value (`empty_filter_rules`).
- **API.** `rsigma-parser` gains a `WindowMode` enum (`Sliding`/`Tumbling`/`Session`, default `Sliding`) and `window: WindowMode` plus `gap: Option<Timespan>` fields on `CorrelationRule`, populated from either the `rsigma.*` or the first-class spelling. `rsigma-eval` adds `window_mode` and `gap_secs` to `CompiledCorrelation` and an `apply_window_open` helper. `rsigma-convert` adds the warnings channel described above plus `Backend::correlation_methods`/`default_correlation_method` and `correlation_method`/`gap` options on `PostgresBackend`. The LSP offers a new `correlation-session` snippet that emits the primary `rsigma.window`/`rsigma.gap` spelling.
- **Backward compatible.** `window` is optional and defaults to `sliding`; `gap` is only valid under `window: session`. No existing rule changes meaning or becomes invalid.

### `sigma-version`: gate breaking spec changes by the declared specification major (#188)

rsigma now reads an optional top-level `sigma-version` attribute on a Sigma document: the Sigma specification MAJOR version the document targets (for example `sigma-version: 3`). It is the reference implementation of the rule-level spec-version mechanism proposed as [SEP #213](https://github.com/SigmaHQ/sigma-specification/issues/213), split out of array matching so that every future breaking spec change is gated by one declared version rather than a per-feature escape.

- **Fixed-floor default.** When `sigma-version` is absent, the document resolves to a fixed floor (major `2`, the v2.x line): a constant defined by the specification, not the latest version the tool supports. Existing rules keep their current semantics and are never silently reinterpreted. Only the major is significant (a release string like `"2.1.0"` is accepted and read for its major), since breaking changes occur only at major bumps.
- **Array matching is now gated.** Array-matching bracket selectors (`field[any]`, `args[0]`, ...) are active only at major `3` or higher. A rule that declares `sigma-version: 3` reads a trailing `[...]` as an array selector; at the floor (absent or major `2`) brackets are literal field-name characters, normalized to the escaped form (`args\[0\]`) so the escape-aware evaluator and converters resolve them literally. This is a behavior change to the (unreleased) always-on array matching, with no compatibility cost because the feature has not shipped.
- **Lint rules.** `unsupported_sigma_version` (error) flags a declared major newer than this build implements; `array_matching_without_version` (warning) flags a document that uses bracket-selector syntax but resolves below major `3`, where the brackets would be read literally rather than as selectors. The linter also resolves cross-document references by `id` or `name`, across a whole directory: `sigma_version_mismatch` (warning) flags a correlation/filter and a rule it references that declare different majors, and `unknown_rule_reference` (warning) flags a `correlation.rules` or `filter.rules` entry that resolves to no rule in the linted set (directory scope only, where the index is complete). Directory linting now runs a two-pass index so references resolve across sibling files. The lint catalogue now lists 70 built-in checks plus the 1 reserved enum value (`empty_filter_rules`).
- **API.** `rsigma-parser` gains a `version` module (`SPEC_VERSION_FLOOR`, `SPEC_VERSION_ARRAY_MATCHING`, `SPEC_VERSION_SUPPORTED`, `resolve_major`, `array_matching_enabled`, `is_unsupported`), an optional `sigma_version: Option<u32>` field on `SigmaRule`, `CorrelationRule`, and `FilterRule`, and a `fieldpath::escape_brackets` helper. Gating happens at parse time, so the evaluator and converters consume the already-gated AST with no version logic of their own.

### Array matching: `[any]`/`[all]`/`[all_or_empty]`/`[none]` blocks, implicit any-member, and positional indexing (#159)

rsigma can now match members of arrays in event data, an experimental extension proposed to the Sigma specification and accepted as a Sigma Enhancement Proposal ([issue #158](https://github.com/timescale/rsigma/issues/158), [sigma-specification Discussion #106](https://github.com/SigmaHQ/sigma-specification/discussions/106), [SEP #212](https://github.com/SigmaHQ/sigma-specification/issues/212)). Arrays are first-class in cloud and audit logs (CloudTrail, GCP, Okta, Azure Activity, Kubernetes audit, Windows Event Logs) and there was previously no portable way to match a member. The feature is documented in the new [Array Matching guide](docs/guide/array-matching.md) and ships marked experimental because the surface syntax is still being finalized upstream.

**Three constructs, all expressed with `[...]` selectors on the field path.**

- **Implicit any-member.** A plain field expression matches a scalar or any member of an array (`connections: '1.2.3.1'`), including through dotted paths into arrays of objects (`connections.ip|cidr: '123.1.0.0/16'`). This required fixing a first-match-wins bug in `JsonEvent::get_field`: a dotted path crossing an array now collects every element's leaf value, so any-member matching is correct rather than testing only the first element.
- **Object-scope blocks** `field[any]:`, `field[all]:`, `field[all_or_empty]:`, and `field[none]:` open a nested detection evaluated against a single array member, for same-element correlation (one connection that is both `protocol: TCP` and in a suspicious CIDR). `[any]` requires at least one matching member; `[all]` requires a non-empty array where every member matches; `[all_or_empty]` is `[all]` but also matches an empty or missing array (the vacuously-true reading); `[none]` is the dual of `[any]` (no member matches) and matches an empty or missing array. The block body comes in two forms (the dual approach accepted in SEP #212): a **basic** conjunction map (the common case), and an **extended** nested detection with its own `condition:` plus named element-scoped sub-selections, for per-element `and`/`or`/`not` (for example "any connection in the CIDR that is *not* TCP"). The basic form is the implicit-AND degenerate case of the extended form. Inside a block body, a standalone `.` references the current scalar member (with modifiers, e.g. `.|gte`), so an array of scalars can carry multiple, named, or negated per-element predicates ("any 5xx response code that is not 504").
- **Positional indexing** `field[N]` selects one element, for ordered arrays where each index carries meaning (`args[0]` is the process image, `args[1..]` are parameters). Indices may be negative (`args[-1]` is the last element, counting from the end). It is deterministic: a missing field, a non-array value, or an out-of-range index does not match. It composes with paths and quantifiers (`connections[0].ip`, `rules[any].ip[0]`).

Array selectors are kept strictly distinct from the existing `all` value-list modifier. Only an unescaped trailing `[...]` is a selector; a literal bracket in a field name is escaped as `\[` / `\]` (mirroring the existing `\*` / `\?` wildcard escaping), so `args\[0\]` matches a field literally named `args[0]` rather than index 0.

**New lint rule.** `flattened_array_correlation` (warning) flags two or more sibling keys that share a quantified array prefix (e.g. `connections[any].protocol` and `connections[any].ip`); they open independent scopes and do not correlate on the same element, so the rule points authors at the object-scope block form. The lint catalogue now lists 66 built-in checks plus the 1 reserved enum value (`empty_filter_rules`).

**Conversion.** A new `Backend::convert_array_match` hook lowers the constructs where a backend can express them and errors with `UnsupportedArrayMatching` otherwise, never emitting a query with different semantics. The PostgreSQL/TimescaleDB backend lowers object-scope blocks to `EXISTS` / `NOT EXISTS` over `jsonb_array_elements` (guarded by `jsonb_typeof(...) = 'array'`) and positional indices to `->n` / `->>n` (negative subscripts on PG 11+), in JSONB mode. Because `[none]` and `[all_or_empty]` must match an empty or missing array, they lower to a `CASE` that only unnests an actual array and treats a missing/null value as a match, so `jsonb_array_elements` is never applied to a scalar. The extended block body lowers to the same per-element primitive with a boolean inner predicate (the nested `condition:` becomes `OR` / parenthesized `NOT` over the element alias), so it costs no backend coverage. A backend that cannot lower a positional `field[N]` index rejects it (via the new `Backend::supports_field_index` capability) rather than emitting a literal field reference that would diverge from the evaluator; LynxDB, other text backends, and PostgreSQL flat-column mode report the construct as unsupported. Positional indexing is unexpressible in Elasticsearch query DSL because Lucene arrays are unordered sets, which is the strongest argument for evaluating the index in the engine.

**AST and API.** `rsigma-parser` gains `ArrayQuantifier` (`Any`, `All`, `AllOrEmpty`, `None`) and the `Detection::ArrayMatch` / `Detection::And` / `Detection::Conditional` variants, plus a `fieldpath` module of shared escape-aware helpers (bracket unescaping and unescaped-bracket detection) reused by the evaluator and converter; `rsigma-eval` gains the matching `CompiledDetection` variants. The rule index, bloom filter, and cross-rule Aho-Corasick prefilters no longer prune array-valued fields.

**Tests.** New parser, evaluator, and converter tests cover the flat-array, object-array fan-out, any/all/none/all_or_empty correlation and empty-array semantics, scalar-member, nested-quantifier, mixed-map, positional-index (including negative indices), extended-block (per-element negation, disjunction, and `[all]` with a nested condition), `.` scalar-element marker, and escaped-bracket literal-field cases, plus PostgreSQL golden SQL and unsupported-backend errors.

### Strip the UTF-8 BOM from RFC 5424 syslog messages (#187)

RFC 5424 section 6.4 mandates that a UTF-8 `MSG` begin with a byte order mark (`U+FEFF`, bytes `EF BB BF`) as an encoding marker, not as content. `syslog_loose` preserves it verbatim, and `str::trim()` does not remove it (`U+FEFF` is not Unicode `White_Space`), so the BOM previously leaked into the parsed event: it corrupted the `_raw` field and anchored matchers (`startswith`, exact equality), and it blocked embedded-JSON detection because `serde_json` errors on a leading BOM, silently degrading a BOM-prefixed JSON payload to a key/value event.

- **The syslog adapter now strips a single leading BOM from the message body by default**, gated by a new `SyslogConfig.strip_bom` field (defaults to `true`).
- **Opt out** with `rsigma engine eval --syslog-strip-bom false` / `rsigma engine daemon --syslog-strip-bom false`, or the `input.syslog_strip_bom` / `eval.syslog_strip_bom` config keys, to keep the message byte-for-byte.

### `rstix`: STIX 2.1 + TAXII 2.1 library crate, Phase 1 core foundation (#185)

Introduces `rstix`, a new workspace library crate for native STIX 2.1 and TAXII 2.1 support. This first phase lands the core foundation only; the object model, serialization dispatch, pattern engine, validation pipeline, and graph/marking/store/TAXII runtime behaviours are deferred to later phases.

- **Core primitives** (`rstix::core`): a validated `StixId` in `{type}--{uuid}` form with 42 typed-ID wrappers and SDO/SCO/SRO/Meta kind discriminants; `StixTimestamp` and `TaxiiTimestamp`, where `StixTimestamp` preserves fractional-second precision for round-tripping but compares and hashes by instant so the same moment with different digit widths is treated as equal; `Confidence` plus six interchange scales (None/Low/Medium/High, Admiralty, 0-10, WEP, DNI, MISP); `SpecVersion`; `LanguageTag`; and the `QueryableStixObject` / `QueryValue` query traits.
- **Deterministic SCO IDs** (`rstix::id`): `generate_sco_id` derives UUIDv5 identifiers from RFC 8785 (JCS) canonicalized contributing properties under the STIX namespace. Per-type property selection follows STIX 2.1, including single-hash selection by preference order, the spec-mandated UUIDv4 fallback for `process` and for objects with no contributing properties present, and a first-available-hash fallback for non-preferred algorithms. The generated IDs are pinned against python-stix2 golden vectors.
- **Vocabulary tables** (`rstix::vocab`): open and closed STIX controlled vocabularies and the ordered `OpinionValue` enum, backed by compile-time `phf` sets.
- **Surface**: `#![forbid(unsafe_code)]`, a single default `serde` feature, and `parse_bundle` reserved as a `NotImplemented` entry point for the next phase. The workspace crate map, architecture page, and feature-flags reference are updated for the new crate.

### Gated match-detail enrichment for detection results (#186)

`matched_fields` entries can now explain *why* each field matched, gated behind a new opt-in verbosity level so the default wire shape is byte-for-byte unchanged.

- **New `MatchDetailLevel { Off, Summary, Full }`** on `rsigma-eval`, configured via `Engine::set_match_detail` (and the `CorrelationEngine` passthrough). `Off` is the default and preserves the historical `{field, value}` shape exactly; all new keys are `Option`/skipped on serialization, so existing sinks, the daemon NDJSON wire format, and the golden tests are unaffected unless a caller opts in.
- **`Summary`** adds `selection` (the originating named detection), `matcher` (a new `MatcherKind` enum: `exact`, `contains`, `startswith`, `endswith`, `regex`, `one_of`, `cidr`, `numeric`, `exists`, `fieldref`, `null`, `bool`, `expand`, `timestamp`, `keyword`), and `case_sensitive`. **`Full`** additionally records `pattern`, the value the matcher tested against (truncated for very long pattern sets). Negated matchers set `negated: true`.
- **Closed two long-standing reporting gaps** (visible only at `Summary`/`Full`, so `Off` is untouched): keyword detections, which previously contributed nothing to `matched_fields`, are now reported under the sentinel field `"keyword"`; and `null`-on-absent matches, previously invisible because the field had no value, are now reported with `value: null`.
- **New `CompiledMatcher::describe()`** (returning `MatchDescriptor`) produces the structural description used to populate these fields. It runs only when a rule matches and only above `Off`, so the non-matching hot path is unchanged.
- **CLI/runtime plumbing**: `rsigma engine eval --match-detail <off|summary|full>`, `rsigma engine daemon --match-detail <…>` plus the `daemon.engine.match_detail` config key, and `RuntimeEngine::set_match_detail` (carried across hot reloads).

[v0.14.0...v0.15.0](https://github.com/timescale/rsigma/compare/v0.14.0...v0.15.0)

## [0.14.0] - 2026-06-05

**TL;DR**
RSigma v0.14.0 is the "layered config, structured output, and correctness/hardening" release:
* Layered YAML configuration with explicit precedence (flag > env > project > user > system > default) plus a new `rsigma config` group (`init`, `validate`, `show`, `schema`, `path`, `reload`).
* Structured output everywhere: a global `--output-format <json|ndjson|table|csv|tsv>` selector with a TTY-aware default, plus global `--color`, `--quiet`, and `--no-stats`.
* Custom linter tag namespaces via a repeatable `--tag-namespace` flag and a `tag_namespaces` config key, so organisation-specific tags no longer force disabling `unknown_tag_namespace` wholesale, thanks to @fwosar.
* Sigma correctness: multi-field `value_count` composite keys, compile-time rejection of multi-field numeric aggregations, empty `value_median` returns `None`, cross-crate detection-name selector consistency, and convert-side rejection of modifiers it cannot express.
* Runtime hardening: a category-based HTTP egress policy (SSRF/cloud-metadata defense applied at DNS resolution), a 10 MiB enricher response cap, hot-reload that preserves engine tuning, and fail-closed dynamic-source resolution.
* Evaluator and parser robustness: compile-time rejection of conflicting detection-modifier combinations, allocation-free `JsonEvent` dot-path traversal, and CLI diagnostics that stop silently swallowing invalid `status` / `level` / `related:` metadata.
* Detached dynamic sources: pipeline-embedded `sources:` now warns louder on stderr and through the daemon hot-reload path.
* Release pipeline, CI, Docker, and supply-chain hardening before publish, two batched Dependabot rollups, and a docs-accuracy sweep across the site.

### Documentation accuracy: TLS, feature flags, metric and lint counts, CLI surface, endpoint inventory, benchmark freshness (#181)

A docs-only sweep that closes the accuracy gaps that accumulated over the v0.13.x line. No source code changes; every fix points the documentation at the actual behaviour that ships in the binary.

- **Daemon TLS is no longer described as roadmap.** `docs/reference/http-api.md` and `docs/reference/architecture.md` previously told operators that in-process TLS termination was planned and linked to issue #128. The `daemon-tls` Cargo feature, the `--tls-cert` / `--tls-key` / `--tls-client-ca` / `--tls-min-version` flag set, and the SIGHUP cert hot-reload all shipped in the v0.14.0 release window; both pages now point at the existing `security.md#tls-termination-for-the-api-listener` write-up instead.
- **Feature flag catalogue matches the manifest again.** `docs/reference/feature-flags.md` opened by claiming a workspace of seven crates (it has been six since the binary / `rsigma-cli` split). The `daemon-tls` row listed `rustls-pemfile` as a pulled-in dependency; the actual manifest pulls `rustls`, `tokio-rustls`, `rustls-pki-types`, `x509-parser`, `hyper`, `hyper-util`, and `tower-service`. The "per-feature CI matrix" section described a per-feature opt-in matrix that does not exist in `.github/workflows/ci.yml` today (CI runs `--all-features` plus the three-OS test matrix). All three drifts are corrected, and the production-recommended `cargo install` recipe now includes `daemon-tls`.
- **Metric counts agree across the three pages that publish them.** `docs/reference/metrics.md` headlined "30 metric names across four concerns" while its own section headings summed to 37 rows; the actual registry in `crates/rsigma-cli/src/daemon/metrics.rs` exposes 38 metric names under `--all-features` (33 always-present plus 3 OTLP and 2 TLS gated on the matching build features), grouped into seven concerns. Engine core is 17 metrics, not 16. `docs/guide/streaming-detection.md` and `docs/guide/observability.md` propagated the stale "27" number; both are now aligned, and observability gains the previously missing enrichment (6) and TLS (2) rows.
- **Lint rule counts are honest.** `docs/reference/lint-rules.md` claimed 66 built-in checks; one of them (`empty_filter_rules`) is enum-only and not emitted in production. Page now reads "65 built-in checks plus 1 reserved enum value". The "Filter rules (7)" heading was actually a table of 8 rows including the reserved variant -- relabelled "Filter rules (8 IDs, 7 emitted)". The "Detection-modifier hygiene (5)" heading listed 7 rows that are not duplicates of the detection section above -- relabelled "Detection-modifier hygiene (7)" with the misleading "subset of the detection rules above" wording removed.
- **CLI global flags are fully documented.** `docs/cli/index.md` listed only `--log-format` and asserted "every subcommand accepts one global flag", missing the other four globals (`--output-format`, `--color`, `--quiet`, `--no-stats`) that have shipped alongside it. The overview now describes all five with their defaults, accepted values, effect, and the layered **flag > env > config > default** precedence model. The command tree gains the previously omitted `rule migrate-sources` entry, and `docs/cli/rule/lint.md` drops the stale command-local `--color` flag (color is global now) and documents the four machine renderers (`json`, `ndjson`, `csv`, `tsv`) the lint command honours when `--output-format` is set explicitly.
- **Command-group overviews list every group.** `docs/getting-started/concepts.md` claimed "the five command groups" but the table only listed four (`engine`, `rule`, `backend`, `pipeline`); add the missing `config` row with its six subcommands (`init`, `validate`, `show`, `schema`, `path`, `reload`). The `rule` row picks up `migrate-sources`. `docs/reference/output.md` drops `rule validate` from the `table` output consumers (the command always prints its bespoke per-file summary regardless of `--output-format`) and spells that out so operators are not surprised when the selector does nothing on that command.
- **`POST /api/v1/sources/resolve/{source_id}` is in the HTTP API inventory.** The daemon registers both the body variant (`/api/v1/sources/resolve` with a JSON body that names one source) and the path-parameter variant (`/api/v1/sources/resolve/{source_id}` with no body). Only the body variant was documented; the path variant now appears in both the summary table and a short body section with the success response (`200 {"status":"resolve_triggered","source_id":"..."}`) and the two failure responses (`404` when no dynamic sources are configured, `429` when a refresh for the same source is still in flight).
- **Benchmark figures are labelled as captured on v0.9.0.** `BENCHMARKS.md` (and the docs-site mirror `docs/benchmarks.md` that includes it) carried `Date: 2026-05-07` / `Version: 0.9.0` headers; the workspace has since shipped through v0.13.0 and parts of the hot path have moved. Relabel as "Date captured" / "Captured on version" and add a one-paragraph freshness admonition that asks anyone refreshing the numbers to update the metadata block in the same commit.
- **Site-level loose ends.** The `llmstxt` plugin block in `mkdocs.yml` now lists `rule/migrate-sources`, every `cli/config/*` page, `reference/output.md`, `reference/configuration.md`, and `guide/enrichers.md` -- five public pages that an LLM consuming the generated `llms.txt` had no way to surface before. `docs/developers/testing.md` had a stale CLI E2E table ("12 files / 167 tests") that missed seven files added since (`cli_config.rs`, `cli_daemon_enrichment.rs`, `cli_daemon_fields_observer.rs`, `cli_daemon_tls.rs`, `cli_migrate_sources.rs`, `cli_output_format.rs`, `cli_sources_deprecation.rs`); the page now lists 19 files with their per-file test counts and asks readers to verify the exact total against their tree rather than copy a stale number forward.

### Eval and convert internals: modifier validation, dot-path perf, golden routing (#180)

Three independent quality fixes for the evaluator and converter that all surface bugs the previous code silently swallowed or paid an avoidable allocation for.

**Conflicting modifier combinations are now rejected at compile time.** `compile_detection_item` previously turned the parsed modifier list into a flat boolean context and dispatched through `compile_value` in a fixed precedence order. Whichever flag the dispatch checked first won, so a rule declared as `Field|cidr|contains` silently produced a CIDR match with `contains` dropped, `Field|re|contains` produced a regex match with `contains` dropped, `Field|gt|contains` ran the numeric comparison and dropped `contains`, `Field|exists|contains` collapsed to an existence check that dropped both the substring matcher and the value, `Field|wide|utf16` silently picked whichever UTF-16 dialect the dispatch implemented first, and `Field|i` with no `|re` silently became a no-op. The rules still compiled, still matched something, but the semantics were never what the author wrote. A new `validate_modifiers` pass runs before `compile_value` and rejects five categories of contradiction: more than one operator per item (the operator set spans `contains` / `startswith` / `endswith` / `re` / `cidr` / `exists` / `fieldref` / `gt` / `gte` / `lt` / `lte` and every timestamp part); more than one UTF-16 encoding from `wide` / `utf16` / `utf16be`; `base64` together with `base64offset`; any value transformation (`base64` / `base64offset` / `wide` / `utf16` / `utf16be` / `windash` / `expand`) on a field that also carries a non-string operator that does not consume the transformed value; and the regex flag modifiers (`|i` / `|m` / `|s`) without `|re`. Legal combinations stay legal: `|re|i|m|s`, `|base64|wide`, `|contains|cased`, `|contains|all` with multiple values, `|contains|neq`, `|re|neq`, and a single timestamp part all continue to compile. Errors flow through the existing `EvalError::InvalidModifiers` variant with a message that lists every offending modifier so the rule author can pick which one to drop. The full SigmaHQ corpus (`rules/` plus `rules-compliance/` plus `rules-emerging-threats/` plus `rules-placeholder/` plus `rules-threat-hunting/`, ~3.7k detection rules at the pinned CI SHA) compiles unchanged.

**`JsonEvent` dot-path traversal no longer allocates per lookup.** `JsonEvent::get_field` is called once per detection item per event for every nested-field rule (`process.command_line`, `actor.id`, …) and also drives keyword scans, group-key extraction for correlation, value-count and numeric aggregation field reads, FieldRef matchers, and timestamp extraction. The dot-notation branch previously did `let parts: Vec<&str> = path.split('.').collect();` and walked the slice, allocating a small vector on every lookup whose only purpose was to be sliced once per recursion. The walker now consumes the leading segment with `str::split_once('.')` on each recursion and re-passes the unconsumed path on the array branch (matching the existing OR semantics for `events.actors.name` style lookups). The pathological trailing-dot case (`a.b.`) and consecutive-dot case (`a..b`) keep matching `None` rather than falsely returning the leaf or panicking; two regression tests cover both inputs.

**Postgres and LynxDB goldens are now routed through `convert_collection`.** Both runners previously parsed the `SigmaCollection` and called `Backend::convert_rule` in a loop, bypassing the orchestration layer that the `rsigma backend convert` CLI uses. The gap meant that pipeline-state plumbing, per-rule error collection, and the `_rule_tables` / `_rule_schemas` / `_rule_queries` correlation map injection were never exercised by the goldens. Both `tests/golden_postgres.rs` and `tests/golden_lynxdb.rs` now invoke `convert_collection(&backend, &collection, &[], "default")` and assert on the flattened query output, with a hard assertion on `output.errors.is_empty()` so a silent partial conversion now fails the test instead of producing an empty `actual` string. The 20 existing goldens (11 Postgres, 9 LynxDB) pass unchanged.

### Parser and CLI diagnostics: invalid metadata, output controls, panic-free migrate (#179)

Tightens five small but visible cracks in the parser and CLI surface that all silently swallowed problems an operator was almost certainly trying to catch.

**Invalid `status` / `level` and malformed `related:` entries are now surfaced.** `parse_detection_rule`, `parse_correlation_rule`, and `parse_filter_rule` previously coerced any unparseable `status:` or `level:` into a silent `None` (`get_str(m, "status").and_then(|s| s.parse().ok())`), and `parse_related` `filter_map`ped away any item that was not a mapping, was missing `id`/`type`, or carried an unknown `type`. A typo such as `status: stabel` or `type: derved` round-tripped to the in-memory rule with the field absent and no diagnostic. The parsers now thread a `&mut Vec<String>` for warnings, push index-qualified messages (`related[2] invalid type 'derved' (expected one of: derived, obsolete, merged, renamed, similar)`), and let `parse_sigma_yaml` extend `SigmaCollection.errors` with the result. Existing CLI surfaces (`rule parse`, `rule validate`, the "Loaded rules" path) already render `collection.errors`, so the new warnings flow through unchanged.

**New `SigmaCollection` ergonomics.** Three helpers cover the "treat any error as failure" path that downstream callers were re-implementing each time: `SigmaCollection::has_errors()`, `SigmaCollection::error_count()`, and `SigmaCollection::into_result()` (consumes the collection and returns `Err(Vec<String>)` when anything failed, `Ok(self)` on a clean parse). The stale doc on the `errors` field that referenced a non-existent `collect_errors` flag is replaced with the actual contract.

**`rule lint` honours `--quiet` and `--no-stats`.** Both global flags had no effect on the human renderer, so CI scrapers that piped only findings still got a "Loaded lint config: …" progress line on stderr and a "Checked N file(s): … passed, … failed" trailing summary on stdout. The summary block is now gated by `OutputCtx::show_stats()` and the config-load progress by `show_progress()`; findings still print under both flags. The structured `tracing::info!("Lint summary", …)` event continues to fire so log-based consumers still see the per-run totals.

**Invalid `global.output_format` / `global.color` config values now warn instead of silently falling back.** A typo like `output_format: xml` or `color: rainbow` in the YAML config used to bypass the `OutputFormat::parse` / `ColorChoice::parse` filter, return `None`, and revert the operator to the TTY-aware defaults with no signal. A new `output::warn_invalid_global_output` wrapper between `config::discovered_global_output` and `OutputCtx::resolve` validates both strings, emits a stderr warning that lists the accepted alternatives, and strips the bad value so the resolver still falls back cleanly. The command itself still succeeds because the warning is informational.

**`rule migrate-sources` no longer panics on a pipeline read race.** After writing the extracted `sources.yml`, the rewrite loop in `cmd_migrate_sources` re-read each pipeline file with `std::fs::read_to_string(path).unwrap()`. A file deleted between scan and rewrite (or a permission flip on a flaky filesystem) crashed the CLI. The read now matches the soft-error pattern the `std::fs::write` call below it already used: print a `warning:` line, skip the offending pipeline, and keep going. The extracted sources file is already on disk at that point, so a single unreadable pipeline does not invalidate the other rewrites.

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

### Dependency bumps (#178)

Rolls up eight open Dependabot PRs into a single merge. Docker: the `rust:1-alpine` base image digest moves from `606fd31` to `66f48b1` (#169). CI (all repinned by commit SHA, batched via the `actions-updates` group, #177): `taiki-e/install-action` 2.79.3 to 2.79.12, `EmbarkStudios/cargo-deny-action` 2.0.18 to 2.0.20, `docker/setup-buildx-action` 4.0.0 to 4.1.0, `docker/login-action` 4.1.0 to 4.2.0, `github/codeql-action` 4.35.5 to 4.36.0, and `docker/metadata-action` 6.0.0 to 6.1.0. Rust (workspace `Cargo.lock`): `log` 0.4.29 to 0.4.30 in the `patch-updates` group (#173), `async-nats` 0.48.0 to 0.49.0 (#174), and `hyper` 1.9.0 to 1.10.0 (#175). VS Code extension: `@types/vscode` ^1.116.0 to ^1.120.0, `@vscode/vsce` ^3.9.0 to ^3.9.1, and `esbuild` ^0.27.7 to ^0.28.0 in the `npm-updates` group (#170); `typescript` ^5.9.3 to ^6.0.3 (#171); `@types/node` ^20.19.39 to ^25.9.1 (#172). The three VS Code PRs all touched `editors/vscode/package.json` and `package-lock.json`; resolved by keeping the newest version from each PR and regenerating the lockfile with `npm install --package-lock-only --ignore-scripts`. The `rusqlite` 0.39.0 to 0.40.0 bump (#176) is deliberately deferred: it pulls in `libsqlite3-sys` 0.38.0, whose `build.rs` uses the `cfg_select!` macro that is not stable on the workspace MSRV of 1.88.0. It will be re-batched once MSRV is raised.

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

[0.18.0]: https://github.com/timescale/rsigma/releases/tag/v0.18.0
[0.17.0]: https://github.com/timescale/rsigma/releases/tag/v0.17.0
[0.16.0]: https://github.com/timescale/rsigma/releases/tag/v0.16.0
[0.15.0]: https://github.com/timescale/rsigma/releases/tag/v0.15.0
[0.14.0]: https://github.com/timescale/rsigma/releases/tag/v0.14.0
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
