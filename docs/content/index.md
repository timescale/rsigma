---
title: "RSigma: Sigma Detection Engineering Toolkit in Rust"
titleAppend: false
description: "RSigma is a Rust toolkit for Sigma detection rules: parse, lint, evaluate, correlate, and convert rules, and run a streaming detection daemon from one binary."
toc: false
---

::: hero layout:split glow:true
# Sigma detection engineering in one Rust binary

Parse, lint, evaluate, correlate, and convert [Sigma](https://sigmahq.io/) rules from a single self-contained binary or embeddable Rust workspace. Built on open standards: [Sigma v2.1.0](https://github.com/SigmaHQ/sigma-specification/tree/0c857d07da0e71eaaab2d667b3cce6f2c8469578/specification), [OpenTelemetry](https://opentelemetry.io/), and [STIX](https://oasis-open.github.io/cti-documentation/stix/intro)/[TAXII](https://oasis-open.github.io/cti-documentation/taxii/intro).

::: tag "v{{ rsigma.version }}" icon:tag ::: ::: tag "MIT" icon:scale ::: ::: tag "{{ rsigma.lint.rules }} lint rules" icon:shield-check ::: ::: tag "All 8 correlations" icon:git-branch ::: {.rsigma-hero-tags}

::: button "Quick Start" url:"./getting-started/quick-start/" icon:rocket ::: ::: button "Install" url:"./getting-started/installation/" icon:download ::: ::: button "GitHub" url:"https://github.com/timescale/rsigma" icon:external-link :::

== side

::: tabs
::: tab "Evaluate" icon:terminal
```bash
rsigma engine eval --pretty -r rules/ \
  -e '{"CommandLine":"cmd /c whoami"}'
```
```json
{
  "rule_title": "Suspicious whoami invocation",
  "level": "medium",
  "matched_selections": ["selection"],
  "matched_fields": [
    {"field": "CommandLine", "value": "cmd /c whoami"}
  ]
}
```
:::
::: tab "Daemon" icon:radio
```bash
rsigma engine daemon -r rules/ -p ecs_windows \
  --input http --api-addr 127.0.0.1:9090
```
Runs continuously with hot-reload, SQLite-backed correlation windows, NATS/OTLP/HTTP/stdin ingest, enrichers, risk-based alerting, and Prometheus metrics.
:::
::: tab "Convert" icon:database
```bash
rsigma backend convert rules/ -t postgres
```
```sql
SELECT * FROM security_events
WHERE "CommandLine" ILIKE '%whoami%'
```
Native PostgreSQL/TimescaleDB, LynxDB, and Fibratus targets, plus 30+ pySigma backends via `sigma-cli`.
:::
::: tab "Rust" icon:code
```rust
let collection = parse_sigma_yaml(yaml)?;
let mut engine = Engine::new();
engine.add_collection(&collection)?;
let matches = engine.evaluate(
    &JsonEvent::borrow(&event),
);
```
Workspace of {{ rsigma.crate_count }} published crates on [crates.io](https://crates.io/crates/rsigma), plus [WebAssembly](reference/wasm-abi.md) support.
:::
:::
:::

## Install in one command {#install}

::: tabs
::: tab "Prebuilt binary" icon:download
```bash
curl -fsSL -o rsigma.tar.gz \
  https://github.com/timescale/rsigma/releases/download/v{{ rsigma.version }}/rsigma-x86_64-unknown-linux-gnu.tar.gz
tar -xzf rsigma.tar.gz && sudo install -m 0755 rsigma /usr/local/bin/rsigma
gh attestation verify rsigma-x86_64-unknown-linux-gnu.tar.gz --repo timescale/rsigma
```
Archives for Linux, macOS, and Windows (x86_64 and arm64) include SLSA build provenance. See [Installation](getting-started/installation.md).
:::
::: tab "Docker" icon:container
```bash
docker pull {{ rsigma.docker_image }}:latest
docker run --rm --read-only --cap-drop=ALL \
  --security-opt=no-new-privileges:true \
  -v /path/to/rules:/rules:ro \
  {{ rsigma.docker_image }}:latest rule validate /rules/
```
Multi-arch (`linux/amd64`, `linux/arm64`) images signed with keyless cosign, SPDX SBOM, and SLSA Build L3 provenance. See [Docker deployment](deployment/docker.md).
:::
::: tab "Cargo" icon:package
```bash
cargo install --locked rsigma
cargo install --locked rsigma-lsp
```
Requires Rust `{{ rsigma.msrv }}` or newer (`{{ rsigma.edition }}` edition). Add `--all-features` to match the release archives.
:::
::: tab "AI agents (MCP + skills)" icon:bot
```bash
rsigma mcp serve --rules-dir rules/
npx skills add timescale/sigma-rules -y && npx skills add timescale/rsigma -y
```
Expose structured tools (`parse_rule`, `lint_rules`, `evaluate_events`, `convert_rules`, ...) to Cursor, Claude Code, and other MCP clients. See [MCP server](guide/mcp-server.md).
:::
:::

## Performance at a glance {#performance}

::: grids
::: card "1.12M events/s" icon:zap
Single-core JSON runtime pipeline (`100` rules); format auto-detect runs at `1.13M events/s`.
:::
::: card "404K events/s" icon:server
End-to-end HTTP daemon across 8 cores with `--logsource-routing` on 3,132 SigmaHQ rules.
:::
::: card "501K events/s" icon:git-branch
Stateful correlation throughput; loading 3,132 rules takes `~0.3 s` and `~113 MB` peak RSS.
:::
::: card "2.85M events/s" icon:layers
Dynamic pipeline detection throughput once built, with zero per-event source resolution cost.
:::
:::

Measured on Apple M4 Pro; full Criterion tables and SigmaHQ corpus methodology live on the [benchmarks](benchmarks.md) page and in [performance tuning](guide/performance-tuning.md).

## One toolkit across the detection lifecycle {#lifecycle}

![RSigma detection engineering loop](../assets/images/detection-loop.svg)

::: grids
::: card "Author and test" icon:pencil-ruler
Draft rules from logs (`rule draft`), propose verified filters (`rule tune`), lint against `{{ rsigma.lint.rules }}` checks with `{{ rsigma.lint.autofix }}` auto-fixes, format (`rule fmt`), get real-time LSP diagnostics, and backtest corpora (`rule backtest`).

[Linting](guide/linting-rules.md) · [Drafting](guide/rule-drafting.md) · [Tuning](guide/rule-tuning.md) · [Backtest](cli/rule/backtest.md)
:::
::: card "Stream and alert" icon:radio
Run `engine daemon` with JSON, syslog, logfmt, CEF, EVTX, and OTLP over HTTP, NATS JetStream, Unix sockets, or stdin. Correlate in SQLite-backed windows, enrich via DNS, MMDB, STIX, or HTTP, score entity risk, group incidents, and send signed webhooks or OCSF findings.

[Streaming daemon](guide/streaming-detection.md) · [Enrichers](guide/enrichers.md) · [Alert pipeline](guide/alert-pipeline.md)
:::
::: card "Hunt and convert" icon:database
Compile rules natively to PostgreSQL/TimescaleDB (five output modes including continuous aggregates), LynxDB, and Fibratus, or delegate 30+ SIEM targets to `sigma-cli`. Run read-only `hunt run` queries against archives and feed matches straight back into `rule draft` and `rule backtest`.

[Rule conversion](guide/rule-conversion.md) · [Hunting](guide/hunting.md) · [CLI Reference](cli/index.md)
:::
::: card "Measure and govern" icon:bar-chart-2
Export MITRE ATT&CK Navigator layers (`rule coverage`), score data-source maturity with DeTT&CT (`rule visibility`), inspect live field drift, fuse signals into keep/tune/retire verdicts (`rule scorecard`), and gate PRs with `timescale/rsigma-action`.

[Scorecard](guide/detection-scorecard.md) · [ATT&CK coverage](guide/attack-coverage.md) · [CI/CD](guide/ci-cd.md)
:::
:::

## Why RSigma {#why-rsigma}

RSigma combines pySigma-style conversion with a stateful streaming evaluator in one self-contained binary.

| | RSigma | pySigma | sigma_engine | sigma-rust |
|---|---|---|---|---|
| **Language** | Rust | Python | Rust | Rust |
| **Runtime evaluation** | Yes (streaming + stateful) | No (converter only) | Yes (stateless) | Yes (stateless) |
| **Correlation rules** | All 8 types | Partial | No | No |
| **Filter rules** | Yes | Yes | No | No |
| **Conversion backends** | PostgreSQL, LynxDB, Fibratus natively; pySigma backends through sigma-cli | 30+ | No | No |
| **Streaming daemon** | Yes (NATS, HTTP, OTLP) | No | No | No |
| **Dynamic pipelines** | Yes (HTTP, file, command, NATS) | Yes (HTTP, file, command) | No | No |
| **Built-in linter** | {{ rsigma.lint.rules }} rules, auto-fix | Limited | No | No |
| **LSP and MCP servers** | Yes | No | No | No |
| **Single binary** | Yes (multi-arch, signed) | No (requires Python) | Library only | Library only |
| **License** | MIT | LGPL-3.0 | AGPL-3.0 | MIT |

## Built with RSigma {#built-with-rsigma}

::: grids
::: card "Detection engines and EDR" icon:shield
- **[AxoDetect](https://axoflow.com/axodetect)** (Commercial): Axoflow's detection workbench running Sigma rules in-stream inside its security data pipeline.
- **[Rustinel](https://github.com/Karib0u/rustinel)** (Apache-2.0): Cross-platform endpoint detection engine with RSigma as its Sigma backend for live telemetry.
- **[Kestrel EDR](https://github.com/lawbyte/kestrel-edr)** (Apache-2.0): Self-hosted Windows EDR evaluating custom and SigmaHQ rules on-device.
- **[Garmr](https://github.com/hentorp/garmr)** (AGPL-3.0/commercial): Self-hosted application-audit and insider-risk platform using RSigma for per-event detection.
:::
::: card "Telemetry, forensics, and pipelines" icon:activity
- **[Sluice](https://github.com/Dr1nS0menOp/SLUICE)** (AGPL-3.0): Generates Vector configs that trim SIEM ingest while proving with RSigma that Sigma detections and correlations still fire.
- **[mozu](https://github.com/fukusuket/mozu)** (AGPL-3.0): Windows NTFS forensic triage from `$MFT` and `$UsnJrnl:$J` matching file records against Sigma rules.
- **[LocalObserve](https://github.com/JJediny/LocalObserve)**: Local-first Linux security observability stack using RSigma for edge detection and webhooks.
- **[LogsTotal](https://github.com/wagga40/LogsTotal)** (MIT): Self-hosted log analysis platform comparing findings across multiple Sigma engines.
:::
::: card "Authoring, CTI, and testing" icon:wrench
- **[detection.studio](https://github.com/northsh/detection.studio)** (MIT): Browser-based Sigma playground with real-time evaluation via RSigma compiled to WebAssembly.
- **[Sigmacatch](https://github.com/frack113/sigmacatch)** (MIT): Captures live Windows Event Log events, matches them with RSigma, and writes SigmaHQ regression data.
- **[sagan2sigma](https://github.com/NRGLine4Sec/sagan2sigma)** (GPL-2.0): Converts Sagan rules to Sigma and verifies them with RSigma.
- **[Sheut](https://github.com/PerceptraHQ/sheut-community)** (MPL-2.0): Local-first CTI workbench using RSigma for STIX 2.1 validation and interchange.
:::
:::

## Featured in {#featured-in}

::: grids
::: card "DEW #149 (March 2026)" icon:quote
"RSigma is essentially a SIEM. Building a tool like RSigma is challenging because the Sigma specification has evolved into a robust domain-specific language over the years."

[Read issue](https://www.detectionengineering.net/i/191079258/detection-engineering-gem)
:::
::: card "tl;dr sec #320 (March 2026)" icon:quote
"Accurately evaluating the full spectrum of what Sigma rules can express is quite complex. It's pretty neat to read about how RSigma handles all of these conditional expressions, correlating across rules, etc."

[Read issue](https://tldrsec.com/p/tldr-sec-320#blue-team)
:::
::: card "DEW #157 (May 2026)" icon:quote
"Instead of hardcoding IOC values in rule YAML, you declare external sources in the pipeline config, and RSigma fetches and injects them at evaluation time."

[Read issue](https://www.detectionengineering.net/p/dew-157-shai-hulud-goes-open-source)
:::
:::

::: collapsible "More coverage and newsletter mentions"
- **[The Deep Purple Sec by BlackNoise](https://www.blacknoise.co/the-deep-purple-sec-march-2026/)** (March 2026): "Defensive teams can pipe logs through CLI commands, apply field-mapping pipelines, and chain correlations for multi-stage attack detection."
- **[DEW #154](https://www.detectionengineering.net/i/195467950/state-of-the-art)** (April 2026): "RSigma is not a SIEM, but it's an impressive feat to build a self-contained Rust binary that operates much like one. For teams doing pre-SIEM rule validation or forensics, it's a solid plug-and-play option."
- **[This Week in Rust 663](https://this-week-in-rust.org/blog/2026/08/05/this-week-in-rust-663/)** (August 2026): Featured the [RSigma v0.20.0 release](https://github.com/timescale/rsigma/releases/tag/v0.20.0), [The State of RSigma](https://mostafa.dev/the-state-of-rsigma-7ba0a99020d9), and [Part Two: The Loop](https://mostafa.dev/the-state-of-rsigma-part-two-the-loop-c114f379dd78).
- **[Rust Bytes #139](https://weeklyrust.substack.com/p/whats-new-in-1990)** (October 2026): Featured RSigma in the Project Spotlight.
:::

## Talks and deep dives {#talks-and-deep-dives}

::: tabs
::: tab "Talks" icon:video
| Event | Talk | Topic | Materials |
|-------|------|-------|-----------|
| Linux Security Summit Europe 2026 | [Detection Engineering with RSigma](https://lsseu2026.sched.com/event/2WHc4) | One Linux detection from auditd and Tetragon telemetry through normalization, portable Sigma evaluation, stateful correlation, fixture-based testing, and deployment | [Video](https://www.youtube.com/watch?v=cqeYdA39qv0), [slides](https://hosted-files.sched.co/lsseu2026/d0/talk.pdf), [demo and materials](https://github.com/mostafa/rsigma-lss-eu-2026-talk) |
:::
::: tab "Selected articles" icon:book-open
| Article | Topic |
|---------|-------|
| [The State of RSigma](https://mostafa.dev/the-state-of-rsigma-7ba0a99020d9) | A tour of everything RSigma does today and where it is headed |
| [The State of RSigma, Part Two: The Loop](https://mostafa.dev/the-state-of-rsigma-part-two-the-loop-c114f379dd78) | One detection walked end to end through every station (Okta MFA reset to account takeover) |
| [Building a Detection Layer on PostgreSQL with Sigma Rules](https://mostafa.dev/building-a-detection-layer-on-postgresql-with-sigma-rules-042caeb42b2a) | Five PostgreSQL output formats and TimescaleDB continuous aggregates |
| [Detection-as-Code in One GitHub Action with RSigma](https://mostafa.dev/detection-as-code-in-one-github-action-with-rsigma-0ebfb4c857fa) | Gating a Sigma rule repository in CI with lint, validate, fields-drift, backtest, and ATT&CK coverage |
:::
::: tab "Full 9-part series" icon:list
| # | Article | Topic |
|---|---------|-------|
| 1 | [Pattern Detection and Correlation in JSON Logs](https://mostafa.dev/pattern-detection-and-correlation-in-json-logs-fab16334e4ee) | Forensic investigation of a Trivy supply-chain compromise |
| 2 | [Streaming Logs to RSigma for Real-Time Detection](https://mostafa.dev/streaming-logs-to-rsigma-for-real-time-detection-72084b8041ad) | Okta cross-tenant impersonation via the daemon and NATS JetStream |
| 3 | [Building a Detection Layer on PostgreSQL with Sigma Rules](https://mostafa.dev/building-a-detection-layer-on-postgresql-with-sigma-rules-042caeb42b2a) | Five PostgreSQL output formats and TimescaleDB continuous aggregates |
| 4 | [Security Observability with RSigma and the LGTM Stack](https://mostafa.dev/security-observability-with-rsigma-and-the-lgtm-stack-375ccd260795) | Pairing RSigma with Loki, Mimir, and Grafana |
| 5 | [Wiring Live Threat Intel into Sigma Detection with Dynamic Pipelines](https://mostafa.dev/wiring-live-threat-intel-into-sigma-detection-with-dynamic-pipelines-4de29b4af7ca) | Dynamic pipelines: HTTP, file, command, and NATS sources |
| 6 | [Cloud Detection at Scale on a Laptop](https://mostafa.dev/cloud-detection-at-scale-on-a-laptop-e46540322856) | Running cloud-scale detection locally with RSigma |
| 7 | [The State of RSigma](https://mostafa.dev/the-state-of-rsigma-7ba0a99020d9) | A tour of everything RSigma does today and where it is headed |
| 8 | [Detection-as-Code in One GitHub Action with RSigma](https://mostafa.dev/detection-as-code-in-one-github-action-with-rsigma-0ebfb4c857fa) | Gating a Sigma rule repository in CI with lint, validate, fields-drift, backtest, and ATT&CK coverage |
| 9 | [The State of RSigma, Part Two: The Loop](https://mostafa.dev/the-state-of-rsigma-part-two-the-loop-c114f379dd78) | One detection through the full lifecycle: author, test, deploy, detect, alert and triage, measure, and hunt |
:::
:::

## Where to go next {#next-steps}

::: grids
::: card "Quick Start" icon:clock
Write a rule, evaluate an event, run the daemon with hot-reload, and convert to SQL in three minutes.

[Start the tutorial](getting-started/quick-start.md)
:::
::: card "Core Concepts" icon:book-open
Learn how Sigma detection, correlation, and filter rules map to `engine eval`, `engine daemon`, and pipelines.

[Read core concepts](getting-started/concepts.md)
:::
::: card "Library API" icon:code
Embed `rsigma-parser`, `rsigma-eval`, `rsigma-convert`, `rsigma-runtime`, `rsigma-mcp`, or `rstix` in Rust.

[Browse library docs](library/index.md)
:::
::: card "Architecture" icon:cpu
Trace how rules flow from YAML through the AST, HIR, compiled engine, sinks, and WASM ABI.

[Explore architecture](reference/architecture.md)
:::
:::

Latest release: `v{{ rsigma.version }}` (MIT licensed, {{ rsigma.crate_count }} crates, Rust `{{ rsigma.msrv }}`, edition `{{ rsigma.edition }}`). See [release notes and version tags](release-notes.md#version-tags) or the [security policy](security-policy.md).
