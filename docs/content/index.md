# Welcome to RSigma's documentation!

RSigma is a [Sigma](https://sigmahq.io/) detection engineering toolkit: parser, linter, evaluator, correlation engine, conversion framework, streaming daemon, and MCP and LSP servers. It builds on open industry standards throughout: Sigma for detection rules, [OpenTelemetry](https://opentelemetry.io/) for log ingestion and detection export, and [STIX](https://oasis-open.github.io/cti-documentation/stix/intro) and [TAXII](https://oasis-open.github.io/cti-documentation/taxii/intro) for threat intelligence.

::: grids
::: grid
::: card "Install RSigma" icon:download
Install with a signed binary archive, Docker, or Cargo.

[Installation steps](./getting-started/installation.md)
:::
:::
::: grid
::: card "Quickstart" icon:clock
Write a rule, evaluate it, run the daemon, and convert to SQL.

[Getting started](./getting-started/quick-start.md)
:::
:::
::: grid
::: card "Core concepts" icon:book-open
Sigma rules, processing pipelines, the eval/daemon split, and the noun-led CLI.

[Core concepts](./getting-started/concepts.md)
:::
:::
::: grid
::: card "Detection engineering loop" icon:refresh-cw
Author, test, deploy, detect, alert, measure, and hunt: one map of the full lifecycle.

[The loop](./guide/detection-engineering-loop.md)
:::
:::
::: grid
::: card "CLI Reference" icon:terminal
Per-subcommand reference for `engine`, `rule`, `backend`, `pipeline`, `config`, and `mcp`.

[CLI Reference](./cli/index.md)
:::
:::
::: grid
::: card "Rule conversion" icon:database
Generate PostgreSQL, LynxDB, or Fibratus queries from Sigma rules for historical hunting.

[Rule conversion](./guide/rule-conversion.md)
:::
:::
::: grid
::: card "Streaming detection" icon:radio
Run the daemon with NATS, HTTP, or OTLP input. Hot-reload, metrics, state.

[Streaming detection](./guide/streaming-detection.md)
:::
:::
:::

## Why RSigma

| | RSigma | pySigma | sigma_engine | sigma-rust |
|---|---|---|---|---|
| **Language** | Rust | Python | Rust | Rust |
| **Runtime evaluation** | Yes (streaming + stateful) | No (converter only) | Yes (stateless) | Yes (stateless) |
| **Correlation rules** | All 8 types | Partial | No | No |
| **Filter rules** | Yes | Yes | No | No |
| **Conversion backends** | PostgreSQL, LynxDB, Fibratus | 20+ | No | No |
| **Streaming daemon** | Yes (NATS, HTTP, OTLP) | No | No | No |
| **Dynamic pipelines** | Yes (HTTP, file, command, NATS) | Yes (HTTP, file, command) | No | No |
| **Built-in linter** | {{ rsigma.lint.rules }} rules, auto-fix | Limited | No | No |
| **LSP server** | Yes | No | No | No |
| **Single binary** | Yes (multi-arch, signed) | No (requires Python) | Library only | Library only |
| **License** | MIT | LGPL-3.0 | AGPL-3.0 | MIT |

RSigma combines pySigma-style conversion with a streaming evaluator in one self-contained binary.

## Featured in

| Outlet | Quote |
|--------|-------|
| [DEW #149](https://www.detectionengineering.net/i/191079258/detection-engineering-gem) (March 2026) | "RSigma is essentially a SIEM. Building a tool like RSigma is challenging because the Sigma specification has evolved into a robust domain-specific language over the years." |
| [tl;dr sec #320](https://tldrsec.com/p/tldr-sec-320#blue-team) (March 2026) | "Accurately evaluating the full spectrum of what Sigma rules can express is quite complex. It's pretty neat to read about how RSigma handles all of these conditional expressions, correlating across rules, etc." |
| [BlackNoise](https://www.blacknoise.co/the-deep-purple-sec-march-2026/) (March 2026) | "Defensive teams can pipe logs through CLI commands, apply field-mapping pipelines, and chain correlations for multi-stage attack detection." |
| [DEW #154](https://www.detectionengineering.net/i/195467950/state-of-the-art) (April 2026) | "RSigma is not a SIEM, but it's an impressive feat to build a self-contained Rust binary that operates much like one. For teams doing pre-SIEM rule validation or forensics, it's a solid plug-and-play option." |
| [DEW #157](https://www.detectionengineering.net/p/dew-157-shai-hulud-goes-open-source) (May 2026) | "Instead of hardcoding IOC values in rule YAML, you declare external sources in the pipeline config, and RSigma fetches and injects them at evaluation time." |
| [This Week in Rust 663](https://this-week-in-rust.org/blog/2026/08/05/this-week-in-rust-663/) (August 2026) | Featured the [RSigma v0.20.0 release](https://github.com/timescale/rsigma/releases/tag/v0.20.0) and [The State of RSigma](https://mostafa.dev/the-state-of-rsigma-7ba0a99020d9), and [Part Two: The Loop](https://mostafa.dev/the-state-of-rsigma-part-two-the-loop-c114f379dd78). |

## Built with RSigma

| Project | Role |
|---|---|
| [detection.studio](https://github.com/northsh/detection.studio) | Browser-based Sigma playground with real-time evaluation via RSigma compiled to WebAssembly |
| [Garmr](https://github.com/hentorp/garmr) | Self-hosted application-audit and insider-risk platform using RSigma for per-event Sigma detection |
| [LocalObserve](https://github.com/JJediny/LocalObserve) | Local-first Linux security observability stack using RSigma for edge Sigma detection and webhook alerting |
| [Rustinel](https://github.com/Karib0u/rustinel) | Cross-platform endpoint detection engine with RSigma as an opt-in Sigma backend for live telemetry |
| [sagan2sigma](https://github.com/NRGLine4Sec/sagan2sigma) | Converts Sagan rules to Sigma and verifies them with RSigma |
| [Sheut](https://github.com/PerceptraHQ/sheut-community) | Local-first cyber threat intelligence workbench using RSigma for STIX 2.1 validation and interchange |
| [Sigmacatch](https://github.com/frack113/sigmacatch) | Captures live Windows Event Log events, matches them with RSigma, and writes SigmaHQ-ready regression data |

## Read the deep dives

An article series on building RSigma and using it in production:

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

## At a glance

- **Latest release:** `v{{ rsigma.version }}` (MIT licensed; seven crates in the workspace).
- **MSRV:** Rust `{{ rsigma.msrv }}`, edition `{{ rsigma.edition }}`.
- **Cross-platform binaries:** Linux, macOS, Windows on amd64 and arm64.
- **Container image:** `{{ rsigma.docker_image }}:latest` (multi-arch, cosign-signed, SBOM, SLSA Build L3 provenance).
- **Benchmarks:** detection and correlation throughput numbers live on the [benchmarks](benchmarks.md) page.
