# Welcome to RSigma's documentation!

[![CI](https://github.com/timescale/rsigma/actions/workflows/ci.yml/badge.svg)](https://github.com/timescale/rsigma/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/rsigma)](https://crates.io/crates/rsigma)
[![MSRV](https://img.shields.io/badge/MSRV-{{ rsigma.msrv }}-blue)](https://github.com/timescale/rsigma/blob/main/Cargo.toml)
[![Docker](https://img.shields.io/badge/ghcr.io-rsigma-blue?logo=docker)](https://ghcr.io/timescale/rsigma)
[![GitHub Release](https://img.shields.io/github/v/release/timescale/rsigma)](https://github.com/timescale/rsigma/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

Hello, and welcome to RSigma's documentation.

RSigma is a complete Rust toolkit for the [Sigma](https://sigmahq.io/) detection standard, including a parser, evaluation engine, rule conversion, streaming runtime, linter, CLI, and LSP server. Or, as Zack Allen put it in [Detection Engineering Weekly #149](https://www.detectionengineering.net/i/191079258/detection-engineering-gem), "RSigma is essentially a SIEM."

<div class="grid cards" markdown>

- :material-download:{ .lg .middle } **Install RSigma**

    ---

    Install RSigma with Cargo, Docker, or a signed binary archive.

    [:octicons-arrow-right-24: Installation steps](./getting-started/installation.md)

- :material-clock-fast:{ .lg .middle } **Quickstart**

    ---

    Write a rule, evaluate it, run the daemon, and convert to SQL in five minutes.

    [:octicons-arrow-right-24: Getting started](./getting-started/quick-start.md)

- :material-book-open-page-variant:{ .lg .middle } **Core concepts**

    ---

    Sigma rules, processing pipelines, the eval/daemon split, and the noun-led CLI groups.

    [:octicons-arrow-right-24: Core concepts](./getting-started/concepts.md)

- :material-console:{ .lg .middle } **CLI Reference**

    ---

    Per-subcommand reference for `engine`, `rule`, `backend`, and `pipeline`.

    [:octicons-arrow-right-24: CLI Reference](./cli/index.md)

- :material-database-search:{ .lg .middle } **Rule conversion**

    ---

    Generate PostgreSQL or LynxDB queries from Sigma rules for historical hunting.

    [:octicons-arrow-right-24: Rule conversion](./guide/rule-conversion.md)

- :material-radio-tower:{ .lg .middle } **Streaming detection**

    ---

    Run the daemon with NATS, HTTP, or OTLP input. Hot-reload, metrics, state.

    [:octicons-arrow-right-24: Streaming detection](./guide/streaming-detection.md)

</div>

## Why RSigma

| | RSigma | pySigma | sigma_engine | sigma-rust |
|---|---|---|---|---|
| **Language** | Rust | Python | Rust | Rust |
| **Runtime evaluation** | Yes (streaming + stateful) | No (converter only) | Yes (stateless) | Yes (stateless) |
| **Correlation rules** | All 8 types | Partial | No | No |
| **Filter rules** | Yes | Yes | No | No |
| **Conversion backends** | PostgreSQL, LynxDB, ... | 20+ | No | No |
| **Streaming daemon** | Yes (NATS, HTTP, OTLP) | No | No | No |
| **Dynamic pipelines** | Yes (HTTP, file, command, NATS) | No | No | No |
| **Built-in linter** | 66 rules, auto-fix | Limited | No | No |
| **LSP server** | Yes | No | No | No |
| **Single binary** | Yes (multi-arch, signed) | No (requires Python) | Library only | Library only |
| **License** | MIT | LGPL-3.0 | AGPL-3.0 | MIT |

RSigma is the only Sigma toolkit that combines pySigma-style conversion with a real streaming evaluator, all in a single self-contained binary.

## Featured in

!!! quote "Detection Engineering Weekly #149 (March 2026)"
    "RSigma is essentially a SIEM. Building a tool like RSigma is challenging because the Sigma specification has evolved into a robust domain-specific language over the years."

    Zack Allen, [DEW #149](https://www.detectionengineering.net/i/191079258/detection-engineering-gem)

!!! quote "tl;dr sec #320 (March 2026)"
    "Accurately evaluating the full spectrum of what Sigma rules can express is quite complex. It's pretty neat to read about how RSigma handles all of these conditional expressions, correlating across rules, etc."

    [tl;dr sec #320](https://tldrsec.com/p/tldr-sec-320#blue-team)

!!! quote "BlackNoise: The Deep Purple Sec, March 2026"
    "Defensive teams can pipe logs through CLI commands, apply field-mapping pipelines, and chain correlations for multi-stage attack detection."

    [BlackNoise](https://www.blacknoise.co/the-deep-purple-sec-march-2026/)

!!! quote "Detection Engineering Weekly #154 (April 2026)"
    "RSigma is not a SIEM, but it's an impressive feat to build a self-contained Rust binary that operates much like one. For teams doing pre-SIEM rule validation or forensics, it's a solid plug-and-play option."

    [DEW #154](https://www.detectionengineering.net/i/195467950/state-of-the-art)

## Read the deep dives

A five-part article series on building RSigma and using it in production:

| # | Article | Topic |
|---|---------|-------|
| 1 | [Pattern Detection and Correlation in JSON Logs](https://mostafa.dev/pattern-detection-and-correlation-in-json-logs-fab16334e4ee) | Forensic investigation of a Trivy supply-chain compromise. |
| 2 | [Streaming Logs to RSigma for Real-Time Detection](https://mostafa.dev/streaming-logs-to-rsigma-for-real-time-detection-72084b8041ad) | Okta cross-tenant impersonation via the daemon and NATS JetStream. |
| 3 | [Building a Detection Layer on PostgreSQL with Sigma Rules](https://mostafa.dev/building-a-detection-layer-on-postgresql-with-sigma-rules-042caeb42b2a) | Five PostgreSQL output formats and TimescaleDB continuous aggregates. |
| 4 | [Security Observability with RSigma and the LGTM Stack](https://mostafa.dev/security-observability-with-rsigma-and-the-lgtm-stack-375ccd260795) | Pairing RSigma with Loki, Mimir, and Grafana. |
| 5 | [Wiring Live Threat Intel into Sigma Detection with Dynamic Pipelines](https://mostafa.dev/wiring-live-threat-intel-into-sigma-detection-with-dynamic-pipelines-4de29b4af7ca) | Dynamic pipelines: HTTP, file, command, and NATS sources. |

## At a glance

- **Latest release:** `v{{ rsigma.version }}` (MIT licensed; six crates in the workspace).
- **MSRV:** Rust `{{ rsigma.msrv }}`, edition `{{ rsigma.edition }}`.
- **Cross-platform binaries:** Linux, macOS, Windows on amd64 and arm64.
- **Container image:** `{{ rsigma.docker_image }}:latest` (multi-arch, cosign-signed, SBOM, SLSA Build L3 provenance).
- **Throughput:** ~1.06M events/sec detection, ~569K events/sec correlation on an Apple M4 Pro. See [benchmarks](benchmarks.md).
