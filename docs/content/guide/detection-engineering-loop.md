# Detection Engineering Loop

Detection engineering spans human judgment (what deserves a detection, what the telemetry shows) and repeatable software work (authoring, testing, deployment, detection, alerting, measurement, hunting). RSigma owns the software phases and exposes clean interfaces to the rest. This page is the map: one revolution of the loop, station by station, with links into the detailed guides.

![RSigma detection engineering loop](../../assets/images/detection-loop.svg)

The **Engineer** cycle (blue) is detection-as-code: turn incident evidence into a linted rule, prove it against history, and ship it through CI. The **Operate** cycle (orange) is security operations: evaluate the live stream, compress raw matches into incidents, and grade what earns its keep. **Hunt** bridges the two: compile the same rule for whatever store holds the archive, find variants the live path missed, and feed new exemplars back into **Author**.

## Before the loop

RSigma does not replace threat-intel review, severity triage of candidate detections, or analyst investigation of what normal looks like. Those phases produce the NDJSON exemplars and the baseline corpus that `rule draft` and `rule backtest` expect. Once you have them, the stations below pick up.

## Engineer cycle

### Author

Turn exemplar events into a new Sigma rule or a verified filter for an existing noisy rule, finish metadata and correlation logic, and document the detection strategy.

- [`rule draft`](../cli/rule/draft.md): profile exemplars against a baseline and emit verified YAML. See [Drafting Rules from Logs](rule-drafting.md).
- [`rule tune`](../cli/rule/tune.md): contrast confirmed false positives with protected true positives and emit a verified Sigma filter. See [Rule Tuning](rule-tuning.md).
- [`rule lint`](../cli/rule/lint.md) and the LSP ([VS Code and Cursor](../editors/vscode.md), [Neovim, Helix, Zed](../editors/neovim.md)): the {{ rsigma.lint.rules }} lint rules with auto-fix. See [Linting Rules](linting-rules.md).
- [`rule doc --scaffold`](../cli/rule/doc.md): stamp in ADS metadata (blind spots, validation recipe, response plan). See [Detection Strategy](detection-strategy.md).
- [MCP server](mcp-server.md): drive the same toolchain from AI agents.

### Test

Prove the rule before it ships: why an event matched or did not, whether it regresses on known-good and known-bad corpora, and how field-mapping pipelines transform it. RSigma replays corpora you already have; it does not generate attacker telemetry (see [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) for that).

- [`rule validate`](../cli/rule/validate.md): parse, compile, and resolve dynamic sources before any event replay.
- [`engine explain`](../cli/engine/explain.md): non-short-circuiting PASS/FAIL trace per selection.
- [`rule backtest`](../cli/rule/backtest.md): per-rule fire counts against declared expectations. See [Evaluating Rules](evaluating-rules.md).
- [`pipeline diff`](../cli/pipeline/diff.md): unified diff of the rule before and after pipeline transforms.
- [`engine eval`](../cli/engine/eval.md): one-shot evaluation for ad hoc checks.

### Deploy

Turn a green laptop check into merge policy and a live ruleset.

- [`rule validate`](../cli/rule/validate.md): parse, compile, and resolve dynamic sources before merge.
- [CI/CD](ci-cd.md): lint, `rule validate --resolve-sources`, merge-base fields-drift diff, backtest, and coverage in the pipeline. Use [rsigma-action](https://github.com/timescale/rsigma-action) for a single GitHub Action gate.
- [Streaming detection](streaming-detection.md): hot-reload rules and pipelines without restart.
- [Docker](../deployment/docker.md) and [installation](../getting-started/installation.md): signed containers and release binaries.

## Operate cycle

### Detect

Hold rules against the live event stream with correlation, schema routing, and bounded state.

- [Streaming detection](streaming-detection.md): daemon lifecycle, hot-reload, correlation windows, and state persistence. See also [`engine daemon`](../cli/engine/daemon.md).
- [Schema routing](schema-routing.md) and [logsource-aware evaluation](logsource-routing.md): route events to the right pipeline and skip conflicting rules.
- [Processing pipelines](processing-pipelines.md) and [dynamic sources](../reference/dynamic-sources.md): field mapping and runtime intel injection.
- [Input formats](input-formats.md), [NATS streaming](nats-streaming.md), and [OTLP integration](otlp-integration.md).

### Alert and triage

Turn raw matches into one incident per entity, enrich before the page, and ingest analyst verdicts.

- [Enrichers](enrichers.md): GeoIP, asset context, runbook links on the sink path.
- [Risk-based alerting](risk-based-alerting.md): entity-scored alerting with tactic and source multipliers.
- [Alert pipeline](alert-pipeline.md): deduplication, silences, inhibition, and grouping.
- [Webhooks](webhooks.md): HMAC-signed delivery to Slack, PagerDuty, or custom endpoints.
- [OCSF findings](ocsf-findings.md): emit Detection Finding (class 2004) JSON on sinks with `?format=ocsf`.
- [Triage feedback loop](triage-feedback.md) and [disposition source recipes](disposition-recipes.md): ingest verdicts via `POST /api/v1/dispositions` (see [HTTP API](../reference/http-api.md)) and fold them into per-rule false-positive ratios.

### Measure

Review the portfolio on evidence instead of vibes.

- [`rule scorecard`](../cli/rule/scorecard.md): fuse a required backtest and coverage report (optional `--metrics` and `--triage`) into keep/tune/retire verdicts. See [Detection Scorecard](detection-scorecard.md).
- [`rule hygiene`](../cli/rule/hygiene.md): flag silent, noisy, untagged, no-owner, incomplete-ads, broken-fields, and deprecated rules. See [Rule Hygiene](rule-hygiene.md).
- [`rule coverage`](../cli/rule/coverage.md): ATT&CK Navigator layer and Atomic Red Team cross-reference. See [ATT&CK Coverage](attack-coverage.md).
- [`rule visibility`](../cli/rule/visibility.md): DeTT&CT data-source scoring and field observability. See [Visibility and Data Sources](visibility-and-data-sources.md).
- [Observability](observability.md): Prometheus counters and Grafana dashboards.

## Hunt

The daemon only sees now. Hunt compiles the same rule for historical stores and feeds findings back into authoring.

- [`backend convert`](../cli/backend/convert.md): native PostgreSQL, LynxDB, and Fibratus targets; sigma-cli delegation for Splunk, Elasticsearch, Sentinel, and 30+ more. See [Rule Conversion](rule-conversion.md).
- [`rule fields`](../cli/rule/fields.md): mapping catalog for the fields a rule references.

## What RSigma does not own

| Phase | Handoff |
|-------|---------|
| Requirements and discovery | Threat intel, business context, analyst judgment |
| Attack simulation | [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team); RSigma replays and converts |
| Log storage and search | Hunt targets PostgreSQL, LynxDB, or your SIEM via `backend convert` |
| Case management | Dispositions API consumes verdicts; the durable record stays in your case system |
| Response | Webhooks hand off to whatever runs the playbook |

## Relationship to broader detection-engineering lifecycles

The loop above is an RSigma product map. Its station names organize software surfaces by what a practitioner does with RSigma; they are not a new lifecycle standard, nor a direct rendering of the [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework) functions. Published detection-engineering lifecycles instead describe the team's end-to-end process. They differ in wording but converge on roughly six phases: **requirements and discovery**, **triage and feasibility**, **investigation**, **development**, **testing and validation**, and **deployment and maintenance**. For representative treatments, see the [SANS detection engineering lifecycle](https://www.sans.org/blog/logs-alerts-introducing-detection-engineering-poster), the [NVISO detection development lifecycle](https://blog.nviso.eu/2025/07/08/detection-engineering-practicing-detection-as-code-introduction-part-1/), and [Splunk's detection engineering overview](https://www.splunk.com/en_us/blog/learn/detection-engineering.html).

The station tour and the broader lifecycle overlap, but they are not one-to-one:

| Broader lifecycle phase | RSigma station or handoff | Relationship |
|-------------------------|----------------------------|--------------|
| Requirements and discovery | Measure → Author | Coverage, visibility, scorecard, and hygiene findings create the next detection requirement; business context and threat prioritization remain human inputs. |
| Triage and feasibility | Before the loop | Analysts decide whether the behavior matters and whether the required telemetry exists before committing to a rule. This is distinct from the **Alert and triage** station, which handles findings after deployment. |
| Investigation | Hunt → Author | Historical search, captured events, and analyst research produce representative exemplars for authoring. |
| Development | Author | Draft, edit, lint, document, and map the detection. |
| Testing and validation | Test | Validate, explain, replay corpora, backtest expectations, and inspect pipeline transformations. |
| Deployment and maintenance | Deploy → Detect → Alert and triage → Measure | CI and packaging ship the ruleset; the daemon evaluates it; the alert path groups and enriches findings; measurements drive tuning or retirement. |

The views are complementary. The broader lifecycle locates the team in the detection process; the RSigma loop locates the repeatable work in the product. RSigma leaves pre-development judgment in **Before the loop**, maps development and validation directly onto **Author** and **Test**, expands deployment and maintenance across four operational stations, and promotes **Hunt** to an explicit feedback path because historical findings commonly become the next rule or test exemplar.

## Further reading

- [The State of RSigma](https://mostafa.dev/the-state-of-rsigma-7ba0a99020d9): a tour of everything RSigma does today.
- [The State of RSigma, Part Two: The Loop](https://mostafa.dev/the-state-of-rsigma-part-two-the-loop-c114f379dd78): one detection walked end to end through every station (Okta MFA reset to account takeover).
