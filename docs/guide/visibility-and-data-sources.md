# Visibility and Data Sources

Detection coverage answers "which techniques do my rules detect." Visibility answers a question that comes first: "which telemetry do I actually receive, and do my rules depend on data I am not collecting." A rule for a data source you do not ingest never fires, no matter how good it is. [`rsigma rule visibility`](../cli/rule/visibility.md) turns the field-observability signal rsigma already produces into the two artifacts blue teams use to track data-source maturity: a [DeTT&CT](https://github.com/rabobank-cdc/DeTTECT) administration pair and a visibility [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) layer.

## The workflow

The signal comes from [`--observe-fields`](observability.md): as the engine evaluates events it records every field key it sees, then joins that against the fields your rules reference. The result partitions into observed-but-unreferenced fields (a gap signal) and referenced-but-unobserved fields (a broken-coverage signal). `rule visibility` consumes that partition and rolls it up to ATT&CK data sources.

```bash
# 1. Capture the observed field signal from a representative event stream.
rsigma engine eval -r rules/ --observe-fields --observe-fields-report fields.json < events.ndjson

# 2. Score visibility and emit the DeTT&CT files and a Navigator layer.
rsigma rule visibility -r rules/ --observed fields.json \
    --dettect-data-sources data-sources.yaml \
    --dettect-techniques techniques.yaml \
    --navigator visibility.json
```

The observed report and the live daemon's `GET /api/v1/fields` endpoint share one JSON shape, so a long-running daemon works the same way:

```bash
rsigma rule visibility -r rules/ --addr 127.0.0.1:9090 --navigator visibility.json
```

With no `--observed` or `--addr`, the command still runs and reports the rule-expected baseline with every source unobserved, a useful "what would full visibility look like" picture before any telemetry is wired up.

## How scoring works

Each rule logsource resolves through the mapping table to the ATT&CK data sources it expects (for example `process_creation` to Process, `registry_set` to Windows Registry). Each rule field attributes to a data component, so the global field signal scores per data source. A data source's score is the fraction of its mapped rule fields that were observed, mapped onto DeTT&CT's 0-to-4 scale:

| Observed fraction | Score | Level |
|-------------------|-------|-------|
| none observed | 0 | none |
| up to 25% | 1 | minimal |
| up to 50% | 2 | medium |
| up to 100% | 3 | good |
| all observed | 4 | excellent |

A data source whose mapped fields are all unobserved is a **blind spot**: your rules reference it but the telemetry never arrived. A data source you observe but no rule consumes is **untapped**: data you pay to collect with no detection written against it. The two are inverses, and surfacing both is the point.

The scores are deliberately conservative seeds. DeTT&CT files are meant to be analyst-tuned, so the emitted YAML marks every score as a seed for review and the `data_quality` dimensions carry the seed value rather than fabricated precision.

## The mapping table

The bundled table covers common process, network, file, registry, module, script, and authentication logsources and their fields, with a representative set of `data_component -> technique` edges. Override it with `--mapping <path-or-url>` to extend coverage or point at a site-specific table; a bare `--mapping` fetches the curated default over HTTP (cached for 7 days). Rule logsources the table does not recognize are surfaced as a hygiene list so you know what to add.

## Visibility versus detection coverage

`rule visibility` and [`rule coverage`](../cli/rule/coverage.md) emit Navigator layers in the same format (4.5) but score different things: coverage scores a technique by the number of rules that detect it, visibility scores it by how well you can see the underlying activity (0-4). Load both layers in the Navigator and the gaps line up:

- A technique with detection but no visibility is a rule that cannot fire.
- A technique with visibility but no detection is telemetry you collect but do not act on.
- A technique with both is genuine coverage.

This is the maturity-matrix Technology/Visibility cell that detection-coverage reporting alone cannot fill.

## CI usage

Gate a pipeline on blind spots so a rule that depends on data you do not collect fails the build:

```bash
rsigma rule visibility -r rules/ --observed fields.json --fail-on-blind-spots
```

`--fail-on-blind-spots` exits `1` when any rule-expected data source has no observed telemetry, the actionable "you wrote rules for data you do not receive" signal.

## See also

- [`rule visibility` reference](../cli/rule/visibility.md) for the full flag table and report shape.
- [Observability](observability.md) for the `--observe-fields` signal.
- [ATT&CK Coverage](attack-coverage.md) for the detection axis.
- [CI/CD](ci-cd.md) for wiring detection-as-code checks into a pipeline.
