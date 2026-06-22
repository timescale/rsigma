# `rsigma rule visibility`

Score telemetry visibility: turn the field-observability signal into a [DeTT&CT](https://github.com/rabobank-cdc/DeTTECT) data-source and technique administration YAML plus a visibility [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) layer.

## Synopsis

```text
rsigma rule visibility [OPTIONS] --rules <PATH>
```

## Description

`rule visibility` answers a different question than [`rule coverage`](coverage.md). Coverage reports the detection axis ("which techniques your rules detect"); visibility reports the data axis ("which fields and logsources you actually see"). The two are co-equal inputs to a mature detection program, and the two Navigator layers stack so the cells where you have data but no detection (or detection but no data) become visible at a glance.

The command joins three sets in one pass:

- The rule logsource inventory and rule field set from `--rules` (the same `RuleFieldSet` extractor `rule fields` uses).
- The observed field signal from `--observed` (the `engine eval --observe-fields` JSON, a saved `GET /api/v1/fields` snapshot, or stdin) or `--addr` (a live daemon). When omitted, every source reports as unobserved, the "what would full visibility look like" baseline.
- A bundled, overridable mapping table that resolves logsources and fields to ATT&CK data sources, data components, and techniques.

Each rule logsource resolves to the data sources it expects to receive; observed fields attribute to data components so the global field signal scores per data source. A data source whose mapped rule fields are all in the broken-coverage `missing` set is a blind spot: you wrote rules for data you do not receive.

### Visibility scoring

Scores ride DeTT&CT's 0-to-4 scale (none, minimal, medium, good, excellent), derived from the fraction of a data source's mapped rule fields that were observed: all observed scores 4, all unobserved scores 0, and the band between splits into minimal/medium/good. The scores are conservative seeds for analyst review, not authoritative measurements: the emitted DeTT&CT files mark every score as a seed and the `data_quality` dimensions carry the same seed value rather than fabricated precision.

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-r, --rules <PATH>` | required | Sigma rule file or directory of rules. Repeatable. |
| `--observed <FILE>` | unset | Observed field report: the `engine eval --observe-fields` JSON, a saved `GET /api/v1/fields` snapshot, or `-` for stdin. Omit for the rule-expected baseline. Conflicts with `--addr`. |
| `--addr <DAEMON_ADDR>` | unset | Fetch the observed snapshot from a live daemon (`GET /api/v1/fields`) as `host:port` or a full URL. |
| `--mapping [<PATH_OR_URL>]` | bundled | Override the logsource/field to ATT&CK data-source mapping table. A path or URL reads that table; a bare `--mapping` fetches the curated default URL. May also be supplied via `visibility.mapping`. |
| `--dettect-data-sources <FILE>` | unset | Write the DeTT&CT data-source administration YAML to this file. |
| `--dettect-techniques <FILE>` | unset | Write the DeTT&CT technique-administration YAML to this file. |
| `--navigator <FILE>` | unset | Write the visibility ATT&CK Navigator layer (format 4.5) to this file. |
| `--fail-on-blind-spots` | off | Exit `1` when any rule-expected data source has no observed telemetry. May also be supplied via `visibility.fail_on_blind_spots`. |
| `--config <PATH>` | unset | Load a specific YAML config file instead of running the discovery chain. |
| `--dry-run` | off | Print the effective `visibility` section and exit `0` without running. |

A bare `--mapping` and any `--mapping <URL>` fetch over HTTP and cache for 7 days under the user cache directory (`~/.cache/rsigma/visibility` on Linux), with a stale-cache fallback when offline. The bundled default table needs no network.

The global `--output-format` applies: `table` (the TTY default) renders the human report with the data-source breakdown plus blind-spot and untapped sections, `json` emits the single report document, and `ndjson`/`csv`/`tsv` emit one row per data source.

## Mapping table

The bundled table covers common process, network, file, registry, module, script, and authentication logsources and their fields. Override it with `--mapping` to extend the coverage or point at a site-specific table. The format is JSON:

```json
{
  "logsources": [
    {"category": "process_creation", "data_source": "Process", "data_component": "Process Creation", "products": ["Windows"]}
  ],
  "fields": [
    {"field": "Image", "data_component": "Process Creation"}
  ],
  "data_components": [
    {"name": "Process Creation", "data_source": "Process", "techniques": ["T1059"]}
  ]
}
```

A logsource entry matches a rule when every field it specifies equals the rule's corresponding logsource field; an unset field is a wildcard. Rule logsources that match no entry are surfaced as a hygiene list so you know to extend the table.

## Report

The JSON document (`--output-format json`) has a stable shape:

- `summary`: rule, logsource, data-source, and technique counts, the blind-spot and untapped counts, the observed event total, and whether an observed signal was present.
- `data_sources[]`: per data source, the 0-to-4 score and level, the products and data components, the contributing logsources, the mapped rule fields, the observed subset, and whether it is a blind spot.
- `blind_spots[]`: rule-expected data sources whose mapped fields were all unobserved.
- `untapped[]`: observed data sources no rule consumes (telemetry you receive but write no rule against).
- `unmapped_logsources[]`: rule logsources the mapping table does not recognize.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success. With `--fail-on-blind-spots`, no rule-expected data source was a blind spot. |
| `1` | `--fail-on-blind-spots` was set and at least one rule-expected data source had no observed telemetry. |
| `2` | The rules path could not be read or parsed. |
| `3` | The observed report or mapping table could not be fetched or parsed, or an invalid flag was passed. |

## Examples

### Score visibility from an eval report

```bash
rsigma engine eval -r rules/ --observe-fields --observe-fields-report fields.json < events.ndjson
rsigma rule visibility -r rules/ --observed fields.json
```

### Export the DeTT&CT files and a Navigator layer

```bash
rsigma rule visibility -r rules/ --observed fields.json \
    --dettect-data-sources data-sources.yaml \
    --dettect-techniques techniques.yaml \
    --navigator visibility.json
```

Open `visibility.json` alongside a `rule coverage` layer in the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) to compare the visibility and detection axes.

### Pull the snapshot from a live daemon

```bash
rsigma rule visibility -r rules/ --addr 127.0.0.1:9090
```

### Gate CI on blind spots

```bash
rsigma rule visibility -r rules/ --observed fields.json --fail-on-blind-spots
```

## See also

- [Visibility and Data Sources](../../guide/visibility-and-data-sources.md) for the end-to-end DeTT&CT workflow.
- [Observability](../../guide/observability.md) for the `--observe-fields` signal this command consumes.
- [`rule coverage`](coverage.md) for the detection axis; visibility and coverage are the two halves of a mature program.
- [Configuration](../../reference/configuration.md) for the `visibility` config section.
- [Exit Codes reference](../../reference/exit-codes.md) for the canonical table.
