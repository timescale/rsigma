# `rsigma rule test`

Replay embedded `rsigma.exemplars` against their host detection and correlation rules.

## Synopsis

```text
rsigma rule test --rules <PATH> [--rules <PATH> ...] [-p <PIPELINE>] [--fail-on-missing]
```

## Description

Exemplars are example events stored on the rule under [`rsigma.exemplars`](../../reference/custom-attributes.md#rsigmaexemplars). Each entry declares whether the host rule should `match` or `no-match`. `rule test` loads the rules, builds a fresh engine per exemplar, and asserts only the target rule's result.

Detection exemplars run in a synthetic collection of the target rule plus the source collection's filters. Correlation exemplars load the full collection and replay their timestamped `events` from a fixed base timestamp plus each relative `offset`. Optional `-p` pipelines use the same collection-loading APIs as production evaluation. Filter rules must not carry exemplars.

A structurally valid `expect: match` exemplar satisfies ADS validation *presence* when `rsigma.ads.validation` prose is absent. Presence is not proof: only a passing `rule test` shows that the current rule still matches the recipe.

Output uses the global `--output-format` layer. Without an explicit format the command prints a table. In the JSON and NDJSON output a failed assertion carries a `diagnostic` explaining why, such as `the rule did not match the event` or `the correlation fired at event index 1 (offset 30s)`.

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--rules` / `-r` | required, repeatable | Sigma rule file or directory. |
| `--pipeline` / `-p` | none | Builtin pipeline name or YAML file (repeatable). |
| `--fail-on-missing` | off | Exit 1 when a detection or correlation rule has no exemplars. |

## Examples

### Test a rule file

```bash
rsigma rule test -r rules/windows/whoami.yml
```

### Gate a ruleset in CI

```bash
rsigma rule test -r rules/ --fail-on-missing
```

### JSON report

```bash
rsigma rule test -r rules/ --output-format json
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Every asserted exemplar passed. |
| `1` | At least one assertion failed, or `--fail-on-missing` found a rule with no exemplars. |
| `2` | A rule path could not be read or a rule failed to compile. |
| `3` | Invalid exemplar shape, ambiguous title identity, a pipeline error, or a missing correlation reference. |

## See also

- [Custom Attributes: `rsigma.exemplars`](../../reference/custom-attributes.md#rsigmaexemplars) for the schema and execution semantics.
- [Detection Strategy](../../guide/detection-strategy.md) for how exemplars relate to ADS validation.
- [`rule lint`](lint.md) for the static `exemplar_shape` and `exemplar_wrong_rule_kind` checks.
- [`rule backtest`](backtest.md) for corpus-level expectations outside the rule file.
