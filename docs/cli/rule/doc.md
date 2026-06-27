# `rsigma rule doc`

Report or scaffold the Alerting and Detection Strategy (ADS) document for one or more Sigma rules.

## Synopsis

```text
rsigma rule doc [OPTIONS] <RULES>...
rsigma rule doc --scaffold [--in-place] <RULE>
```

## Description

The [ADS framework](https://github.com/palantir/alerting-detection-strategy-framework) is the durable, peer-reviewed strategy document every production detection should carry: a goal, an ATT&CK categorization, a strategy abstract, technical context, stated blind spots and assumptions, false-positive notes, a true-positive validation recipe, a priority, and a response plan. RSigma carries four of those on standard Sigma fields (`description`, `attack.*` `tags`, `falsepositives`, `level`) and the rest under the [`rsigma.ads.*`](../../reference/custom-attributes.md#ads-detection-strategy-attributes-rsigmaads) custom-attribute namespace.

`rule doc` has two modes:

- **Render** (the default) assembles each rule's ADS document, reports which required sections are present or missing, and renders through the global `--output-format` layer or as a canonical Markdown document with `--format markdown`.
- **Scaffold** (`--scaffold`) emits a `rsigma.ads.*` template prefilled from what the rule already has, to stdout or merged into the rule file with `--in-place`.

The ADS bar (which statuses are enforced and which sections are required) is read from the `ads:` block in a [`.rsigma-lint.yml`](../../reference/lint-rules.md#ads-detection-strategy-metadata-11), discovered from the rule path or set with `--lint-config`. Without one, the built-in defaults apply: enforce `stable`, require every section.

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `<RULES>...` | required | One or more Sigma rule files or directories of rules. |
| `--scaffold` | off | Emit a `rsigma.ads.*` template for a single rule instead of a report. |
| `--in-place` | off | With `--scaffold`, merge the template into the rule file's `custom_attributes:` block instead of printing it. |
| `--format <FORMAT>` | `auto` | `auto` renders through `--output-format`; `markdown` emits the canonical ADS document per rule. |
| `--missing-only` | off | Report only rules below the configured ADS bar. Filters the output only; the exit code is unchanged. |
| `--fail-on-missing` | off | Exit 1 when any requested rule is below the bar. Makes `rule doc` a standalone CI gate. |
| `--lint-config <PATH>` | discovered | Path to a `.rsigma-lint.yml` whose `ads:` block sets the bar. |
| `--config <PATH>` | discovered | Path to an rsigma config file (the `doc` section). |
| `--dry-run` | off | Print the effective `doc` config and exit. |

## Examples

### Report the ADS status of a ruleset

```bash
rsigma rule doc rules/ --output-format table
```

### Emit a Markdown ADS document for a runbook

```bash
rsigma rule doc rules/windows/whoami.yml --format markdown > whoami-ads.md
```

### Gate a ruleset in CI

```bash
rsigma rule doc rules/ --fail-on-missing
```

### Scaffold the missing sections into a rule

```bash
rsigma rule doc --scaffold rules/windows/whoami.yml --in-place
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success. Every requested rule met the bar, or a plain render, or a scaffold. |
| `1` | `--fail-on-missing` found at least one rule below the configured ADS bar. |
| `2` | A rule path could not be read. |
| `3` | A bad flag (e.g. `--scaffold` on a directory) or unreadable config. |

## See also

- [Detection Strategy](../../guide/detection-strategy.md) for the authoring workflow and the CI gate.
- [Custom Attributes: `rsigma.ads.*`](../../reference/custom-attributes.md#ads-detection-strategy-attributes-rsigmaads) for the attribute reference.
- [Lint Rules: ADS detection-strategy metadata](../../reference/lint-rules.md#ads-detection-strategy-metadata-11) for the enforcement checks.
- [`rule lint`](lint.md) for the broader spec-conformance checks.
