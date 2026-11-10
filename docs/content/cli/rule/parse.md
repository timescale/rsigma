---
description: "Reference for rsigma rule parse: parse a single Sigma rule YAML file and print its abstract syntax tree as JSON for inspection or tooling."
---

# `rsigma rule parse`

{{ added "0.12.0" }}

Parse a single Sigma YAML file and print the AST as JSON.

## Synopsis

```text
rsigma rule parse [OPTIONS] <PATH>
```

## Description

Reads one Sigma rule file, parses it through `rsigma-parser`, and writes the resulting AST to stdout as JSON. Useful for inspecting how RSigma sees a rule, building tooling on top of the parsed shape, or diffing two parse results to spot subtle YAML changes.

The output is one JSON object with `rules`, `correlations`, and `filters` arrays, so multi-document YAML files (action-global/action-reset/action-repeat fragments) list each document in the matching array. A file that cannot be read, or is not valid UTF-8, is reported on stderr and the process exits with code `2`. A YAML syntax error is a warning: parsing stops at the broken document, the documents before it still print, and the process exits with code `0`. A document that fails rule validation, such as a missing `logsource`, conflicting modifiers, or a value of the wrong type for its modifiers, is listed on stderr under `Warnings:` and left out of the AST, and the process exits with code `0`. Use [`rule validate`](validate.md) as a gate that fails on those errors.

## Flags

| Flag | Description |
|------|-------------|
| `<PATH>` | Path to a Sigma YAML file. |
| `-p, --pretty` | Pretty-print JSON output (two-space indent). Prefer global `--output-format json|ndjson` for new scripts; `table`/`csv`/`tsv` warn and fall back to JSON. See [Output Formats](../../reference/output.md). |

## Examples

### One-shot AST dump

```bash
rsigma rule parse rules/proc_creation_win_whoami.yml --pretty
```

### Diff two parses

```bash
rsigma rule parse rules/before.yml --pretty > before.json
rsigma rule parse rules/after.yml --pretty  > after.json
diff -u before.json after.json
```

### Pipe into `jq` for structured introspection

```bash
rsigma rule parse rules/whoami.yml | jq '.rules[0].detection.named.selection'
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | The file was readable. A YAML syntax error or missing-required-field is reported as a warning to stderr and the partial AST still prints to stdout. |
| `2` | The file could not be read (path not found, permission denied, not valid UTF-8), or an `action: global` or `action: repeat` merge exceeded the nesting limit. |

For a strict per-rule gate that fails on parse errors, use [`rule validate`](validate.md).

## See also

- [`rule validate`](validate.md) for parsing a rule file or every rule in a directory, plus pipeline compile checks.
- [`rule stdin`](stdin.md) for parsing a rule streamed in over stdin.
- [`rule condition`](condition.md) for parsing just a condition expression.
- [Linting Rules](../../guide/linting-rules.md) for the spec-conformance gate that goes beyond parsing.
