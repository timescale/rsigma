# `rsigma rule parse`

Parse a single Sigma YAML file and print the AST as JSON.

## Synopsis

```text
rsigma rule parse [OPTIONS] <PATH>
```

## Description

Reads one Sigma rule file, parses it through `rsigma-parser`, and writes the resulting AST to stdout as JSON. Useful for inspecting how rsigma sees a rule, building tooling on top of the parsed shape, or diffing two parse results to spot subtle YAML changes.

Multi-document YAML files (action-global/action-reset/action-repeat fragments) parse into a single JSON object listing each document. Parse errors are written to stderr and the process exits with code `2`.

## Flags

| Flag | Description |
|------|-------------|
| `<PATH>` | Path to a Sigma YAML file. |
| `-p, --pretty` | Pretty-print JSON output (two-space indent). |

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
rsigma rule parse rules/whoami.yml | jq '.detection.selection'
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | The file was readable. A YAML syntax error or missing-required-field is reported as a warning to stderr and the partial AST still prints to stdout. |
| `2` | The file could not be opened (IO error, permission denied, path not found). |

For a strict per-rule gate that fails on parse errors, use [`rule validate`](validate.md).

## See also

- [`rule validate`](validate.md) for parsing every rule in a directory plus pipeline compile checks.
- [`rule stdin`](stdin.md) for parsing a rule streamed in over stdin.
- [`rule condition`](condition.md) for parsing just a condition expression.
- [Linting Rules](../../guide/linting-rules.md) for the spec-conformance gate that goes beyond parsing.
