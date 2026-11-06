# `rsigma rule fmt`

{{ added "unreleased" }}

Rewrite Sigma rules into rsigma's canonical layout while keeping their comments and meaning.

## Synopsis

```text
rsigma rule fmt [OPTIONS] [PATHS]...
```

## Description

Reads one rule file or every `*.yml`/`*.yaml` under a directory (recursive), classifies each YAML document as a detection rule, correlation, filter, or `action: global`/`repeat`/`reset` fragment, and rewrites it with the canonical layout that `rsigma rule fmt` and the LSP formatter share. The formatter keeps comments attached to the entries they describe, along with anchors, aliases, tags, and directives.

Before it returns changed text, the formatter runs a semantic guard. The guard parses the output again and refuses the rewrite unless the YAML values, parsed rules, correlations, filters, parser diagnostics, comment attachment, anchors, aliases, tags, directives, and `action` values all match the source. Files that are not Sigma documents are skipped with a `skipped:` line on stderr.

For the layout rules, key order tables, comment placement, and the full list of refused constructs see [Formatting Rules](../../guide/formatting-rules.md).

## Flags

### Input

| Flag | Description |
|------|-------------|
| `[PATHS]...` | Sigma rule files or directories to format. Defaults to the current directory when omitted. Explicit file arguments are accepted whatever their extension; directory walks add `*.yml` and `*.yaml` files only. `-` reads one document from stdin and must be the only path. |

### Mode

| Flag | Description |
|------|-------------|
| `--check` | Report files that would change and exit `1` if any would be reformatted. |
| `--diff` | Print a unified diff for each file that would change and exit `1` if any would be reformatted. |
| `--write` | Rewrite files in place with an atomic rename. |
| `--stdout` | Print the formatted text of exactly one file to stdout. A non-Sigma file is echoed unchanged so editor integrations never blank a buffer. |

Without a mode flag, `rule fmt` reports the files that would change. `--write` cannot be combined with `--check`, `--diff`, `--stdout`, or `-`; `--stdout` cannot be combined with `--check` or `--diff`, and needs exactly one file path or `-`.

### Output

The wire format and color resolution are controlled by the global `--output-format`, `--color`, `--quiet`, and `--no-stats` flags documented in the [CLI overview](../index.md#global-flags). `rule fmt` keeps text output for reports, diffs, and formatted YAML; an explicit `--output-format` produces a warning and falls back to text.

stdout carries data: the `Would reformat: <path>` report lines, unified diffs, or the formatted text from `--stdout`. stderr carries progress, warnings, errors, `skipped:` lines, the `Reformatted:` lines from `--write`, and the trailing summary. `--quiet` suppresses progress and the summary; `--no-stats` suppresses only the summary.

## Examples

### Report files that are not canonical

```bash
rsigma rule fmt rules/
```

```text
Would reformat: rules/whoami.yml
1 would be reformatted, 0 already formatted, 0 skipped (run with --write to apply)
```

### Gate a pull request in CI

```bash
rsigma rule fmt --check rules/
```

```text
Would reformat: rules/whoami.yml
1 would be reformatted, 0 already formatted, 0 skipped (run with --write to apply)
```

### Review the changes before applying them

```bash
rsigma rule fmt --diff rules/whoami.yml
```

### Apply the canonical layout

```bash
rsigma rule fmt --write rules/
```

```text
Reformatted: rules/whoami.yml
1 reformatted, 0 already formatted, 0 skipped
```

### Format a buffer from an editor or pipe

```bash
rsigma rule fmt --stdout rules/whoami.yml > /tmp/whoami.yml
```

Read from stdin with `-`. The report and diff modes accept it too:

```bash
rsigma rule fmt --stdout - < rules/whoami.yml
cat rules/whoami.yml | rsigma rule fmt --check -
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | The report or write finished, or nothing needed to change. |
| `1` | `--check` or `--diff`: at least one file would be reformatted. |
| `2` | A file or stdin could not be read, parsed, formatted, or written. |
| `3` | Conflicting mode flags, `--stdout` without exactly one file, `--write` with `-`, or `-` mixed with file paths. |

## See also

- [Formatting Rules](../../guide/formatting-rules.md) for the canonical layout, comment placement, and refused constructs.
- [`rule lint`](lint.md) for spec and hygiene checks.
- [`rule validate`](validate.md) for the parse-and-compile gate.
- [CI/CD](../../guide/ci-cd.md) for pipeline patterns.
