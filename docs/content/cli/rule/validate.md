# `rsigma rule validate`

{{ added "0.12.0" }}

Parse a Sigma rule file, or all Sigma rules in a directory (recursive), and report results.

## Synopsis

```text
rsigma rule validate [OPTIONS] <PATH>
```

## Description

Parses a single Sigma file, or walks a directory and parses every `*.yml`/`*.yaml` Sigma file, with `rsigma-parser`, optionally applies one or more processing pipelines, and compiles each rule with the evaluator's compiler. Reports the counts on stdout (human summary by default). Pass `--output-format json|ndjson|table|csv|tsv` for a structured envelope or `PATH,STATUS,ERRORS` rows. Exits with code `2` if any rule fails to parse or compile. See [Output Formats](../../reference/output.md).

The parser reports two kinds of problems. A parse error drops the document: malformed YAML, a missing condition, conflicting modifiers, an unknown detection reference. A parse warning keeps the document but ignores an invalid value: a `status` or `level` outside the allowed set, a malformed `related` entry, or an unreadable `sigma-version`. Parse warnings are reported but do not fail validation unless you pass `--fail-level warning`. {{ added "0.25.0" }}

Correlation references are checked as compile errors too. A correlation fails validation when it references a rule `id` or `name` that no detection or correlation rule carries. A reference that resolves to more than one rule also fails validation, which happens when rules share the referenced `id` or `name`, or when one rule's `name` equals another rule's `id`. {{ added "0.24.0" }}

This is the cheapest CI gate: no events are evaluated, just rules and pipelines. Wire it as the first step of every detection-as-code pipeline before [`rule lint`](lint.md) and [`engine eval`](../engine/eval.md) fixture tests.

For narrative coverage see [Linting Rules](../../guide/linting-rules.md) and [CI/CD](../../guide/ci-cd.md).

## Flags

| Flag | Description |
|------|-------------|
| `<PATH>` | A Sigma YAML file, or a directory searched recursively for Sigma YAML files. Single files are accepted. {{ added "0.24.0" }} |
| `-v, --verbose` | Show details for each file, not just the summary. |
| `-p, --pipeline <PIPELINES>` | Processing pipeline(s) to apply. Builtin names (`ecs_windows`, `fibratus_windows`, `sysmon`) or YAML file paths. Repeatable. |
| `--source <FILE_OR_DIR>` | External source file(s) or directory of source files. Repeatable. Same standalone `sources:` YAML shape as the daemon's `--source`. Required for meaningful `--resolve-sources` runs after the v0.19.0 removal of pipeline-embedded `sources:`. |
| `--resolve-sources` | Resolve and fetch every loaded dynamic source during validation. Sources must be reachable for validation to pass. |
| `--fail-level <FAIL_LEVEL>` | Lowest parse diagnostic severity that exits `2`: `error` (default) fails on parse errors and compile errors, and `warning` also fails on parse warnings. Same flag name and default as [`rule lint --fail-level`](lint.md). {{ added "0.25.0" }} |

## Examples

### Plain validation

```bash
rsigma rule validate rules/
```

Output:

```text
Parsed 24 documents from rules/
  Detection rules:   22
  Correlation rules: 2
  Filter rules:      0
  Parse errors:      0
  Parse warnings:    0
  Pipeline applied:  0 pipeline(s)
  Compiled OK:       24
  Compile errors:    0
```

### Validate a single file

{{ added "0.24.0" }}

```bash
rsigma rule validate rules/windows/proc_creation_whoami.yml
```

A YAML syntax error in the file counts as a parse error and exits with code `2`, the same as a broken file inside a directory.

### Fail on parse warnings

{{ added "0.25.0" }}

```bash
rsigma rule validate rules/ --fail-level warning
```

A rule with `status: draft` still parses and compiles, so plain `rule validate` reports it under `Parse warnings` and exits `0`. With `--fail-level warning` the same run exits `2`. [`rule lint`](lint.md) reports the same value as an `invalid_status` error.

### Structured output

{{ added "0.25.0" }}

With `--output-format json`, the envelope carries `summary` (including `parse_errors` and `parse_warnings` counts), `parse_errors`, `parse_warnings`, and `compile_errors` arrays of messages. With `ndjson`, `table`, `csv`, or `tsv`, each finding is one row whose `status` is `parse_error`, `parse_warning`, or `compile_error`, and a clean run emits a single `ok` row.

### Validate with a pipeline applied

```bash
rsigma rule validate rules/ -p pipelines/ecs.yml
```

Catches rules that reference fields the pipeline drops or renames in an incompatible way.

### Strict CI: also exercise dynamic sources

```bash
rsigma rule validate rules/ -p pipelines/dynamic.yml --source sources.yml --resolve-sources
```

The job fails with exit `3` if any HTTP, file, or command source is unreachable. Use this on PR builds for repos that ship dynamic pipelines.

### Verbose per-file output

```bash
rsigma rule validate rules/ -v
```

Lists each parse error, parse warning, and compile error under its own heading after the summary.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Every rule parsed and compiled. Parse warnings do not change the exit code unless `--fail-level warning` is set. |
| `2` | At least one parse or compile error, or at least one parse warning with `--fail-level warning`. |
| `3` | Pipeline file could not be loaded, `--source` load failure, `--resolve-sources` failed on a dynamic source, or the binary lacks the `daemon` feature needed for source resolution. |

## See also

- [`rule lint`](lint.md) for the spec-conformance gate ({{ rsigma.lint.rules }} lint rules, auto-fix).
- [`rule parse`](parse.md) for a single-file AST dump.
- [Linting Rules](../../guide/linting-rules.md) and [Processing Pipelines](../../guide/processing-pipelines.md).
- [CI/CD](../../guide/ci-cd.md) for the validate/lint/eval pipeline pattern.
