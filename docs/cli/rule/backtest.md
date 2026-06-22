# `rsigma rule backtest`

Replay an event corpus against a ruleset, diff the per-rule fire counts against declared expectations, and emit a CI-native report.

## Synopsis

```text
rsigma rule backtest [OPTIONS] --rules <RULES> --corpus <PATH>
```

## Description

`engine eval` answers "what fired on this data." `rule backtest` answers "did the rules I intended to fire actually fire, and did anything else fire that should not." It walks an event corpus (one file or a directory, recursively), evaluates every record, tallies how many times each rule fired per corpus file, and diffs those counts against an optional expectations file.

Unlike `engine eval --fail-on-detection`, which is corpus-global and inverts on any rule firing, backtest asserts per rule. A positive fixture can require a specific rule to fire at least once, a negative fixture can require a specific rule to fire exactly zero times, and any rule that fires without a covering expectation is surfaced as a potential false positive on a known-benign corpus.

Backtest reuses the same input parsing as `engine eval`, so NDJSON, syslog, plain, logfmt, CEF, and EVTX corpora all work the same way. Correlation rules are first-class; correlation state is reset for each corpus file, so each file is an independent time slice (carrying window state across files would produce phantom correlations).

Without an `--expectations` file, backtest still runs and prints per-rule statistics; it just has nothing to diff.

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-r, --rules <PATH>` | required | Sigma rule file or directory of rules. May also be supplied via `backtest.rules` in a config file. |
| `--corpus <PATH>` | required | Event corpus: a file or a directory walked recursively. Repeatable. Extension dispatch: `.ndjson`/`.jsonl` as NDJSON, `.evtx` via the feature-gated adapter, everything else through `--input-format`. May also be supplied via `backtest.corpus`. |
| `--expectations <PATH>` | unset | Expectations YAML (per-rule fire-count assertions). |
| `--unexpected <POLICY>` | `warn` | What a rule firing with no covering expectation means: `fail`, `warn`, or `ignore`. Overrides the expectations-file default. |
| `-p, --pipeline <P>` | unset | Processing pipeline(s) to apply. Builtin names (`ecs_windows`, `sysmon`) or YAML file paths. Repeatable. |
| `--input-format <FMT>` | `auto` | Input log format for non-NDJSON corpus files: `auto`, `json`, `syslog`, `plain`, `logfmt`, `cef`. |
| `--syslog-tz <TZ>` | `+00:00` | Default timezone offset for RFC 3164 syslog. |
| `--syslog-strip-bom <BOOL>` | `true` | Strip a leading UTF-8 BOM from RFC 5424 syslog messages. |
| `--jq <JQ>` | unset | `jq` filter to extract the event payload from each JSON object. Mutually exclusive with `--jsonpath`. |
| `--jsonpath <JSONPATH>` | unset | JSONPath (RFC 9535) query to extract the event payload. |
| `--junit <PATH>` | unset | Write a JUnit XML report (one test case per expectation, plus one per unexpected-firing rule under the `fail` policy). |
| `--report <PATH>` | unset | Write the full JSON report to a file regardless of the stdout format. |
| `--config <PATH>` | unset | Load a specific YAML config file instead of running the discovery chain. |
| `--dry-run` | off | Print the effective `backtest` section and exit `0` without running. |

The global `--output-format` applies: `table` (the TTY default) renders the human report, `json` emits the single report document, and `ndjson`/`csv`/`tsv` emit one row per rule.

## Expectations file

```yaml
# expectations.yml
defaults:
  unexpected_detections: warn   # fail | warn | ignore
expectations:
  - rule: 5f0d7d3c-3aab-43fa-952f-8f7b2d966ee5   # rule id (preferred) or exact title
    corpus: auth-logs.ndjson                      # optional: scope to one corpus file
    at_least: 1                                   # must fire
  - rule: Suspicious Whoami Execution
    exactly: 0                                    # must not fire anywhere
  - rule: 9a1b2c3d-...
    at_least: 3
    at_most: 10                                   # bounded noise budget
```

- `rule` matches `rule_id` first, then falls back to `rule_title`. A title shared by more than one rule is a configuration error; reference it by id instead.
- Each entry sets exactly one of `exactly` or any combination of `at_least`/`at_most`.
- `corpus` scopes the count to a single corpus file (the path relative to the `--corpus` root, with `/` separators). Omit it to count across the whole corpus.
- An expectation that references a rule not present in `--rules` is a configuration error, so a renamed or deleted rule fails CI.
- Correlation rules are referenced the same way and their fires count the same way.

## Report

The JSON document (`--output-format json`, or written via `--report`) has a stable shape:

- `summary`: corpus files, events processed, rules loaded, expectations passed/failed, unexpected-fire counts, the effective policy, and the run duration.
- `expectations[]`: per expectation, the resolved rule, optional scope, bound, actual count, and pass/fail.
- `rules[]`: per rule, the id, title, level, logsource, total fires, and a per-corpus-file breakdown.
- `unexpected[]`: rules that fired with no covering expectation, with counts. This is the false-positive signal on a known-benign corpus.
- `by_logsource[]`: a rollup of unexpected fires grouped by rule logsource, the per-logsource false-positive-density view.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | All expectations met, and no unexpected fires under the `fail` policy. |
| `1` | At least one expectation failed, or unexpected fires occurred under the `fail` policy. |
| `2` | The rules path could not be read or compiled. |
| `3` | Bad expectations file, missing corpus path, or an invalid flag. |

## Examples

### Assert a positive and a negative fixture

```bash
rsigma rule backtest -r rules/ --corpus ci/corpus/ --expectations ci/expectations.yml
```

### Fail the build on any unexpected fire over a benign corpus

```bash
rsigma rule backtest -r rules/ --corpus ci/benign/ \
    --expectations ci/expectations.yml --unexpected fail
```

### Emit a JUnit report for CI annotation

```bash
rsigma rule backtest -r rules/ --corpus ci/corpus/ \
    --expectations ci/expectations.yml --junit backtest.xml
```

### Per-rule statistics with no expectations

```bash
rsigma rule backtest -r rules/ --corpus samples/ --output-format json | jq '.rules'
```

## See also

- [CI/CD](../../guide/ci-cd.md) for the detection-as-code pipeline that wires backtest into GitHub Actions and GitLab CI.
- [`rule scorecard`](scorecard.md) to feed this JSON report (with the coverage report) into per-rule keep/tune/retire verdicts.
- [`engine eval`](../engine/eval.md) for one-shot evaluation; backtest is the corpus-replay test harness built on top of it.
- [Configuration](../../reference/configuration.md) for the `backtest` config section.
- [Exit Codes reference](../../reference/exit-codes.md) for the canonical table.
