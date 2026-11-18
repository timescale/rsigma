---
description: "RSigma exit codes: the five structured codes every subcommand uses so CI runners can tell a clean run from findings, a config error, or an incomplete batch run."
---

# Exit Codes

`rsigma` uses a structured exit-code scheme so CI runners can distinguish a tool failure from a finding. The same five codes apply to every subcommand. The exact source of truth is the [`exit_code` module](https://github.com/timescale/rsigma/blob/main/crates/rsigma-cli/src/exit_code.rs).

## Codes

| Code | Constant | Meaning |
|------|----------|---------|
| `0` | `SUCCESS` | Operation completed cleanly. For `engine eval`, events were processed (detections may have fired). For `rule lint`, no findings at or above `--fail-level`. For `rule validate`, every rule parsed and compiled. |
| `1` | `FINDINGS` | The tool ran but produced findings. For `engine eval --fail-on-detection`, at least one detection or correlation fired. For `rule lint --fail-level <X>`, at least one finding at or above `X`. For `rule fmt --check` or `rule fmt --diff`, at least one file would be reformatted. Also used by `pipeline resolve` when any source returns `"status": "error"`, and by `rule hygiene` and `rule scorecard` when `--fail-on` matches. |
| `2` | `RULE_ERROR` | The input rules could not be loaded or compiled. For `rule validate`, parse or compile errors. For `backend convert`, conversion failed or every rule failed. For `engine eval`, `rule lint`, `rule fields`, and `rule parse`, the rules path or file could not be read. For `rule condition`, the expression has bad syntax. For `rule stdin`, stdin could not be read. |
| `3` | `CONFIG_ERROR` | Configuration or argument error: bad pipeline file, unknown backend target, malformed `--suppress` duration, invalid `--jq` filter, schema load/fetch/parse failure, unreachable daemon client call. |
| `4` | `RUNTIME_ERROR` | A stdin batch run that did not complete cleanly: a signal stopped it before end of input, reading stdin failed, output reached neither a sink nor the DLQ, the final state save failed, or a pipeline task panicked. {{ added "unreleased" }} |

## Per-command behavior

| Command | `0` | `1` | `2` | `3` | `4` |
|---------|-----|-----|-----|-----|-----|
| `engine eval` | Default; or no match with `--fail-on-detection`. | Detection/correlation fired (with `--fail-on-detection`). | Rules path unreadable. | Bad `-p`, `--jq`, `--jsonpath`, `--suppress`, unknown or broken `--ruleset`, etc. | (not used) |
| `engine daemon` | Normal shutdown (including `--dry-run`). | (not used) | Initial rules could not be loaded or compiled. | Bad `--input`, `--output`, pipeline file, TLS/auth/audit misconfiguration, etc. In a stdin batch run, also unrestorable stored state. {{ added "unreleased" }} | A stdin batch run that did not complete cleanly. {{ added "unreleased" }} |
| `rule parse` | File readable; YAML errors and missing-field issues are warnings on stderr and the partial AST still prints. | (not used) | File could not be opened (IO error). | (not used) | (not used) |
| `rule validate` | Every rule parsed and compiled. | (not used) | At least one parse or compile error. | Pipeline/`--source` load failure, `--resolve-sources` failure, unknown or broken `--ruleset`. | (not used) |
| `rule lint` | No findings at or above `--fail-level`. | Findings at or above `--fail-level` (including schema violations when `--schema` is set). | Rules path unreadable. | Schema argument/load/fetch/parse/compile failure, or other CLI configuration error. | (not used) |
| `rule fmt` | Report or write finished, or nothing to change. | `--check` or `--diff`: at least one file would be reformatted. | A file could not be read, parsed, formatted, or written. | Conflicting mode flags, or `--stdout` without exactly one file. | (not used) |
| `rule fields` | Listed cleanly. Per-rule parse errors are warnings only. | (not used) | Rules path unreadable. | Pipeline file unreadable. | (not used) |
| `rule condition` | Expression parsed. | (not used) | Bad expression syntax. | (not used) | (not used) |
| `rule stdin` | YAML syntax errors and invalid documents are warnings; the partial AST still prints. | (not used) | stdin read failure (including non-UTF-8 input), or an `action: global`/`action: repeat` merge over the nesting limit. | (not used) | (not used) |
| `backend convert` | Conversion succeeded. | (not used) | Conversion failed, rules path empty (without `--skip-unsupported`). | Unknown `--target`/`--format`, unwritable `--output`, no sigma-cli for a delegated target. | (not used) |
| `backend build` | Every selected group converted, or `--check` found no drift. | `--check` found drift. | At least one rule failed to convert without `skip_unsupported`; the other groups still ran. | No configured groups, unknown group or ruleset, missing `target`/`output`, two groups writing the same file, a pipeline that fails to load, unknown target or format, unwritable output, or no sigma-cli for a delegated target. {{ added "unreleased" }} | (not used) |
| `backend targets` | Always. | (not used) | (not used) | (not used) | (not used) |
| `backend formats` | Formats listed for a native target, or a successful sigma-cli listing. | (not used) | (not used) | Unknown non-native target with no usable sigma-cli result. | (not used) |
| `pipeline resolve` | Every source returned `"status": "ok"` (or a successful `--dry-run`). | At least one source returned `"status": "error"`. | Pipeline unreadable, no sources loaded, or no sources matched `-s/--source`. | Bad `--source-file` load or other configuration error. | (not used) |
| `ruleset list` | Every declared ruleset resolved. | (not used) | (not used) | A ruleset failed to resolve; other rows are still printed. {{ added "unreleased" }} | (not used) |
| `ruleset show` | The requested ruleset and document resolved. | (not used) | (not used) | Unknown ruleset or id, resolution error, or unreadable configuration. {{ added "unreleased" }} | (not used) |
| `ruleset build` | The output was written, or `--check` found no drift. | `--check` found drift. | A source had parse errors. | Resolution error, missing output, non-empty directory without `--force`, or unreadable configuration. {{ added "unreleased" }} | (not used) |
| `ruleset diff` | No change, or changes without `--fail-on-change`. | Changes were found with `--fail-on-change`. | (not used) | Resolution error, missing or unreadable lockfile, unknown lock version, or unreadable configuration. {{ added "unreleased" }} | (not used) |

## Non-obvious behaviors

- `engine eval`, `rule parse`, and `rule fields` log per-rule parse errors as warnings on stderr and still exit `0`. Use `rule validate` for a strict per-rule gate that fails on parse or compile errors.
- Every command that accepts `--ruleset` exits `3` for an unknown ruleset name or a ruleset that fails to resolve. {{ added "unreleased" }}
- `rule stdin` is equally lenient, including for YAML syntax errors. Only a failed stdin read or an over-deep `action: global`/`action: repeat` merge exits `2`.
- `engine eval` exits `0` by default even when matches fire. Pass `--fail-on-detection` to make matches fail the build.
- Daemon exit codes `3` for unrestorable state and `4` for an incomplete run apply only to `--input stdin` with the default `--stdin-mode batch`. With `--stdin-mode stream`, and with HTTP, NATS, and unix-socket input, the daemon keeps starting fresh on an incompatible snapshot and exit `0` at shutdown. {{ added "unreleased" }}
- `rule lint` exits `0` for findings below `--fail-level`. The default threshold is `error`, so a clean lint with only info or warning findings still returns `0`.
- The `hint` lint severity never triggers exit `1`, even with `--fail-level info`.
- `pipeline resolve` exits `1` when any source fails after printing per-source status. For a gate that also validates rules, use `rule validate --resolve-sources` (exit `3` on source failure).

## CI patterns

The [CI/CD guide](../guide/ci-cd.md#exit-codes) shows the GitHub Actions, GitLab CI, pre-commit, and generic shell pipelines that consume these codes.

## See also

- [`exit_code` module on GitHub](https://github.com/timescale/rsigma/blob/main/crates/rsigma-cli/src/exit_code.rs)
- [CI/CD](../guide/ci-cd.md) for end-to-end pipeline examples.
- [`rule lint`](../cli/rule/lint.md), [`engine eval`](../cli/engine/eval.md), [`rule validate`](../cli/rule/validate.md), [`pipeline resolve`](../cli/pipeline/resolve.md) for per-command flag tables.
