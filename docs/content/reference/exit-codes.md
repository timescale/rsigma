# Exit Codes

`rsigma` uses a structured exit-code scheme so CI runners can distinguish a tool failure from a finding. The same four codes apply to every subcommand. The exact source of truth is the [`exit_code` module](https://github.com/timescale/rsigma/blob/main/crates/rsigma-cli/src/exit_code.rs).

## Codes

| Code | Constant | Meaning |
|------|----------|---------|
| `0` | `SUCCESS` | Operation completed cleanly. For `engine eval`, events were processed (detections may have fired). For `rule lint`, no findings at or above `--fail-level`. For `rule validate`, every rule parsed and compiled. |
| `1` | `FINDINGS` | The tool ran but produced findings. For `engine eval --fail-on-detection`, at least one detection or correlation fired. For `rule lint --fail-level <X>`, at least one finding at or above `X`. For `rule fmt --check` or `rule fmt --diff`, at least one file would be reformatted. Also used by `pipeline resolve` when any source returns `"status": "error"`, and by `rule hygiene` and `rule scorecard` when `--fail-on` matches. |
| `2` | `RULE_ERROR` | The input rules could not be loaded or compiled. For `rule validate`, parse or compile errors. For `backend convert`, conversion failed or every rule failed. For `engine eval`, `rule lint`, `rule fields`, and `rule parse`, the rules path or file could not be read. For `rule condition`, the expression has bad syntax. For `rule stdin`, stdin could not be read. |
| `3` | `CONFIG_ERROR` | Configuration or argument error: bad pipeline file, unknown backend target, malformed `--suppress` duration, invalid `--jq` filter, schema load/fetch/parse failure, unreachable daemon client call. |

## Per-command behavior

| Command | `0` | `1` | `2` | `3` |
|---------|-----|-----|-----|-----|
| `engine eval` | Default; or no match with `--fail-on-detection`. | Detection/correlation fired (with `--fail-on-detection`). | Rules path unreadable. | Bad `-p`, `--jq`, `--jsonpath`, `--suppress`, etc. |
| `engine daemon` | Normal shutdown (including `--dry-run`). | (not used) | Initial rules could not be loaded or compiled. | Bad `--input`, `--output`, pipeline file, TLS/auth/audit misconfiguration, etc. |
| `rule parse` | File readable; YAML errors and missing-field issues are warnings on stderr and the partial AST still prints. | (not used) | File could not be opened (IO error). | (not used) |
| `rule validate` | Every rule parsed and compiled. | (not used) | At least one parse or compile error. | Pipeline/`--source` load failure, `--resolve-sources` failure. |
| `rule lint` | No findings at or above `--fail-level`. | Findings at or above `--fail-level` (including schema violations when `--schema` is set). | Rules path unreadable. | Schema argument/load/fetch/parse/compile failure, or other CLI configuration error. |
| `rule fmt` | Report or write finished, or nothing to change. | `--check` or `--diff`: at least one file would be reformatted. | A file could not be read, parsed, formatted, or written. | Conflicting mode flags, or `--stdout` without exactly one file. |
| `rule fields` | Listed cleanly. Per-rule parse errors are warnings only. | (not used) | Rules path unreadable. | Pipeline file unreadable. |
| `rule condition` | Expression parsed. | (not used) | Bad expression syntax. | (not used) |
| `rule stdin` | YAML syntax errors and invalid documents are warnings; the partial AST still prints. | (not used) | stdin read failure (including non-UTF-8 input), or an `action: global`/`action: repeat` merge over the nesting limit. | (not used) |
| `backend convert` | Conversion succeeded. | (not used) | Conversion failed, rules path empty (without `--skip-unsupported`). | Unknown `--target`/`--format`, unwritable `--output`, no sigma-cli for a delegated target. |
| `backend targets` | Always. | (not used) | (not used) | (not used) |
| `backend formats` | Formats listed for a native target, or a successful sigma-cli listing. | (not used) | (not used) | Unknown non-native target with no usable sigma-cli result. |
| `pipeline resolve` | Every source returned `"status": "ok"` (or a successful `--dry-run`). | At least one source returned `"status": "error"`. | Pipeline unreadable, no sources loaded, or no sources matched `-s/--source`. | Bad `--source-file` load or other configuration error. |

## Non-obvious behaviors

- `engine eval`, `rule parse`, and `rule fields` log per-rule parse errors as warnings on stderr and still exit `0`. Use `rule validate` for a strict per-rule gate that fails on parse or compile errors.
- `rule stdin` is equally lenient, including for YAML syntax errors. Only a failed stdin read or an over-deep `action: global`/`action: repeat` merge exits `2`.
- `engine eval` exits `0` by default even when matches fire. Pass `--fail-on-detection` to make matches fail the build.
- `rule lint` exits `0` for findings below `--fail-level`. The default threshold is `error`, so a clean lint with only info or warning findings still returns `0`.
- The `hint` lint severity never triggers exit `1`, even with `--fail-level info`.
- `pipeline resolve` exits `1` when any source fails after printing per-source status. For a gate that also validates rules, use `rule validate --resolve-sources` (exit `3` on source failure).

## CI patterns

The [CI/CD guide](../guide/ci-cd.md#exit-codes) shows the GitHub Actions, GitLab CI, pre-commit, and generic shell pipelines that consume these codes.

## See also

- [`exit_code` module on GitHub](https://github.com/timescale/rsigma/blob/main/crates/rsigma-cli/src/exit_code.rs)
- [CI/CD](../guide/ci-cd.md) for end-to-end pipeline examples.
- [`rule lint`](../cli/rule/lint.md), [`engine eval`](../cli/engine/eval.md), [`rule validate`](../cli/rule/validate.md), [`pipeline resolve`](../cli/pipeline/resolve.md) for per-command flag tables.
