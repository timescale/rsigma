# Exit Codes

`rsigma` uses a structured exit-code scheme so CI runners can distinguish a tool failure from a finding. The same four codes apply to every subcommand. The exact source of truth is the [`exit_code` module](https://github.com/timescale/rsigma/blob/main/crates/rsigma-cli/src/exit_code.rs).

## Codes

| Code | Constant | Meaning |
|------|----------|---------|
| `0` | `SUCCESS` | Operation completed cleanly. For `engine eval`, events were processed (detections may have fired). For `rule lint`, no findings at or above `--fail-level`. For `rule validate`, every rule parsed and compiled. |
| `1` | `FINDINGS` | The tool ran but produced findings. For `engine eval --fail-on-detection`, at least one detection or correlation fired. For `rule lint --fail-level <X>`, at least one finding at or above `X`. For `pipeline resolve`, at least one source returned an error. |
| `2` | `RULE_ERROR` | The input rules could not be loaded or compiled. For `rule validate`, parse or compile errors. For `backend convert`, conversion failed or every rule failed. For `engine eval` and `rule lint`, the rules path could not be read. |
| `3` | `CONFIG_ERROR` | Configuration or argument error: bad pipeline file, unknown backend target, malformed `--suppress` duration, invalid `--jq` filter, unreadable schema file. |

## Per-command behaviour

| Command | `0` | `1` | `2` | `3` |
|---------|-----|-----|-----|-----|
| `engine eval` | Default; or no match with `--fail-on-detection`. | Detection/correlation fired (with `--fail-on-detection`). | Rules path unreadable. | Bad `-p`, `--jq`, `--jsonpath`, `--suppress`, etc. |
| `engine daemon` | Normal shutdown. | (not used) | Rules path unreadable at startup. | Bad `--input`, `--output`, pipeline file, etc. |
| `rule parse` | Parsed cleanly. | (not used) | Parse error. | (not used) |
| `rule validate` | Every rule parsed and compiled. | (not used) | At least one parse or compile error. | Pipeline load failure, `--resolve-sources` failure. |
| `rule lint` | No findings at or above `--fail-level`. | Findings at or above `--fail-level`. | Rules path or schema file unreadable. | Bad `--schema` argument. |
| `rule fields` | Listed cleanly. | (not used) | Rules path unreadable or rule parse error. | Pipeline file unreadable. |
| `rule condition` | Expression parsed. | (not used) | Parse error. | (not used) |
| `rule stdin` | Parsed cleanly. | (not used) | Parse error. | (not used) |
| `backend convert` | Conversion succeeded. | (not used) | Conversion failed, rules path empty (without `--skip-unsupported`). | Unknown `--target`, unknown `--format`, unwritable `--output`. |
| `backend targets` | Always. | — | — | — |
| `backend formats` | Backend listed. | — | — | Unknown backend name. |
| `pipeline resolve` | All sources resolved. | At least one source errored. | Pipeline file unreadable. | Bad `--source` ID. |

## Non-obvious behaviours

- `engine eval` logs per-rule parse errors as warnings on stderr and exits `0`. Use `rule validate` for a strict per-rule gate.
- `engine eval` exits `0` by default even when matches fire. Pass `--fail-on-detection` to make matches fail the build.
- `rule lint` exits `0` for findings below `--fail-level`. The default threshold is `error`, so a clean lint with only info or warning findings still returns `0`.
- The `hint` lint severity never triggers exit `1`, even with `--fail-level info`.

## CI patterns

The [CI/CD guide](../guide/ci-cd.md#exit-codes) shows the GitHub Actions, GitLab CI, pre-commit, and generic shell pipelines that consume these codes.

## See also

- [`exit_code` module on GitHub](https://github.com/timescale/rsigma/blob/main/crates/rsigma-cli/src/exit_code.rs)
- [CI/CD](../guide/ci-cd.md) for end-to-end pipeline examples.
- [`rule lint`](../cli/rule/lint.md), [`engine eval`](../cli/engine/eval.md), [`rule validate`](../cli/rule/validate.md) for per-command flag tables.
