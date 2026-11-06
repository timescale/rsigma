# Workflows

Command names and the convert split are in [SKILL.md](../SKILL.md). This page is the loop. Flag tables are on [rsigma.io](https://rsigma.io/), not here.

Author Sigma YAML with the sigma-rules skill. Use the steps below to check and run it.

## Write, lint, evaluate, convert

Prefer the MCP tool when `rsigma mcp serve` is connected. Otherwise use the CLI.

1. **Draft.** Hand-authored YAML (sigma-rules), `rule draft` from exemplar events, or `reverse_convert` / `rule reverse` from a Lucene query, which needs at least one logsource product, category, or service. Call `parse_rule` (or `rule parse`) and stop if the rule is invalid. Parse errors cover a missing logsource, conflicting modifiers, values of the wrong type, invalid regexes, and undefined detections, and each names the field.
2. **Lint.** `lint_rules` or `rule lint`. Each finding has a rule id and a `fixable` flag. Apply a known-safe fix with `fix_rules` or `rule lint --fix`. Rewrite the rest by hand. Do not treat a count of checks as stable. The catalogue is the [linting guide](https://rsigma.io/guide/linting-rules/).
3. **Format.** `rule fmt --write` rewrites the file into the canonical layout and keeps comments. Run `rule fmt --check` in CI. The formatter refuses any rewrite that would change what the rule means. Guide: [Formatting Rules](https://rsigma.io/guide/formatting-rules/).
4. **Evaluate.** `evaluate_events` or `engine eval` against a few positive and negative events. `match_detail` of `summary` or `full` explains why an event matched. When the events live on the rule as `rsigma.exemplars`, `test_exemplars` or `rule test` is the closed runner.
   Correlation inputs do not produce standalone output by default, including a correlation that feeds another correlation. Set top-level `generate: true` on the referencing correlation or pass `--emit-detections` when those matches are needed.
5. **Tune.** For a noisy rule, `tune_rules` or `rule tune` with classified false positives and a true-positive set that must still fire. Review the returned filter before writing it.
   Target filters by rule `id` or `name`, not title. Selector patterns in a filter condition refer only to that filter's own detection items.
6. **Validate.** `validate_rules` or `rule validate` on the set, with pipelines when the rules depend on them. Parse warnings, such as an invalid `status` or `level`, are reported but do not fail validation; pass `fail_level: warning` (or the [`rule validate`](https://rsigma.io/cli/rule/validate/) `--fail-level` flag) to fail on them.
   Pipeline conditions use the pySigma `*_cond_op`, `*_cond_not`, and `*_cond_expr` keys. Placeholder transformations require `|expand` values; `value_placeholders` must resolve every variable unless runtime substitution is explicitly enabled.
7. **Convert.** `convert_rules` or `backend convert` to the deployment target. Native targets run in-process. Other targets need sigma-cli, and on MCP they also need `--allow-sigma-cli`.

Guide: [MCP server](https://rsigma.io/guide/mcp-server/).

## Eval versus daemon

`engine eval` reads a fixed input and exits. Use it to test a rule.

`engine daemon` stays up, reloads rules, and exposes health and metrics. Use it when events are a stream. It needs the `daemon` feature. NATS input also needs `daemon-nats`, and OTLP logs arrive on `/v1/logs` on the API address with `daemon-otlp`, not through `--input`. Release binaries include all three; a `cargo install rsigma` build has only `daemon`.

The API binds `0.0.0.0:9090` by default, and a non-loopback address refuses to start unless it has TLS (or `--allow-plaintext`) and authentication (`--api-token-env`, `--tls-client-ca`, or `--allow-unauthenticated`). For local work pass `--api-addr 127.0.0.1:9090`, which needs neither. See [Daemon network exposure](https://rsigma.io/reference/security/#daemon-network-exposure).

Guide: [Evaluating rules](https://rsigma.io/guide/evaluating-rules/), [Streaming detection](https://rsigma.io/guide/streaming-detection/).

## Draft versus a rule you already know

`rule draft` proposes a detection from exemplar events, optionally contrasted with a baseline. `rule draft --groups` proposes a temporal correlation from grouped, timed exemplars. Use draft when the user has events and wants a rule inferred from them.

When the user describes the behavior in words, write the YAML with sigma-rules. Then run the loop above. Do not ask draft to invent a rule from a sentence.

Guide: [Rule drafting](https://rsigma.io/guide/rule-drafting/).

## Convert

Native versus delegated targets are in the Convert section of [SKILL.md](../SKILL.md#convert). When delegation fails, read the error. If `sigma` could not be found or executed, install sigma-cli or set `RSIGMA_SIGMA_CLI`. If sigma-cli rejects the target, install that backend plugin (`sigma plugin install <name>`), then check `rsigma backend targets`.
