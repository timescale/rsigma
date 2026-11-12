---
description: "Reference for rsigma config show: print the effective rsigma configuration after merging every layer, annotated with the layer each value came from."
---

# `rsigma config show`

{{ added "0.14.0" }}

Print the effective configuration after all layers have been merged, annotated with the layer each value came from.

## Synopsis

```text
rsigma config show [--config <PATH>] [--for <global|daemon|eval>] [--format <text|json|yaml>]
```

## Description

Resolves the config the same way `engine daemon` and `engine eval` do at startup, except that this command stops short of the CLI-flag layer (it has no live command-line to read flags from). Concretely it folds:

1. compiled defaults
2. discovered config files (system → user → `.rsigmarc` → `./rsigma.yaml`, or `--config`)
3. the `RSIGMA_*` environment layer

into a single tree, and reports the winning layer for every leaf. Security-sensitive keys set in a project file are left out of the tree, as they are at startup, and each one prints a warning on stderr (see [Project config trust](../../reference/configuration.md#project-config-trust)). {{ added "0.27.0" }} To inspect what a specific live invocation would resolve to, including the flag layer, use `--dry-run` on `engine daemon` or `engine eval` instead.

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-c, --config <PATH>` | discovery chain | Load only this file. |
| `--for <SECTION>` | all sections | Restrict output to `global`, `daemon`, or `eval`. Other top-level sections (`backtest`, `mcp`, …) appear only when `--for` is omitted. |
| `--format <text\|json\|yaml>` | `text` when unset | Output shape. When unset, the global `--output-format` is used (`json`/`ndjson`/`table`/`csv`/`tsv`). Local `--format` wins over the global selector and prints a precedence warning. See [Output Formats](../../reference/output.md). |

## Output

### Text mode

One line per leaf: `<dotted.path> = <value>  (<source>)`. The source is one of `default`, `file`, `env`, or `flag` (`flag` only appears in command `--dry-run` output, never here).

```text
daemon.api.addr = 127.0.0.1:7777  (env)
daemon.input.batch_size = 128  (default)
daemon.input.buffer_size = 50000  (file)
```

### JSON mode

An envelope that pairs the resolved tree with the per-leaf source map.

```json
{
  "config": {
    "daemon": { "api": { "addr": "9.9.9.9:1" } }
  },
  "sources": {
    "daemon.api.addr": "file"
  },
  "ignored_keys": []
}
```

`ignored_keys` {{ added "0.27.0" }} lists the protected keys dropped from project files as `{ "file", "key" }` objects. JSON mode prints no stderr warning for them.

### YAML mode

Just the resolved tree, suitable for piping back into the file layer.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Resolved successfully. |
| `3` | A config file could not be read or parsed. |

## Examples

See what a daemon would use, with the env layer applied:

```bash
RSIGMA_DAEMON__API__ADDR="127.0.0.1:7777" rsigma config show --for daemon
```

Round-trip the effective config to a new file:

```bash
rsigma config show --format yaml > effective.yaml
```

Diff what your repo's `.rsigmarc` adds on top of the user defaults:

```bash
diff <(rsigma config show --config ~/.config/rsigma/config.yaml --format yaml) \
     <(rsigma config show --format yaml)
```

## See also

- [`config validate`](validate.md) to surface unknown keys and inactive sections.
- [Configuration Reference](../../reference/configuration.md) for the precedence model.
