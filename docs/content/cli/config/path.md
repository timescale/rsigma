---
description: "Reference for rsigma config path: print the configuration files rsigma would load for the daemon, eval, and backtest, in increasing precedence order."
---

# `rsigma config path`

{{ added "0.14.0" }}

Print the config files that would be loaded by commands that use the layered config (daemon, eval, backtest, and others), in increasing precedence order.

## Synopsis

```text
rsigma config path [--config <PATH>]
```

## Description

Useful when troubleshooting "which config is actually winning?" without firing up the daemon. Walks the same discovery chain (system → user → nearest `.rsigmarc` → `./rsigma.yaml`/`./rsigma.yml`, or `--config`) and prints one path per line. Prints `none` when no file is found.

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-c, --config <PATH>` | discovery chain | Echo this path back instead of running discovery. |

The global [`--output-format`](../../reference/output.md) selector is honored: the default is one path per line (or `none`); `json`/`ndjson`/`table`/`csv`/`tsv` emit `SOURCE,PATH` rows.

## Examples

```bash
$ rsigma config path
/etc/rsigma/config.yaml
/home/operator/.config/rsigma/config.yaml
./rsigma.yaml
```

```bash
$ rsigma config path
none
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Discovery completed (zero or more paths printed). |

## See also

- [`config show`](show.md) for the resolved values, not just the file list.
- [Configuration Reference](../../reference/configuration.md#discovery).
