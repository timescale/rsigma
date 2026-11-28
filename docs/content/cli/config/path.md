---
description: "Reference for rsigma config path: print the configuration files rsigma would load, and every location discovery searched, in increasing precedence order."
---

# `rsigma config path`

{{ added "0.14.0" }}

Print the config files that would be loaded by commands that use the layered config (daemon, eval, backtest, and others), in increasing precedence order.

## Synopsis

```text
rsigma config path [--config <PATH>]
```

## Description

Useful when troubleshooting "which config is actually winning?" without firing up the daemon. Walks the same discovery chain (system → user → nearest `.rsigmarc` → `./rsigma.yaml`/`./rsigma.yml`, or `--config`) and prints one loaded path per line on stdout. Prints `none` when no file is loaded.

Without `--config`, it then prints every location it searched to stderr, with the layer name and whether the file was loaded, not found, or skipped by the [ownership check](../../reference/configuration.md#file-ownership) (with the reason). The system location is `/etc/rsigma/config.yaml` on Linux and macOS and `%ProgramData%\rsigma\config.yaml` on Windows. A `.rsigmarc` that was not found is shown as the directory the upward walk started in. {{ added "unreleased" }}

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-c, --config <PATH>` | discovery chain | Echo this path back instead of running discovery. |

The global [`--output-format`](../../reference/output.md) selector is honored: the default is one path per line (or `none`); `json`/`ndjson`/`table`/`csv`/`tsv` emit `SOURCE,PATH` rows for the loaded files. The `json` envelope also carries `searched`, one object per location with `layer` (`system`, `user`, `project_rc`, `project_yaml`, or `explicit`), `path`, `status` (`loaded`, `missing`, or `skipped`), and `reason` for a skipped file. {{ added "unreleased" }}

## Examples

```bash
$ rsigma config path
/home/operator/.config/rsigma/config.yaml
./rsigma.yaml
Searched (low to high precedence):
  system       /etc/rsigma/config.yaml (not found)
  user         /home/operator/.config/rsigma/config.yaml (loaded)
  project_rc   .rsigmarc in /home/operator/detections or above (not found)
  project_yaml ./rsigma.yaml (loaded)
```

```bash
$ rsigma config path 2>/dev/null
none
```

On Windows the system row names the `ProgramData` folder:

```text
  system       C:\ProgramData\rsigma\config.yaml (not found)
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Discovery completed (zero or more paths printed). |

## See also

- [`config show`](show.md) for the resolved values, not just the file list.
- [Configuration Reference](../../reference/configuration.md#discovery).
