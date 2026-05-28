# `rsigma config path`

Print the config files that would be loaded by the daemon or eval, in increasing precedence order.

## Synopsis

```text
rsigma config path [--config <PATH>]
```

## Description

Useful when troubleshooting "which config is actually winning?" without firing up the daemon. Walks the same discovery chain (system → user → `.rsigmarc` → `./rsigma.yaml`, or `--config`) and prints one path per line. Prints `none` when no file is found.

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-c, --config <PATH>` | discovery chain | Echo this path back instead of running discovery. |

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
