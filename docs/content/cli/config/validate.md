---
description: "Reference for rsigma config validate: load every rsigma configuration layer and report problems before they cause a daemon or eval run to misbehave."
---

# `rsigma config validate`

{{ added "0.14.0" }}

Load every config layer that would apply at runtime and report problems before they cause a daemon or eval to misbehave.

## Synopsis

```text
rsigma config validate [--config <PATH>] [--format <text|json>] [--strict]
```

## Description

Walks the same [discovery chain](../../reference/configuration.md#discovery) the daemon and eval commands use, deserializes every layer, and reports:

- **Unknown keys** that don't match the schema (typo guard).
- **Inactive sections** that are set but inert in this build because the gating Cargo feature is disabled (`daemon` without the `daemon` feature, `daemon.nats` without `daemon-nats`, `daemon.api.tls` without `daemon-tls`).
- **Errors** that prevent a file from loading at all.

By default unknown keys are warnings; `--strict` upgrades them to hard errors so CI can gate on configuration cleanliness.

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-c, --config <PATH>` | discovery chain | Load only this file (bypasses discovery). |
| `--format <text\|json>` | `text` when unset | Human-readable summary on stderr or a machine-readable envelope on stdout. When unset, the global `--output-format` is used (`json`/`ndjson`/`table`/`csv`/`tsv`). Local `--format` wins over the global selector and prints a precedence warning. See [Output Formats](../../reference/output.md). |
| `--strict` | off | Exit with code `3` when any unknown key is reported. |

## Output

### Text mode

Diagnostics go to stderr. Loaded layers are listed in increasing precedence order, then each unknown key, ignored key, and inactive section is printed, followed by a summary line.

```text
Loaded (low to high precedence):
  - /etc/rsigma/config.yaml
  - ./rsigma.yaml
warning: unknown key 'bogus_key' in ./rsigma.yaml
warning: ignoring 'mcp.daemon_url' from project config ./rsigma.yaml; security-sensitive keys are read only from --config, the user or system config, environment variables, or flags
Config is valid.
```

An ignored key is a security-sensitive key set in a project file (`./rsigma.yaml` or `.rsigmarc`), which rsigma drops; see [Project config trust](../../reference/configuration.md#project-config-trust). Ignored keys do not fail validation, even with `--strict`. {{ added "unreleased" }}

### JSON mode

A single envelope is written to stdout (data goes to stdout; warnings stay on stderr only in text mode).

```json
{
  "ok": true,
  "sources": ["/etc/rsigma/config.yaml", "./rsigma.yaml"],
  "unknown_keys": [
    { "file": "./rsigma.yaml", "key": "bogus_key" }
  ],
  "ignored_keys": [
    { "file": "./rsigma.yaml", "key": "mcp.daemon_url" }
  ],
  "inactive_sections": []
}
```

`ignored_keys` {{ added "unreleased" }} lists the protected keys dropped from project files. Table, CSV, TSV, and NDJSON output report each one as an `ignored_key` row.

A failure surfaces `"ok": false` and (for parse failures) an `"error"` field.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Config loaded successfully. `--strict` exits 0 only when there are no unknown keys. |
| `3` | A file could not be read or parsed, or `--strict` saw unknown keys. |

## Examples

Check the discovered config:

```bash
rsigma config validate
```

Validate a specific file and fail the build on typos:

```bash
rsigma config validate -c rsigma.yaml --strict
```

Use the JSON envelope from a CI step:

```bash
rsigma config validate --format json | jq -e '.ok'
```

## See also

- [`config show`](show.md) to see the effective values after layering.
- [Configuration Reference](../../reference/configuration.md).
