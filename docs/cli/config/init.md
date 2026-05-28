# `rsigma config init`

Write a commented YAML config template to disk.

## Synopsis

```text
rsigma config init [--output <PATH>] [--force]
```

## Description

Scaffolds a `rsigma.yaml` populated with every supported section, sensible defaults, and inline comments documenting each key. The first line is a `# yaml-language-server: $schema=` header that lets editors with the yaml-language-server extension auto-complete and validate the file against the [JSON Schema](schema.md) generated from the same source as the config loader.

By default the template is written to `./rsigma.yaml`. Running `init` against an existing file is refused unless `--force` is passed; this is deliberate so an accidental re-run never clobbers operator edits.

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-o, --output <PATH>` | `./rsigma.yaml` | Where to write the template. |
| `--force` | off | Overwrite an existing file. |

## Examples

Scaffold the default location:

```bash
rsigma config init
```

Scaffold a system-wide config and check it loads cleanly:

```bash
sudo mkdir -p /etc/rsigma
sudo rsigma config init -o /etc/rsigma/config.yaml
rsigma config validate -c /etc/rsigma/config.yaml
```

Regenerate the template after a version bump:

```bash
rsigma config init --force
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Template written. |
| `3` | File exists and `--force` was not passed, or the write failed. |

## See also

- [`config validate`](validate.md) to check the resulting file.
- [Configuration Reference](../../reference/configuration.md) for the schema, discovery, and precedence rules.
