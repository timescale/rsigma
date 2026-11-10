---
description: "Reference for rsigma config schema: emit the JSON Schema for the rsigma configuration file, for editor validation and autocompletion of YAML config."
---

# `rsigma config schema`

{{ added "0.14.0" }}

Emit a [JSON Schema](https://json-schema.org/) describing the RSigma config file.

## Synopsis

```text
rsigma config schema
```

## Description

Prints a JSON Schema (draft 2020-12) derived from the same `RsigmaConfigPartial` Rust types the loader uses, so the schema can never drift from what the binary accepts. The schema covers every supported key, including feature-gated sections, the secrets-out-of-config policy (secret fields are absent), and the section structure.

The schema has two main consumers:

- Editors with the [yaml-language-server](https://github.com/redhat-developer/yaml-language-server) extension auto-complete keys and flag typos as you edit. The template emitted by [`config init`](init.md) carries a `# yaml-language-server: $schema=` header pointing at the published schema.
- AI agents and CI tooling can programmatically validate a config before applying it.

## Output

The schema is printed to stdout as pretty-printed JSON. The global [`--output-format`](../../reference/output.md) selector is accepted but the payload is always the schema JSON (other formats warn).

```bash
rsigma config schema | jq '.title'
# "RsigmaConfigPartial"
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Schema emitted. |
| `3` | Schema serialization failed (should never happen in practice). |

## Examples

Validate a config against the schema with an external tool:

```bash
rsigma config schema > /tmp/rsigma.schema.json
check-jsonschema --schemafile /tmp/rsigma.schema.json rsigma.yaml
```

The docs site publishes that schema at <https://rsigma.io/rsigma.schema.json>. [`config init`](init.md), the config template, and the systemd example already point `yaml-language-server` at that URL. The file in the repository is `docs/rsigma.schema.json`, copied to the site root when the docs build. It is the stdout of `rsigma config schema` from an `--all-features` build, which is how the release archives and the container image are built. Regenerate it when the config types change:

```bash
cargo run -p rsigma --all-features -- config schema > docs/rsigma.schema.json
```

## See also

- [`config init`](init.md) emits a template with the `$schema` header.
- [`config validate`](validate.md) is the canonical loader-side check.
