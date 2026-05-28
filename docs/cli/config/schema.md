# `rsigma config schema`

Emit a [JSON Schema](https://json-schema.org/) describing the rsigma config file.

## Synopsis

```text
rsigma config schema
```

## Description

Prints a JSON Schema (draft 2020-12) derived from the same `RsigmaConfigPartial` Rust types the loader uses, so the schema can never drift from what the binary accepts. The schema covers every supported key, including feature-gated sections, the secrets-out-of-config policy (secret fields are simply absent), and the section structure.

Two main consumers:

- **Editors** with the [yaml-language-server](https://github.com/redhat-developer/yaml-language-server) extension auto-complete keys and flag typos as you edit. The template emitted by [`config init`](init.md) carries a `# yaml-language-server: $schema=` header pointing at the published schema.
- **AI agents and CI tooling** can programmatically validate a config before applying it.

## Output

The schema is printed to stdout as pretty-printed JSON.

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

Publish the schema for editor consumption alongside a release:

```bash
rsigma config schema > rsigma.schema.json
# Upload to a stable URL referenced by the `$schema` header in the template.
```

## See also

- [`config init`](init.md) — emits a template with the `$schema` header.
- [`config validate`](validate.md) — the canonical loader-side check.
