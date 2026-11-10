---
description: "Reference for rsigma taxii store: import a local STIX 2.1 bundle JSON file into an on-disk STIX object store for threat intelligence workflows."
---

# `rsigma taxii store`

{{ added "0.23.0" }}

Import a local STIX 2.1 bundle JSON file into an on-disk store ([`FsStore`](../../library/rstix.md#rstix-graph-marking-store)).

Requires the `taxii-sync` Cargo feature (included in prebuilt release binaries and the GHCR image built with `--all-features`).

## Synopsis

```text
rsigma taxii store --bundle <FILE> --store <DIR> [OPTIONS]
```

Use `--bundle -` to read bundle JSON from stdin.

## Description

`taxii store` parses a STIX bundle from disk (or stdin) and imports it with [`FsStore::import_bundle`](../../library/rstix.md#rstix-graph-marking-store). Validation uses the same `Validator::producer_strict()` profile as [`taxii sync`](sync.md): per-object validation before import, with the References phase skipped (appropriate for large bundles where refs resolve after the full import).

Re-running against the same store is idempotent: unchanged objects increment `objects_deduplicated` rather than `objects_added`.

Use this for air-gapped feeds, local MITRE ATT&CK JSON releases, CI fixtures, and development without a TAXII server. For network ingest, use [`taxii sync`](sync.md).

## Flags

### Required

| Flag | Description |
|------|-------------|
| `--bundle <FILE>` | STIX bundle JSON path, or `-` for stdin. |
| `--store <DIR>` | [`FsStore`](../../library/rstix.md#rstix-graph-marking-store) root directory (created when missing). |

### Import / validation

| Flag | Default | Description |
|------|---------|-------------|
| `--bundle-id <ID>` | bundle file `id` | Synthetic bundle id for [`export_bundle`](../../library/rstix.md#rstix-graph-marking-store). |
| `--allow-custom` | off | Parse MITRE ATT&CK and other custom SDOs (`x_*` types). Required for enterprise ATT&CK bundle files. |
| `--strict` | on | Exit `1` when validation rejects one or more objects. |
| `--allow-invalid` | off | Import objects even when validation fails (diagnostics still recorded; conflicts with `--strict`). |

## Output

Structured summary via the global [`--output-format`](../index.md#global-flags) flag (`json`, `ndjson`, `table`, `csv`, `tsv`). Validation rejections are listed on stderr when progress output is enabled.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Import completed; no validation rejections (or `--allow-invalid`). |
| `1` | Validation rejected one or more objects under default `--strict`. |
| `3` | Configuration, parse, or store error. |

## Examples

Import a local bundle into `./stix-store`:

```bash
rsigma taxii store \
  --bundle ./feeds/indicators.json \
  --store ./stix-store
```

Import MITRE ATT&CK Enterprise release JSON (custom types):

```bash
rsigma taxii store \
  --bundle ./enterprise-attack-19.2.json \
  --store ./attck-store \
  --allow-custom
```

Pipe bundle JSON from another tool:

```bash
curl -fsS https://example.com/bundle.json | rsigma taxii store --bundle - --store ./stix-store
```

Point daemon enrichment at the same directory:

```bash
rsigma engine daemon -r rules/ \
  --stix-store ./attck-store \
  --enrichers enrichers.yml \
  --input http --output stdout
```

## See also

- [`taxii sync`](sync.md): paginated TAXII collection ingest
- [Enrichers: STIX local store lookup](../../guide/enrichers.md#stix-local-stix-store-lookup)
- [Feature flags: `taxii-sync`](../../reference/feature-flags.md#rsigma-cli)
