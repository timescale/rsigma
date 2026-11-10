---
description: "Reference for rsigma taxii sync: fetch objects from a TAXII 2.1 collection and persist them in a local on-disk STIX 2.1 store."
---

# `rsigma taxii sync`

{{ added "0.23.0" }}

Fetch objects from a TAXII 2.1 collection and persist them in a local on-disk STIX store ([`FsStore`](../../library/rstix.md#rstix-graph-marking-store)).

Requires the `taxii-sync` Cargo feature (included in prebuilt release binaries and the GHCR image built with `--all-features`).

## Synopsis

```text
rsigma taxii sync --server <URL> --collection <ID> --store <DIR> [OPTIONS]
```

## Description

`taxii sync` calls [`ingest_collection_with_bundle_id`](../../library/rstix.md#rstix-taxii-client) with `IngestOptions::producer_strict()`: per-object validation before import, with the References phase skipped for paginated pages (see [validate-on-ingest](../../library/rstix.md#rstix-taxii-client)). The TAXII client fetches one page at a time (`--limit`, default 64); forward references across pages resolve after the full collection is imported.

When `--api-root` is omitted, the client runs TAXII discovery and uses the server-declared default API root. Pass `--api-root` explicitly when the feed uses a non-default root.

Re-running sync against the same store is idempotent: unchanged objects increment `objects_deduplicated` rather than `objects_added`.

## Flags

### Required

| Flag | Description |
|------|-------------|
| `--server <URL>` | TAXII server base URL (scheme + host, optional path prefix). |
| `--collection <ID>` | Collection id to ingest. |
| `--store <DIR>` | [`FsStore`](../../library/rstix.md#rstix-graph-marking-store) root directory (created when missing). |

### Connection

| Flag | Default | Description |
|------|---------|-------------|
| `--api-root <URL>` | discovery | Full API root URL. When omitted, discovery runs and the `default` API root is used. |
| `--timeout <DURATION>` | `60s` | HTTP timeout (`humantime` duration). |
| `--limit <N>` | `64` | TAXII page size (`limit` query parameter). Must be &gt; 0. |
| `--allow-insecure-http` | off | Allow `http://` URLs (local tests and wiremock only). |
| `--allow-custom` | off | Parse MITRE ATT&CK and other custom SDOs (`x_*` types). |

### Authentication (at most one)

| Flag | Env | Description |
|------|-----|-------------|
| `--bearer-token <TOKEN>` | `RSIGMA_TAXII_BEARER_TOKEN` | `Authorization: Bearer …`. Export the env var or pass `--bearer-token` on the **same** command line; a bare assignment on the previous line is not inherited by the next command in most shells. |
| `--basic-user` + `--basic-password` | `RSIGMA_TAXII_BASIC_PASSWORD` | HTTP Basic |
| `--api-key <VALUE>` | `RSIGMA_TAXII_API_KEY` | Custom header (name via `--api-key-header`, default `X-API-Key`) |

### mTLS

| Flag | Description |
|------|-------------|
| `--client-cert-pem` + `--client-key-pem` | PEM certificate and private key |
| `--client-p12` + `--client-p12-password` | PKCS#12/PFX identity (`RSIGMA_TAXII_CLIENT_P12_PASSWORD`) |

### Import / validation

| Flag | Default | Description |
|------|---------|-------------|
| `--bundle-id <ID>` | `bundle--00000000-0000-0000-0000-000000000001` | Synthetic bundle id for [`export_bundle`](../../library/rstix.md#rstix-graph-marking-store). |
| `--strict` | on | Exit `1` when validation rejects one or more objects. |
| `--allow-invalid` | off | Import objects even when validation fails (diagnostics still recorded; conflicts with `--strict`). |

## Output

Structured summary via the global [`--output-format`](../index.md#global-flags) flag (`json`, `ndjson`, `table`, `csv`, `tsv`). Validation rejections are listed on stderr when progress output is enabled.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Sync completed; no validation rejections (or `--allow-invalid`). |
| `1` | Validation rejected one or more objects under default `--strict`. |
| `3` | Configuration, store, or TAXII client error. |

## Examples

Sync a collection into `./stix-store` with a bearer token:

```bash
rsigma taxii sync \
  --server https://taxii.example.com/ \
  --api-root https://taxii.example.com/api1/ \
  --collection <COLLECTION_ID> \
  --store ./stix-store \
  --bearer-token "$RSIGMA_TAXII_BEARER_TOKEN" \
  --allow-custom
```

Feed daemon enrichment: point `engine daemon --stix-store` at the same directory and declare a `type: stix` enricher. See [Enrichers](../../guide/enrichers.md#stix-local-stix-store-lookup).

MITRE ATT&CK Enterprise (STIX 2.1 TAXII collection; requires `--allow-custom` for `x-mitre-*` types):

```bash
rsigma taxii sync \
  --server https://attack-taxii.mitre.org/ \
  --api-root https://attack-taxii.mitre.org/api/v21/ \
  --collection x-mitre-collection--1f5f1533-f617-4ca8-9ab4-6a02367fa019 \
  --store ./attck-store \
  --allow-custom
```

List available collections (Enterprise, ICS, Mobile share the same ids across API roots):

```bash
curl -sS \
  -H 'Accept: application/taxii+json;version=2.1' \
  'https://attack-taxii.mitre.org/api/v21/collections/' \
  | jq '.collections[] | {id, title}'
```

Pin a specific ATT&CK release by changing the API root (collection ids stay the same):

```bash
--api-root https://attack-taxii.mitre.org/api/v21/attack-19.2/
```

## See also

- [`taxii store`](store.md): import a local STIX bundle JSON file (air-gap, ATT&CK releases, fixtures)
- [rstix TAXII client](../../library/rstix.md#rstix-taxii-client)
- [Feature flags: `taxii-sync`](../../reference/feature-flags.md#rsigma-cli)
