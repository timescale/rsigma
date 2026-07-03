# `rsigma engine discover-schemas`

Mine unrecognized events into candidate schema signatures you can review and commit.

## Synopsis

```text
rsigma engine discover-schemas [OPTIONS]
```

## Description

Reads a JSON/NDJSON corpus, runs a pure-Rust, glass-box mining pass over the events no built-in or `--schema-config` signature already recognizes (the `unknown` and `generic_json` events), and prints ranked candidate declarative signatures plus a paste-ready `schemas:` block. It clusters events by their field-key shape, picks the fields (and low-cardinality values) that best discriminate each cluster, and emits the same signature YAML that [`engine classify`](classify.md) and [schema routing](../../guide/schema-routing.md) consume via `--schema-config`.

This closes the authoring loop the schema tooling otherwise leaves to you: `engine classify` shows you have unknowns, `discover-schemas` proposes signatures, and classifying again with the pasted config verifies them. It never loads rules, evaluates detections, or applies a discovered signature on its own; a human always reviews and renames the proposals first (the emitted names are placeholders like `discovered_alert`).

For the live equivalent on a running daemon, see [`GET /api/v1/schemas/suggestions`](../../reference/http-api.md#get-apiv1schemassuggestions) and the `--discover-schemas` flag on [`engine daemon`](daemon.md).

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-e, --event <EVENT>` | stdin | A single event as a JSON string, or `@path` to read NDJSON from a file. Without this flag, reads NDJSON from stdin. |
| `--schema-config <PATH>` | unset | YAML file of user-defined schema signatures. Events these already recognize are excluded from mining (alias-aware), so a defined schema is never re-proposed. |
| `--min-support <N>` | `3` | Minimum events a cluster must contain to yield a candidate. Filters out one-off shapes. |
| `--similarity <F>` | `0.6` | Jaccard similarity (0.0-1.0) at or above which shapes merge into one cluster. Higher is stricter (more, tighter clusters). |
| `--max-candidates <N>` | `20` | Maximum candidates to emit, highest support first. |
| `--max-predicates <N>` | `3` | Maximum predicates per candidate signature. |
| `--no-value-markers` | off | Propose presence predicates only; never emit `equals`/`in` value markers. |
| `--dry-run` | off | Reclassify the corpus with the proposed signatures loaded and report the before/after per-schema counts. |
| `--emit <report\|yaml>` | `report` | `report` prints candidates with stats in the global output format; `yaml` prints only the paste-ready `schemas:` block. |

The global [`--output-format`](../../reference/output.md) flag selects `json`, `ndjson`, `table`, `csv`, or `tsv` for the report.

## How proposals are built

- **Exclusion.** Events already recognized by a built-in or a `--schema-config` signature are skipped; only `unknown` and `generic_json` events are mined.
- **Clustering.** Events collapse to distinct field-key shapes, which merge by Jaccard similarity. A diversity guard keeps two shapes that disagree on a single constant marker (for example `vendor: foo` vs `vendor: bar`) in separate clusters rather than fusing distinct schemas.
- **Selection.** Each cluster's most discriminative fields become a minimal 1-3 predicate conjunction, weighted so a rarer marker beats a near-ubiquitous field. A low-cardinality, non-sensitive constant value becomes an `equals`/`in` marker; everything else becomes `field_present`. High-cardinality or free-form values (command lines, paths, IPs) are never emitted as value markers.
- **Suggested specificity** sits above `generic_json` and below the strong built-ins, and each candidate is checked against the built-ins so a shadowed proposal is dropped.

## Redaction

The offline command reads a corpus you already hold and derives low-cardinality value markers in-process, emitting them only into the candidate YAML for your review. The online [suggestions endpoint](../../reference/http-api.md#get-apiv1schemassuggestions) instead mines a keys-only sample (values are never retained), so its proposals are presence-only.

## Examples

Discover signatures from an NDJSON corpus and print the report:

```bash
cat events.ndjson | rsigma engine discover-schemas --output-format table
```

Emit only the paste-ready block and append it to a schema config:

```bash
rsigma engine discover-schemas -e @events.ndjson --emit yaml >> schemas.yml
```

Preview the classification impact before committing:

```bash
rsigma engine discover-schemas -e @events.ndjson --dry-run --output-format table
```

Skip anything an existing config already recognizes:

```bash
rsigma engine discover-schemas -e @events.ndjson --schema-config schemas.yml
```

## Output

The structured report carries a `summary` (`events_mined`, `shapes`, `clusters`, `candidates`, `parse_errors`), a `candidates` array (each with `name`, `specificity`, `source` of `corpus` or `keys-only`, `support`, `coverage_of_unknown`, `predicates`, `sample_field_sets`, and any `overlap_warnings`), and a `signatures_yaml` string identical to `--emit yaml`. With `--dry-run` a `dry_run` object carries the before/after per-schema counts. In `table` format the paste-ready block prints below the table.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `2` | Bad input (invalid inline JSON, unreadable file) |
| `3` | Bad schema config |

See [Exit Codes](../../reference/exit-codes.md) for the full scheme.
