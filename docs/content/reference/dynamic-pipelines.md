---
description: "Reference for binding reusable dynamic sources into RSigma processing pipelines through vars, placeholders, and include directives."
---

# Dynamic Pipelines

{{ added "0.10.0" }}

A dynamic pipeline is a processing pipeline that consumes one or more [dynamic sources](dynamic-sources.md). Sources are declared independently in `--source` files, so the same source can also serve [`lookup` enrichers](../guide/enrichers.md#using-dynamic-sources-with-lookup-enrichers) or other pipelines.

This page documents the pipeline-specific binding syntax. For source types, data formats, extraction, refresh policies, and error handling, see [Dynamic Sources](dynamic-sources.md).

## Loading

Load the pipeline and source declarations separately:

```bash
rsigma engine daemon -r rules/ -p pipeline.yml --source sources.yml
```

The source file has a top-level `sources:` list:

```yaml
# sources.yml
sources:
  - id: ip_blocklist
    type: http
    url: https://feeds.example.com/blocklist.json
    format: json
    extract: ".ips"
    refresh: 5m
```

Pipeline-embedded `sources:` blocks are rejected. Use [`rule migrate-sources`](../cli/rule/migrate-sources.md) to extract a legacy block into a standalone source file.

## Source references in `vars`

The `${source.<id>}` syntax binds a resolved source value to a pipeline variable:

```yaml
# pipeline.yml
name: dynamic_threat_intel
priority: 50
vars:
  blocklist: "${source.ip_blocklist}"

transformations:
  - type: value_placeholders
```

Rules consume the variable through the standard Sigma `%name%` placeholder and the `|expand` modifier:

```yaml
detection:
    selection:
        DestinationIp|expand: '%blocklist%'
    condition: selection
```

Whole-value substitution, where `${source.X}` is the complete `vars:` value, preserves arrays so `value_placeholders` can expand them into rule values. Inline substitution stringifies the source value and is best suited to scalars:

```yaml
vars:
  greeting: "Hello, ${source.environment.org_name}!"
```

Dot-path indexing selects a nested value:

```yaml
vars:
  admin_emails: "${source.environment.admin_emails}"
  log_index: "${source.environment.log_index}"
```

Source references expand only in `vars:` and `include:`. Typed transformation fields such as `add_condition.conditions.<field>` do not expand `${source.*}` directly. Bind the source to `vars:` and use `value_placeholders` instead.

## Include directives

A source that resolves to a JSON array of transformation objects can supply pipeline transformations:

```yaml
transformations:
  - include: ${source.dynamic_transforms}
```

The following constraints apply:

- The resolved value must be an array of transformation objects, not a single object.
- Nested includes are rejected. `MAX_INCLUDE_DEPTH` is `1`.
- HTTP and NATS sources require `--allow-remote-include`. File and command sources are allowed by default.

The remote-source restriction limits the impact of a compromised endpoint or NATS broker. See [Security Hardening](security.md#include-directive-security-model).

## Reuse across pipelines and enrichers

A source ID has one declaration and one daemon-managed cache entry. Multiple pipelines can reference it, and a `lookup` enricher can read the same cached value:

```yaml
# enrichers.yml
enrichers:
  - id: blocklist_context
    kind: detection
    type: lookup
    inject_field: blocklist_entry
    source: ip_blocklist
    extract: '.[] | select(. == "${detection.fields.DestinationIp}")'
```

The pipeline and enricher remain independent consumers. A source does not need a pipeline reference to be available to an enricher.

## Validation and inspection

Resolve declarations without starting the daemon:

```bash
rsigma pipeline resolve -p pipeline.yml --source-file sources.yml --pretty
rsigma pipeline resolve -p pipeline.yml --source-file sources.yml --dry-run
```

`pipeline resolve` reports the resolved source values. It still requires `-p` so it can detect legacy pipeline-embedded source declarations and invalid dynamic references.

Validate rules, pipelines, and live source resolution together:

```bash
rsigma rule validate rules/ \
    -p pipeline.yml \
    --source sources.yml \
    --resolve-sources
```

Use the validation form as the CI gate when source availability is required.

## See also

- [Processing Pipelines](../guide/processing-pipelines.md) for the complete pipeline model and transformation catalog.
- [Dynamic Sources](dynamic-sources.md) for declarations, source types, refresh, errors, and resource limits.
- [Enrichers](../guide/enrichers.md#using-dynamic-sources-with-lookup-enrichers) for consuming the same source cache after evaluation.
- [`pipeline resolve`](../cli/pipeline/resolve.md) for command flags and output formats.
