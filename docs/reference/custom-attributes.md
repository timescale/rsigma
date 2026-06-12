# Custom Attributes

Sigma rules accept a `custom_attributes:` mapping for engine and backend hints that aren't part of the core Sigma spec. RSigma recognizes two namespaces:

- `rsigma.*` — engine and correlation behaviour, mostly per-rule overrides of `engine eval` and `engine daemon` CLI flags.
- `postgres.*` — PostgreSQL/TimescaleDB backend routing, used by `backend convert -t postgres` to put specific rules on specific tables, schemas, or databases.

CLI flags and library API calls always take precedence over `custom_attributes` values. Engine-level attributes (`rsigma.timestamp_field`, `rsigma.suppress`, `rsigma.action`) apply only when the CLI did not already set the corresponding flag. Per-correlation attributes always override engine defaults for that rule.

## `rsigma.*` attributes

| Attribute | Effect | Equivalent CLI flag | Scope |
|-----------|--------|---------------------|-------|
| `rsigma.timestamp_field` | Prepends a field name to the timestamp extraction priority list. Default list: `@timestamp`, `timestamp`, `EventTime`, `TimeCreated`, `eventTime`. | `--timestamp-field` | Engine |
| `rsigma.suppress` | Suppression window for repeated correlation alerts. Duration string: `5m`, `1h`, `30s`. | `--suppress` | Engine + per-correlation |
| `rsigma.action` | Post-fire action: `alert` (keep state, re-alert) or `reset` (clear window). | `--action` | Engine + per-correlation |
| `rsigma.include_event` | Embed the full event JSON in detection output for this rule. `"true"` or `"false"`. | `--include-event` | Per-rule |
| `rsigma.correlation_event_mode` | Correlation event inclusion: `none`, `full` (deflate-compressed bodies), `refs` (timestamp + ID only). | `--correlation-event-mode` | Per-correlation |
| `rsigma.max_correlation_events` | Cap on events stored per correlation window for this rule. Integer. | `--max-correlation-events` | Per-correlation |
| `rsigma.max_group_entries` | Cap on retained entries within a single group's window state for this rule (timestamps, value pairs, or per-rule hits). Oldest entries are dropped; session windows keep their span anchor. Integer, quoted. | `--max-group-entries` | Per-correlation |

### Example: keep full events for a brute-force rule, default for everything else

```yaml
title: Brute force login
id: aaaa1111-2222-3333-4444-555555555555
correlation:
    type: event_count
    rules: [failed_login]
    group-by: [User]
    timespan: 5m
    condition: { gte: 5 }
custom_attributes:
    rsigma.correlation_event_mode: "full"
    rsigma.max_correlation_events: 50
```

### Example: longer suppression for a noisy rule

```yaml
title: PowerShell execution
custom_attributes:
    rsigma.suppress: 30m
```

## `postgres.*` attributes

Used by `backend convert -t postgres`. The precedence is, from highest to lowest:

1. Rule-level `custom_attributes` (`postgres.table`, `postgres.schema`, `postgres.database`).
2. Pipeline `set_state` (`key: table`, `key: schema`, `key: database`).
3. CLI backend options (`-O table=...`, `-O schema=...`, `-O database=...`).
4. Backend defaults (`security_events`, no schema, no database).

| Attribute | Effect |
|-----------|--------|
| `postgres.table` | Override the target table for this rule. Generated SQL uses the override instead of `security_events`. |
| `postgres.schema` | Set the PostgreSQL schema for this rule. Useful for multi-tenant setups. |
| `postgres.database` | Connection-level metadata used by some output formats. |

### Example: route a process_creation rule to a dedicated table

```yaml
title: Process Creation
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
custom_attributes:
    postgres.table: process_events
    postgres.schema: siem
```

The generated SQL targets `siem.process_events` instead of the default `security_events`.

## Other namespaces (future)

The `custom_attributes:` mapping is namespace-aware: only `rsigma.*` and `postgres.*` are interpreted by the engine and PostgreSQL backend today. Other namespaces survive parsing but have no behaviour attached. Future backends (LynxDB extensions, planned ATT&CK enricher) will reserve their own namespaces; today's rules using unknown namespaces will silently be ignored, so an authoring mistake (a typo like `rsima.suppress`) will be silent. Always lint with [`rule lint`](../cli/rule/lint.md), which flags unknown `rsigma.*` and `postgres.*` keys.

## See also

- [`engine eval`](../cli/engine/eval.md) and [`engine daemon`](../cli/engine/daemon.md) for the matching CLI flags.
- [Processing Pipelines: custom attributes](../guide/processing-pipelines.md#custom-attributes-rsigma-and-postgres) for setting these via `set_custom_attribute` instead of writing them per rule.
- [Rule Conversion: custom table per rule](../guide/rule-conversion.md#custom-table-per-rule) for the PostgreSQL routing flow.
- [`rsigma-eval` README: custom attributes](https://github.com/timescale/rsigma/blob/main/crates/rsigma-eval/README.md#custom-attributes-rsigma) for the library API.
