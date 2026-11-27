---
description: "Write and run Sigma correlation rules in RSigma: all eight correlation types, group-by and aliases, time windows, chaining, suppression, state, and testing."
---

# Correlation Rules

A detection rule matches one event at a time. A correlation rule matches a pattern across many events: it watches the matches of the rules it references and fires when those matches, grouped by shared field values, satisfy a condition within a time window. Five failed logins for one user in five minutes, one source touching twenty distinct hosts in an hour, and reconnaissance followed by exfiltration from the same machine are all correlations.

RSigma implements all eight correlation types from the [Sigma correlation specification](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-correlation-rules-specification.md). Both [`engine eval`](evaluating-rules.md) and the [daemon](streaming-detection.md) evaluate them statefully. The [PostgreSQL backend](../reference/backends/postgres.md#correlation-rules) converts every type to SQL, and the [Fibratus backend](../reference/backends/fibratus.md#correlation-rules) converts the ones it can express as event sequences.

## Anatomy of a correlation

A correlation lives in its own YAML document next to the rules it references. This one fires when a single user fails to log in five times within five minutes:

```yaml
title: Failed login
name: failed_login
logsource:
    category: authentication
detection:
    selection:
        EventType: failed_login
    condition: selection
---
title: Brute force against one account
correlation:
    type: event_count
    rules:
        - failed_login
    group-by:
        - User
    timespan: 5m
    condition:
        gte: 5
level: high
```

| Key | Meaning |
|-----|---------|
| `correlation.type` | One of the [eight types](#the-eight-correlation-types). |
| `correlation.rules` | The rules whose matches feed this correlation, by `id` or `name`. They can be detection rules or other correlations (see [Chaining correlations](#chaining-correlations)). |
| `correlation.group-by` | Fields that partition matches into independent groups, each with its own window and count. Optional; without it, every match shares one group. |
| `correlation.timespan` | Window length: a whole number followed by `s`, `m`, `h`, `d`, `w`, `M` (month), or `y`, such as `30s`, `5m`, or `1h`. Must be greater than zero. `timeframe` is accepted as a synonym. |
| `correlation.condition` | When to fire. A mapping of `gt`, `gte`, `lt`, `lte`, `eq`, and `neq` with whole-number thresholds; combine operators for a range (`gt: 10` with `lte: 50`). The value types also need `field`, and the temporal types accept a boolean expression instead. |
| `correlation.aliases` | Maps one group-by name to a different field in each referenced rule (see [Aliases](#aliases)). |
| `generate` | Top-level boolean. When `true`, the referenced rules also produce their own results (see [What a correlation emits](#what-a-correlation-emits)). |

An event only counts toward a correlation if it carries every `group-by` field with a scalar value. An event where any of them is absent or null is skipped, a common reason for a correlation that never fires. Group-by fields are read after [processing pipelines](processing-pipelines.md) have renamed them, so use the post-pipeline names.

## The eight correlation types

Each type computes one number per group and window, the `aggregated_value` in the output, and compares it against `condition`.

| Type | Aggregated value | Needs `field` | Typical use |
|------|------------------|---------------|-------------|
| `event_count` | Number of matching events. | no | Brute force, alert storms, repeated failures. |
| `value_count` | Number of distinct values of `field`. A list of fields counts distinct combinations. | yes | One source scanning many ports or hosts, one user on many machines. |
| `value_sum` | Sum of `field`. | yes | Bytes transferred, records exported. |
| `value_avg` | Mean of `field`. | yes | Average request size or session length. |
| `value_percentile` | Value of `field` at `percentile` (0 to 100, default 50), by linear interpolation. | yes | Tail latency, unusually large transfers. |
| `value_median` | Median of `field`. | yes | Typical size or duration, robust to outliers. |
| `temporal` | Number of distinct referenced rules that matched. Fires when all of them did, unless `condition` says otherwise. | no | Several techniques from one host in a short span. |
| `temporal_ordered` | Same as `temporal`, but the rules must match in the order listed in `rules`. | no | Attack chains: access, then escalation, then exfiltration. |

The four numeric types read `field` as a number. Integers, floats, and numeric strings such as `"4096"` count; any other value is skipped. When several fields are listed, only the first is used.

### Counting distinct values

`value_count` fires on breadth rather than volume. This catches one source connecting to more than twenty distinct destination ports within ten minutes:

```yaml
title: Port scan from one source
correlation:
    type: value_count
    rules:
        - network_connection
    group-by:
        - SourceIp
    timespan: 10m
    condition:
        field: DestinationPort
        gt: 20
```

### Aggregating numeric values

`value_sum`, `value_avg`, `value_percentile`, and `value_median` aggregate a numeric field. This fires when one user downloads more than 500 MB in an hour:

```yaml
title: Bulk download by one user
correlation:
    type: value_sum
    rules:
        - file_download
    group-by:
        - User
    timespan: 1h
    condition:
        field: BytesTransferred
        gt: 500000000
```

For a percentile, add `percentile` to the condition: `field: Duration`, `percentile: 95`, `gt: 3000` fires when the 95th percentile of `Duration` in the window exceeds 3000.

### Temporal proximity and order

`temporal` fires when the referenced rules all match within the window for the same group, in any order. `temporal_ordered` additionally requires them to match in the order of `rules`:

```yaml
title: Discovery followed by exfiltration
correlation:
    type: temporal_ordered
    rules:
        - recon_whoami
        - archive_created
        - large_upload
    group-by:
        - Host
    timespan: 30m
```

Without a `condition`, both types require every distinct rule in `rules`. A threshold such as `gte: 2` fires once any two of them have matched. A string condition is a boolean expression over the rule names in `rules`:

```yaml
correlation:
    type: temporal
    rules:
        - recon_whoami
        - exfil_http
        - exfil_dns
    group-by:
        - Host
    timespan: 30m
    condition: recon_whoami and (exfil_http or exfil_dns)
```

## Aliases

Referenced rules do not always name the same thing the same way. A process event might call the host `Computer` while a network event calls it `hostname`. An alias gives the group-by a single name and maps it to the right field in each rule:

```yaml
title: Suspicious process then outbound connection
correlation:
    type: temporal
    rules:
        - suspicious_process
        - outbound_connection
    group-by:
        - host
    timespan: 5m
    aliases:
        host:
            suspicious_process: Computer
            outbound_connection: hostname
```

`group-by` lists the alias name, and each alias entry maps a rule reference from `rules` to the field to read from that rule's events. The output's `group_key` uses the alias name.

## Time windows

Correlation windows run on event time, not arrival time. The engine reads the timestamp from the first of `@timestamp`, `timestamp`, `EventTime`, `TimeCreated`, and `eventTime` that is present. Put your own field first with `--timestamp-field` or the `rsigma.timestamp_field` custom attribute. When an event has no parseable timestamp, the daemon uses the wall clock by default; pass `--timestamp-fallback skip` when replaying historical data so those events stay out of correlation state. [Input Formats](input-formats.md) lists the timestamp formats the engine recognizes.

By default the window slides: each match is compared against the matches within `timespan` before it, so two events correlate whenever they are close enough together, regardless of clock boundaries. RSigma also offers `tumbling` windows (fixed, boundary-aligned buckets) and `session` windows (open while matches keep arriving within a `gap`, capped at `timespan`), set with `rsigma.window` and `rsigma.gap`:

```yaml
title: Slow credential stuffing
correlation:
    type: event_count
    rules:
        - failed_login
    group-by:
        - SourceIp
    timespan: 6h
    condition:
        gte: 50
rsigma.window: session
rsigma.gap: 10m
```

Window modes are an RSigma extension. A [proposal to add them to the Sigma specification](https://github.com/SigmaHQ/sigma-specification/issues/214) was declined because the specification deliberately leaves the windowing strategy to each backend, so rules that use them are not portable to other Sigma tools. [Streaming Detection](streaming-detection.md#window-modes) describes each mode's semantics and out-of-order handling. For conversion, the PostgreSQL backend renders each mode and also lets you pick the strategy per conversion with `-O correlation_method=`, following pySigma's model (see [Rule Conversion](rule-conversion.md#correlation-window-modes)).

## What a correlation emits

When a correlation fires, it emits one result for the group:

```json
{
  "rule_title": "Brute force against one account",
  "rule_id": "...",
  "level": "high",
  "tags": [],
  "correlation_type": "event_count",
  "group_key": [["User", "admin"]],
  "aggregated_value": 5.0,
  "timespan_secs": 300
}
```

The detections a correlation references feed its state but are not emitted on their own by default, so a brute-force correlation does not also print each failed login. Set top-level `generate: true` on the correlation to emit them as well, or pass `--emit-detections` to emit every detection match for that run.

To see which events made a correlation fire, set `rsigma.correlation_event_mode` on the rule (or `--correlation-event-mode` for every correlation) to `full` for the event bodies or `refs` for timestamps and IDs only. `rsigma.max_correlation_events` (default 10) caps how many are kept per window, evicting the oldest first. [Evaluating Rules](evaluating-rules.md#correlation-in-eval-mode) shows both modes, and [Custom Attributes](../reference/custom-attributes.md) lists every per-rule key.

## Chaining correlations

A correlation can reference other correlations in `rules`. This one fires when the brute-force correlation above fires twice for the same user within an hour:

```yaml
title: Repeated brute force bursts
correlation:
    type: event_count
    rules:
        - brute_burst
    group-by:
        - User
    timespan: 1h
    condition:
        gte: 2
```

Here `brute_burst` is the `name` of the first correlation. Only the top of a chain produces output; the correlations below it update its state silently unless a referencing correlation has `generate: true` or `--emit-detections` is on. A parent's `group-by` fields must all be in its child's `group-by`, because a child passes on only its own group key. Chains can be up to ten levels deep, and cycles are rejected when the rules load. A parent in `full` or `refs` event mode carries the events its children kept when they fired.

## After a correlation fires

By default a correlation keeps its window after firing, so the next qualifying match fires again. Two settings change that:

- **Suppression** (`--suppress 5m`, or `rsigma.suppress: 5m` on the rule) drops repeat alerts for the same correlation and group key within the given duration.
- **Reset** (`--action reset`, or `rsigma.action: reset` on the rule) clears the group's window when the correlation fires, so it has to build up from zero again. The default is `alert`.

The flags apply to every correlation; a value on the rule overrides the flag for that rule.

```yaml
title: Brute force against one account
correlation:
    type: event_count
    rules:
        - failed_login
    group-by:
        - User
    timespan: 5m
    condition:
        gte: 5
rsigma.suppress: 30m
rsigma.action: reset
```

## State and memory

Correlation state is a window per correlation and group key. In `engine eval` it lives in memory for the length of the run. The daemon keeps it across restarts when you pass `--state-db`, which snapshots state to SQLite periodically and on shutdown (see [State persistence](streaming-detection.md#state-persistence)).

High-cardinality group keys and long windows are what drive memory. `--max-state-entries` (default 100,000) caps the total number of groups across all correlations and evicts the stalest when reached, and `--max-group-entries` or `rsigma.max_group_entries` caps how much a single group retains. [Performance Tuning](performance-tuning.md#memory-pressure-and-correlation-state) covers sizing.

When several daemons share a NATS consumer group, each replica keeps its own state, so the events of one group key must reach the same replica to correlate. See [consumer groups](nats-streaming.md#consumer-groups).

## Testing and debugging correlations

- **Replay events.** Pipe a file through `rsigma engine eval -r rules/` to check that a correlation fires. Add `--dump-correlation-state` to print every group's current value, threshold, and window entries when the run ends, which answers "why didn't it fire?".
- **Exemplars.** Attach timestamped example events to the rule with `rsigma.exemplars` and run [`rule test`](../cli/rule/test.md); correlation exemplars use an `events` list with relative `offset`s. See [Custom Attributes](../reference/custom-attributes.md).
- **Backtests.** [`rule backtest`](../cli/rule/backtest.md) resets correlation state per corpus file, so keep the events of one incident in one file.
- **Linting.** [`rule lint`](linting-rules.md) checks correlation structure, such as a value type without `field`, a non-numeric threshold, or a session window without `gap`. The [lint rule reference](../reference/lint-rules.md#correlation-rules-18) lists them all.
- **Drafting.** [`rule draft --groups`](rule-drafting.md#drafting-correlations) turns example incidents into the per-step detections plus a `temporal` or `temporal_ordered` correlation, inferring the group-by, order, and window, with an exemplar ready for `rule test`.

[Troubleshooting](../getting-started/troubleshooting.md#a-correlation-never-fires) collects the common causes of a correlation that never fires.

## See also

- [Core Concepts](../getting-started/concepts.md) for how correlations relate to detection and filter rules.
- [Evaluating Rules](evaluating-rules.md#correlation-in-eval-mode) and [Streaming Detection](streaming-detection.md) for running correlations.
- [Rule Conversion](rule-conversion.md#correlation-window-modes), the [PostgreSQL backend](../reference/backends/postgres.md#correlation-rules), and the [Fibratus backend](../reference/backends/fibratus.md#correlation-rules) for converting them.
- [`rsigma-eval`](../library/eval.md#correlation) for the `CorrelationEngine` library API.
