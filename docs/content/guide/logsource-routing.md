---
description: "Speed up Sigma evaluation on mixed-platform streams with RSigma logsource-aware routing, which skips rules whose product, service, or category conflicts."
---

# Logsource-Aware Evaluation

{{ added "0.18.0" }}

When one stream carries events from many platforms (Windows servers and Linux hosts on the same collector, say), most rules in a large ruleset cannot apply to any given event: a `product: windows` rule never matches a Linux event, and vice versa. Logsource-aware evaluation lets an event tagged with its logsource skip the rules that definitely conflict with it, so a mixed-product stream only pays for the rules that can match.

This is the lighter, single-engine sibling of [schema routing](schema-routing.md). Schema routing recognizes an event's schema and applies the matching field-mapping pipeline; logsource routing keeps one ruleset in its native field names and prunes by the rule's declared `product`/`service`/`category`. The two compose: with both enabled, each routed per-schema engine also prunes its own candidates by logsource.

## Conflict-based, not subset

Detection matchers never test the logsource (it is rule metadata), so pruning on it is only safe when there is a genuine conflict. RSigma uses conflict-based semantics: a rule is skipped only when a dimension (`product`, `service`, or `category`) is set on **both** the rule and the event and the two values differ (case-insensitive). A dimension unset on either side is a wildcard.

So a Windows-tagged event with no category:

- skips `product: linux` rules (product set on both sides, and they differ), and
- still evaluates `product: windows, category: process_creation` rules (the event never asserted a category, so there is no conflict), and
- still evaluates rules with no logsource at all.

This is deliberately different from subset/routing semantics, which would require every dimension the rule names to be present and equal in the event. Subset semantics would drop the bulk of Windows rules for a `product: windows`-only event, silently losing detections. Conflict-based pruning never drops a rule on a dimension the event did not assert.

## Where the event logsource comes from

The extractor resolves each dimension independently, taking the first value it finds:

1. **Event fields.** The event carries `product`/`service`/`category` (or the field names you configure with `--logsource-field-map`). The most accurate per-event signal.
2. **Static override.** `--event-logsource product=windows,...` fills a dimension only when that field is absent on the event. Useful for a run dedicated to one source, since the shipper already knows what it is collecting.
3. **EVTX-only format default.** `engine eval -e @file.evtx` implies `product: windows` when no event field or static product is set, because EVTX is a Windows-only format. The daemon never applies a format default.
4. **Schema-derived (with schema routing).** When [schema routing](schema-routing.md#schema-derived-logsource) is also enabled, a recognized schema fills any dimension still unset (for example `sysmon` implies `product: windows, service: sysmon`, including custom dimensions for off-taxonomy schemas).
5. **Otherwise unset**, so pruning fails open and every rule is evaluated.

### The format guardrail

RSigma never infers `product` from an ambiguous wire format. Because pruning is conflict-based, a wrong product guess drops correct rules: a Windows-over-syslog stream mistagged `linux` would prune away every Windows rule. Syslog is a transport, not a platform; CEF carries its product in the message content, not the wire format; and JSON, logfmt, and OTLP are pure containers. So only platform-locked formats (today, EVTX) set a format-derived default; everything else stays unset. `category` is never derived from a format.

## Usage

```bash
# Event fields carry the logsource (product/service/category by default).
rsigma engine eval -r rules/ --logsource-routing -e '{"CommandLine":"whoami","product":"windows"}'

# Remap the field names the dimensions are read from.
rsigma engine eval -r rules/ --logsource-routing --logsource-field-map product=os,service=svc -e @events.ndjson

# Static logsource for a single-source pipeline (no per-event field needed).
rsigma engine daemon -r rules/ --input http --logsource-routing --event-logsource product=windows

# EVTX implies product: windows automatically.
rsigma engine eval -r rules/ --logsource-routing -e @security.evtx
```

### Enabling from a config file

The flags map to a `logsource_routing` block in the [config file](../reference/configuration.md), under both `daemon` and `eval`. A flag always wins over the file.

```yaml
daemon:
  logsource_routing:
    enabled: true
    field_map:
      product: os
    event_logsource:
      product: windows

eval:
  logsource_routing:
    enabled: true
```

## Custom dimensions

Beyond the standard `product`/`service`/`category`, rules and events can carry custom logsource dimensions, and pruning conflicts on them the same way: a rule is skipped only when a custom key is set on both the rule and the event and the values differ. Configure extra dimensions with a `custom.<name>=...` entry in the field map or static override (bare non-standard keys remain an error, to catch typos):

```bash
# Read a custom `tenant` dimension from the event's `org` field.
rsigma engine eval -r rules/ --logsource-routing --logsource-field-map custom.tenant=org -e @events.ndjson

# Pin a static custom dimension when the event field is absent.
rsigma engine daemon -r rules/ --input http --logsource-routing --event-logsource product=windows,custom.tenant=acme
```

In a config file, custom dimensions live under a `custom:` map:

```yaml
eval:
  logsource_routing:
    enabled: true
    field_map:
      custom:
        tenant: org
    event_logsource:
      custom:
        region: eu
```

Custom dimensions follow the same precedence as the standard three: event field, then static default, then (with schema routing) schema-implied custom keys for still-unset dimensions.

## Scaling and the index

Pruning is backed by a product-partitioned rule index. The rules that the value index cannot narrow away (the always-evaluated set) are bucketed by `product`, so an event with product `P` iterates only the product-less bucket and the `P` bucket, never a conflicting bucket. `service` and `category` remain a cheap residual filter on the returned candidates. Evaluation of a product-tagged event against a ruleset split across products drops roughly in proportion to the conflicting fraction.

This is a scaling lever for large mixed-product rulesets, not a fix for low throughput at small rule counts.

## Observability

The daemon exposes these metrics (see [metrics](../reference/metrics.md)):

- `rsigma_rules_pruned_by_logsource_total`: rules skipped by product conflict, both those the index's product partitioning never offers as candidates and those the residual check drops during evaluation.
- `rsigma_events_without_logsource_total`: events with no extractable logsource, evaluated against every rule (fail-open visibility).
- `rsigma_schema_rules_eligible{schema}` and `rsigma_schema_rules_pruned{schema}`: per-schema eligible-versus-pruned rule counts, set when [schema routing](schema-routing.md) is also active. `engine eval` prints the same per-schema summary at the end of a run.

## Guarantees

- Off by default; zero behavior change when disabled.
- Fail-open: an event with no extractable logsource is evaluated against every rule.
- Conflict-based: a mis-tag never silently drops a rule on a dimension the event did not assert, and an ambiguous wire format never sets a product.
- Correlation inherits the pruning, since it evaluates through the same detection engine.

## See also

- [Schema Routing](schema-routing.md) for per-schema pipelines and schema-derived logsource fill.
- [CLI: `engine eval`](../cli/engine/eval.md) and [`engine daemon`](../cli/engine/daemon.md) for the logsource flags.
- [Configuration reference](../reference/configuration.md) for the `daemon.logsource_routing` and `eval.logsource_routing` keys.
- [Prometheus metrics](../reference/metrics.md) for the pruning counters and per-schema gauges.
