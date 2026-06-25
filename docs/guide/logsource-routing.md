# Logsource-Aware Evaluation

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
2. **Static override.** `--event-logsource product=windows,...` sets a fixed logsource for a run dedicated to one source. The most reliable option in practice, since the shipper already knows what it is collecting.
3. **EVTX-only format default.** `engine eval -e @file.evtx` implies `product: windows` when no explicit or static product is configured, because EVTX is a Windows-only format.
4. **Otherwise unset**, so pruning fails open and every rule is evaluated.

### The format guardrail

RSigma never infers `product` from an ambiguous wire format. Because pruning is conflict-based, a wrong product guess does not merely fail to help, it drops correct rules: a Windows-over-syslog stream mistagged `linux` would prune away every Windows rule. Syslog is a transport, not a platform; CEF carries its product in the message content, not the wire format; and JSON, logfmt, and OTLP are pure containers. So only platform-locked formats (today, EVTX) set a format-derived default; everything else stays unset. `category` is never derived from a format.

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

## Scaling and the index

Pruning is backed by a product-partitioned rule index. The rules that the value index cannot narrow away (the always-evaluated set) are bucketed by `product`, so an event with product `P` iterates only the product-less bucket and the `P` bucket, never a conflicting bucket. `service` and `category` remain a cheap residual filter on the returned candidates. Evaluation of a product-tagged event against a ruleset split across products drops roughly in proportion to the conflicting fraction.

This is a scaling lever for large mixed-product rulesets, not a fix for low throughput at small rule counts.

## Observability

The daemon exposes two counters (see [metrics](../reference/metrics.md)):

- `rsigma_rules_pruned_by_logsource_total`: always-evaluated rules skipped by product conflict.
- `rsigma_events_without_logsource_total`: events with no extractable logsource, evaluated against every rule (fail-open visibility).

## Guarantees

- Off by default; zero behavior change when disabled.
- Fail-open: an event with no extractable logsource is evaluated against every rule.
- Conflict-based: a mis-tag never silently drops a rule on a dimension the event did not assert, and an ambiguous wire format never sets a product.
- Correlation inherits the pruning, since it evaluates through the same detection engine.
