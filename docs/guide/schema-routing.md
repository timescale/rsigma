# Schema Routing

Real-world streams mix log schemas: one feed can carry ECS-normalized events, raw (rendered) Windows Event Log, flat Sysmon JSON, CEF, OCSF, and vendor-specific shapes, often all as JSON with only the field names differing. Schema routing recognizes each event's schema from its content and evaluates it against the field-mapping pipeline bound to that schema, so a single ruleset matches across all of them without pre-splitting the stream upstream.

It builds on [schema classification](../cli/engine/classify.md): the same signatures that `engine classify` reports drive the routing decision.

## How it works

1. Each event is classified by content (marker fields and values), not by wire format.
2. The classified schema is looked up in the routing bindings to pick a pipeline-set.
3. The event is evaluated against the detection engine built for that pipeline-set (one engine per distinct pipeline-set, built once).
4. Detections from every per-schema engine feed one shared correlation store.

Routing is opt-in (`--schema-routing`) and detection-side only: it routes to existing pipelines, it does not collect, transport, or normalize events. Collection and normalization stay with the log shipper.

## Configuration

Bindings live in the `routing:` section of the `--schema-config` YAML, alongside any user-defined `schemas:` signatures:

```yaml
# schema-config.yml
schemas:
  # Optional: user-defined signatures, merged over the built-ins.
  - name: my_vendor
    specificity: 70
    match:
      - field_present: vendor.product

routing:
  # What to do with events that match no schema: warn (default), drop,
  # passthrough, or error.
  on_unknown: warn
  # Pipelines for known-but-unbound schemas and the unknown fallback.
  # Empty means "rules with no pipeline".
  default_pipelines: []
  bindings:
    - schema: ecs
      pipelines: [ecs_windows]
    - schema: sysmon
      pipelines: [sysmon]
    - schema: my_vendor
      pipelines: [my_vendor_map.yml]
```

Pipelines are builtin names (`ecs_windows`, `sysmon`) or YAML file paths, the same as `-p`. Identical pipeline-sets are deduplicated, so two schemas bound to the same pipelines share one engine. Under the daemon, dynamic pipelines (those with `${source.*}` placeholders) bound to a schema are resolved at load time and on hot-reload, the same as the non-routing `-p` pipelines.

## Usage

```bash
# One-shot evaluation of a mixed-schema corpus.
cat mixed.ndjson | rsigma engine eval -r rules/ --schema-routing --schema-config schema-config.yml

# Streaming daemon.
rsigma engine daemon -r rules/ --input http --schema-routing --schema-config schema-config.yml
```

`--on-unknown <policy>` overrides the config's `on_unknown` for the run.

### Enabling from a config file

The flags map to a `schema:` block in the [config file](../reference/configuration.md), under both `daemon` and `eval`. A flag always wins over the file:

```yaml
daemon:
  schema:
    observe: true            # daemon only; counts events per schema
    routing: true
    config: /etc/rsigma/schema.yml
    on_unknown: warn

eval:
  schema:
    routing: true
    config: ./schema.yml
    on_unknown: drop
```

## Schema-derived logsource

When schema routing is combined with [logsource routing](logsource-routing.md), the schema rsigma recognizes supplies the event's logsource for [conflict-based pruning](logsource-routing.md#conflict-based-not-subset), even when the event carries no explicit `product`/`service`/`category` field. So an event recognized as `sysmon` implies `product: windows, service: sysmon`, and a Cisco or Linux rule is pruned instead of false-positive matching on a mapped field.

Built-in implied logsources cover the platform-locked schemas: `sysmon` (windows/sysmon), `windows_eventlog` (windows), and the two ECS platform specializations `ecs_windows` (windows) and `ecs_linux` (linux). The plain cross-platform schemas (`ecs`, `ocsf`, `cef`, `generic_json`) imply nothing, because they carry events from many platforms.

An ECS event that also carries a platform marker (`winlog.*`, `host.os.type`) classifies as `ecs_windows`/`ecs_linux` and gets the platform for pruning automatically. These specializations are aliases of `ecs` (see below), so an existing `ecs` binding still matches them, no config change needed. For a source ECS routes without a marker, point the logsource extractor at the event's own OS field instead (`--logsource-field-map product=host.os.type`).

### Schema aliases

An alias makes one schema route as another: an event classified as the alias is dispatched as though it were the canonical schema, so a single binding covers a family of related schemas. The built-in `ecs_windows` and `ecs_linux` alias to `ecs`. Declare your own under `routing.aliases`:

```yaml
routing:
  aliases:
    my_vendor_win: my_vendor
  bindings:
    - schema: my_vendor
      pipelines: [my_vendor_map.yml]
```

Aliasing affects routing only: the alias keeps its own classification label and implied logsource (so `ecs_windows` still contributes `product: windows`), but binds where its canonical binds. A direct binding for the alias itself always takes precedence over the alias.

Attach or override a schema's implied logsource per binding:

```yaml
routing:
  bindings:
    - schema: ecs_windows
      pipelines: [ecs_windows]
      logsource:
        product: windows
    - schema: my_vendor
      pipelines: [my_vendor_map.yml]
      logsource:
        product: linux
        custom:
          tenant: acme
```

Resolution per event is explicit event field, then the static `--event-logsource`, then the schema-derived logsource, then any format default, then unset (fail-open). This prunes only at product/service granularity; category-level pruning inside one product (for example `process_creation` versus `ps_script`) still needs the event to assert a category or a pipeline to derive it.

## Per-schema rule partitioning

By default every per-schema engine compiles the full ruleset (N copies for N pipeline-sets). `--schema-partition-rules` (or `schema.partition_rules: true`) is a gated, opt-in optimization that compiles each platform-locked per-schema engine with only the rules whose product can apply, cutting that memory cost.

It applies conservatively and only where it is safe:

- The default pipeline-set is never partitioned (unbound and unknown events route there and could be any product).
- A set is partitioned only when every schema that routes to it (direct bindings plus aliases) implies a product; a set reachable by a cross-platform schema such as `ecs` keeps the full ruleset. A set bound only to `sysmon`, `windows_eventlog`, or `ecs_windows`, for example, keeps only Windows and product-less rules.
- A set whose pipelines rewrite product via `change_logsource` keeps the full ruleset (the pre-pipeline product is not authoritative there).

Caveat, and why it is off by default: partitioning removes rules at compile time based on the schema's implied product, so an event that is classified as one platform but carries an explicit, contradicting `product` field would not see the removed rules (with the full ruleset, per-event conflict pruning would still keep them). Validate against your corpus before enabling it in production.

## Cross-schema correlation

Correlation works across schemas. Detections from each per-schema engine feed one shared correlation store, and the group-by extraction is schema-aware: a correlation grouped by `User` matches an ECS event's `user.name` and a Sigma-native event's `User` to the same entity, so the two correlate together. Window state, suppression, chaining, and snapshots are unchanged; only the group-key extraction becomes schema-aware.

## Unknown schemas

An event that matches no signature is "unknown". The `on_unknown` policy decides its fate: `warn` and `passthrough` evaluate it against the default pipeline-set (the difference is a logged warning), `drop` skips it, and `error` skips it and flags an error. Pair routing with [`--observe-schemas`](../cli/engine/daemon.md) (daemon) or [`engine classify`](../cli/engine/classify.md) to find sources whose schema is not yet recognized, then add a signature and a binding.

With `--observe-schemas`, the daemon's `GET /api/v1/schemas` endpoint reports a bounded, redacted sample of the field-key shapes of unknown events (`unknown_shapes`), so you can see exactly which key sets are unrecognized and author a signature for them without inspecting raw event values. The same endpoint reports a per-schema routing pruning summary (`routing_pruning`, eligible versus pruned rules) and an `ambiguous` count for events where two different-name signatures tied at the winning specificity. `engine classify` surfaces the same ambiguity per event; resolve it by giving one signature a distinguishing predicate or a higher `specificity`.

## Discovering signatures

Rather than reading the unknown shapes and hand-writing every signature, let RSigma propose them. [`engine discover-schemas`](../cli/engine/discover-schemas.md) mines a JSON/NDJSON corpus: it clusters the unrecognized events (the `unknown` and `generic_json` ones), picks the fields and low-cardinality values that discriminate each cluster, and emits ranked candidate signatures plus a paste-ready `schemas:` block.

```bash
cat events.ndjson | rsigma engine discover-schemas --output-format table
rsigma engine discover-schemas -e @events.ndjson --emit yaml >> schemas.yml
```

The workflow is a loop: `engine classify` shows you have unknowns, `discover-schemas` proposes signatures, and classifying again with the pasted config verifies them (`--dry-run` previews the before/after classification counts in one step). Proposals are always declarative signatures a human reviews and renames; nothing is applied automatically.

On a running daemon, `--discover-schemas` (which implies `--observe-schemas`) samples the shapes of unrecognized events live, and [`GET /api/v1/schemas/suggestions`](../cli/engine/discover-schemas.md) mines them into candidates. The daemon sample is keys-only, so its proposals use presence predicates; run the offline command over a corpus when you want `equals`/`in` value markers.
