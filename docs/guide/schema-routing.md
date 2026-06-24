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

## Cross-schema correlation

Correlation works across schemas. Detections from each per-schema engine feed one shared correlation store, and the group-by extraction is schema-aware: a correlation grouped by `User` matches an ECS event's `user.name` and a Sigma-native event's `User` to the same entity, so the two correlate together. Window state, suppression, chaining, and snapshots are unchanged; only the group-key extraction becomes schema-aware.

## Unknown schemas

An event that matches no signature is "unknown". The `on_unknown` policy decides its fate: `warn` and `passthrough` evaluate it against the default pipeline-set (the difference is a logged warning), `drop` skips it, and `error` skips it and flags an error. Pair routing with [`--observe-schemas`](../cli/engine/daemon.md) (daemon) or [`engine classify`](../cli/engine/classify.md) to find sources whose schema is not yet recognized, then add a signature and a binding.
