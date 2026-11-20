---
description: "Curate vendored Sigma rules into named rulesets with selectors, overlays, dependency policies, and a reproducible build output."
---

# Rulesets

{{ added "unreleased" }}

A ruleset is a named curation of Sigma rules declared in `rsigma.yaml`. It selects documents from one or more source trees, resolves correlation dependencies, applies metadata overlays, and can be materialized into a directory with a lockfile. Every rule-loading command that takes `--ruleset` resolves the same way, so the CLI, MCP tools, and the build output agree on what a ruleset contains.

Rulesets exist because vendored rules are rarely ready to load as-is. A vendor tree carries rules you do not run, metadata you want to override, correlations that reference rules outside the selected set, and missing exemplars or ADS prose. Editing the vendor files makes upgrades painful; a ruleset keeps the curation in your own configuration.

## Configuration

Rulesets live under a `rulesets:` map keyed by name in `rsigma.yaml`. Ruleset names must match `^[a-z][a-z0-9_-]{0,63}$`. Relative paths resolve against the working directory, like every other path in the configuration.

```yaml
rulesets:
  linux_edge:
    description: Linux edge hosts
    sources:
      - ./rules/local
      - ./vendor/sigma/rules/linux
    include:
      - tags: ["attack.t1059*", "attack.t1071*"]
      - logsource: { product: [linux], category: [process_creation] }
        level: [high, critical]
    exclude:
      - status: [deprecated, unsupported]
      - id: [9b2d3e4f-5678-90ab-cdef-1234567890ab]
      - path: ["**/experimental/**"]
    dependencies: include
    overlays:
      - id: 128f744d-f0e5-4a41-9d1f-48e8f97fe204
        set:
          level: critical
          custom_attributes:
            rsigma.suppress: 30m
        append:
          tags: [org.tier1]
      - dir: ./overlays/linux_edge
    stale_overlays: error
    pipelines: [./pipelines/localobserve.yml]
    output: ./build/linux_edge
```

A ruleset is a file-only configuration section. Environment variables such as `RSIGMA_EVAL__RULESET` work, but `RSIGMA_RULESETS__...` is ignored with a warning.

## Sources

`sources` is a non-empty list of files or directories, processed in declaration order. A directory is walked recursively with sorted paths, hidden directories skipped, symlink loops guarded, and only `.yml` and `.yaml` files read. A file is read as is, whatever its extension. A missing source is a configuration error. Sources do not accept globs; use the `path` selector to sub-select files.

Each file is parsed separately, so every document keeps its origin. The resolved collection is deterministic: source order, then sorted file path, then document order within each kind. Two kept documents with the same id (case-insensitive), or the same name, are a configuration error. A vendored rule plus a local fork is resolved by excluding one of them with `path` or `id`.

## Selection

`include` and `exclude` are lists of selectors. A document matches a list when any selector in it matches. A selector matches when every key it sets matches. A key matches when any of its values matches.

| Key | Match |
|-----|-------|
| `id` | Exact, case-insensitive. |
| `name` | Exact, case-sensitive. |
| `title`, `tags` | `globset` globs, case-insensitive. `tags` matches when any rule tag matches. |
| `level` | Exact enum name: `informational`, `low`, `medium`, `high`, or `critical`. |
| `status` | Exact enum name: `stable`, `test`, `experimental`, `deprecated`, or `unsupported`. |
| `kind` | `detection`, `correlation`, or `filter`. |
| `logsource.product`, `logsource.category`, `logsource.service` | Exact, case-insensitive, against the rule's own logsource. A correlation matches when any detection rule it references matches the key. |
| `path` | Glob against the origin path relative to its source root. `*` stays inside one directory; `**` crosses directories. |

An empty `include` admits every detection and correlation candidate. `exclude` always wins. Filters are not selected by `include`: a filter is kept when it is not excluded and its target resolves to a kept detection rule, or when it targets any rule. A filter that targets an excluded or unselected rule is recorded as orphaned or excluded.

Invalid globs and unknown enum values are configuration errors. Unknown keys inside a ruleset are also errors, so a typo cannot silently widen the set.

## Dependencies

`dependencies` controls what happens when a kept correlation references a rule that is not kept. The default is `error`.

- `error` fails resolution and lists each correlation, each missing reference, and why it is missing: not in any source, excluded by a selector, or not matched by `include`.
- `include` pulls a referenced detection rule or correlation back in when `include` did not match it. A rule matched by `exclude` stays out, and that is an error. A reference that exists in no source is an error.
- `drop` drops the correlation and warns. Correlations that reference a dropped correlation drop in turn.

```yaml
rulesets:
  linux_edge:
    sources: [./vendor/sigma/rules/linux]
    include:
      - tags: ["attack.t1059*"]
    dependencies: drop
```

With `dependencies: drop`, a correlation whose referenced rule was not selected is dropped rather than failing the load. The resolved collection is still safe to hand to the correlation engine, which rejects unknown references.

## Overlays

Overlays change metadata on kept detection rules and correlations. They never change `title`, `id`, `name`, `logsource`, `detection`, correlation fields, or `related`, because changing those is a fork.

An overlay entry is exactly one of:

- `{ id, set?, append? }`, which needs at least one of `set` or `append`.
- `{ file: <path> }`, a single overlay file.
- `{ dir: <path> }`, every `.yml` or `.yaml` under the directory, in sorted order.

An overlay file is a YAML sequence of `{ id, set?, append? }` entries. Empty files contribute nothing. Unknown keys are errors everywhere.

`set` accepts `level`, `status`, `description`, `author`, `tags`, `references`, `falsepositives`, `fields`, and `custom_attributes`. Scalars and lists replace the existing value. `custom_attributes` merges per key; each listed key replaces that attribute, and a `null` value removes it. `append` accepts `tags`, `references`, `falsepositives`, `fields`, and `custom_attributes`. Lists are concatenated; `tags` skips duplicates. A `custom_attributes` value must be a sequence, and an absent attribute is created. `custom_attributes` cannot name a standard Sigma key such as `level` or `tags`, or an engine key such as `rsigma.window`, and an empty `set` or `append` is an error.

Overlays apply after selection and dependency closure, in declaration order. A `file` or `dir` entry expands at its own position. Within one entry, `set` applies before `append`. `stale_overlays` defaults to `error`; an overlay whose id matches no kept rule fails unless you set `stale_overlays: warn`.

```yaml
# overlays/linux_edge/exemplars.yml
- id: 128f744d-f0e5-4a41-9d1f-48e8f97fe204
  append:
    custom_attributes:
      rsigma.exemplars:
        - name: org whoami variant
          expect: match
          event: { CommandLine: whoami /priv }
```

Touched exemplars are validated with the rule's kind, and touched `rsigma.ads.*` keys must parse as ADS content. Other attributes are left to the engine. A processing pipeline still wins at compile time: a pipeline `set_custom_attribute` transformation overrides an overlay value.

## Pipelines

`pipelines` is a list of builtin names or YAML file paths. Commands that accept `-p` use an explicit `-p` first, then the ruleset's pipelines, then the section's configured pipelines. `pipeline diff`, `backend convert`, and `hunt run` never use a ruleset's pipelines: the pipelines are the subject of those commands or belong to the target backend.

## Loading a ruleset

Every command that loads a collection accepts `--ruleset <NAME>`, with `--config <PATH>` where a configuration file can override discovery. The flag conflicts with the command's rule-path input.

```bash
rsigma engine eval --ruleset linux_edge --event @event.json
rsigma rule test --ruleset linux_edge --fail-on-missing
rsigma rule doc --ruleset linux_edge
rsigma backend convert --ruleset linux_edge -t postgres
rsigma hunt run --ruleset linux_edge -t postgres --since 2026-07-01T00:00:00Z --until 2026-07-02T00:00:00Z --emit sql
```

The commands that take `--ruleset` are `engine eval`, `engine explain`, `rule validate`, `rule fields`, `rule tune`, `rule doc`, `rule test`, `rule backtest`, `rule coverage`, `rule visibility`, `rule hygiene`, `backend convert`, `pipeline diff`, and `hunt run`. `rule doc --scaffold` conflicts with `--ruleset` because scaffolding targets one rule file.

`rule lint` and `rule fmt` do not take `--ruleset`. They operate on raw files, with source spans and `--fix`, which have no meaning on an in-memory collection. Lint the sources, or build the ruleset and lint the output.

## Building a ruleset

`ruleset build` materializes the resolved collection into canonical YAML files and a lockfile.

```bash
rsigma ruleset build linux_edge -o build/linux_edge
```

The output directory contains `rules/<stem>.yml`, `correlations/<stem>.yml`, `filters/<stem>.yml`, and `ruleset.lock.json`. `<stem>` is the lowercased id when it is filesystem-safe, otherwise a content hash. Writes are atomic and minimal, and stale `.yml` files under the three subdirectories are removed. The lockfile records the spec digest, source digests, overlay files, pipelines, and every emitted document with its hash and applied overlays. It has no timestamps, so an unchanged rebuild is byte-identical.

The build refuses to write into a non-empty directory that has no lockfile unless you pass `--force`. It never deletes anything outside the three subdirectories. A source parse error fails the build with exit 2; resolution errors exit 3.

Use `--check` to verify committed output without writing:

```bash
rsigma ruleset build linux_edge -o build/linux_edge --check
```

It exits 1 when the directory differs from what a build would write.

`ruleset diff` compares a resolved ruleset with a lockfile and reports added, removed, and changed documents, plus source, overlay, and spec changes. Use `--fail-on-change` as a CI gate.

```bash
rsigma ruleset diff linux_edge --lock build/linux_edge/ruleset.lock.json --fail-on-change
```

The build output is a normal rule directory. Load it with `engine eval --rules build/linux_edge` or point `engine daemon --rules` at it. Because the build has already resolved selectors and overlays, the daemon does not need the ruleset configuration at runtime.

## MCP

The MCP tools `validate_rules`, `evaluate_events`, `list_fields`, `convert_rules`, and `test_exemplars` accept a `ruleset` input alongside `yaml` and `path`. Exactly one of the three must be provided. The server reads the rulesets from its `rsigma.yaml` and resolves them against `--rules-dir` when one is set. Every source, overlay file or directory, and pipeline file must stay inside that root; an escape fails the call with an invalid-params error. Builtin pipeline names are allowed.

`convert_rules` ignores a ruleset's pipelines because the conversion target supplies its own pipeline semantics.

## Several rulesets side by side

{{ added "unreleased" }}

`engine eval`, MCP `evaluate_events`, and `engine daemon` can evaluate several rulesets over the same events. Each ruleset keeps its own compiled engines, pipelines, and correlation state. Results carry a `ruleset` field naming the ruleset that produced them, and the results for one event are concatenated in declaration order.

Fan-out is useful when the same event stream should be tested against several curations, for example a Windows subset and a cloud subset, or a stable set and an experimental set. Prefer one ruleset when the curations share correlation state: a rule that appears in two rulesets is evaluated and counted independently in each.

`when` binds a ruleset to schema names. A bound ruleset receives only events whose `SchemaClassifier::classify` result names one of its schemas. Events with no classified schema reach only rulesets without `when`. The classifier comes from `--schema-config` when supplied, otherwise the builtin signatures. Classification runs once per event and only when at least one ruleset has `when`.

A CLI `--ruleset` list replaces the configured list wholesale, and CLI entries carry no `when`. Use the configuration list for schema bindings. `--schema-routing` is allowed with exactly one ruleset and only when that ruleset declares no pipelines, because the routing bindings own pipelines. `when` is not allowed with schema routing.

In the daemon, the ruleset list and definitions are read once at startup. Changing them in `rsigma.yaml` needs a restart. Rule, overlay, and pipeline files under the rulesets hot-reload. The daemon exposes per-ruleset rule counts and skipped events in `/api/v1/status`, `/api/v1/rules`, and `rsigma engine status`. `rsigma_ruleset_rules_loaded`, `rsigma_ruleset_matches_total`, and `rsigma_ruleset_events_skipped_total` carry the same numbers to Prometheus. Rule metadata lookups that resolve a rule overlaid differently in two rulesets report an ambiguous result.

`engine eval --dump-correlation-state` prints a map keyed by ruleset name, even when only one ruleset is selected. `--stats` adds one line per ruleset with detection matches, correlation matches, and, for bound rulesets, skipped events.

### Tenant bindings

{{ added "unreleased" }}

A `daemon.rulesets` entry can list `tenants` next to `when`. A bound ruleset receives only events whose tenant is listed; an unbound ruleset receives every tenant's events, with its state still keyed per tenant. `when` and `tenants` combine with AND. A tenant rejection counts in the same `skipped` counters as a `when` rejection, and `ruleset_stats` reports the binding.

```yaml
rulesets:
  shared_baseline:
    sources: [/etc/rsigma/rules/shared]
  tenant_a_custom:
    sources: [/etc/rsigma/rules/tenant-a]
daemon:
  rulesets:
    - shared_baseline
    - name: tenant_a_custom
      tenants: [tenant-a]
```

A CLI `--ruleset` list replaces the configured list and carries no `tenants`, like `when`. `eval.rulesets` rejects `tenants`. A ruleset binding must name a tenant that some token, `daemon.input.tenant`, or `daemon.input.nats_tenants` entry can produce; a typo would otherwise silently disable the ruleset. See [Multi-tenancy](multi-tenancy.md).

## Converting a ruleset

{{ added "unreleased" }}

`convert:` groups name a ruleset, a target, and an output path, and `rsigma backend build` writes the queries plus a manifest for each group. Pipelines come only from the conversion group, never from the ruleset. See [Rule Conversion](rule-conversion.md#convert-named-rulesets).

## See also

- [Configuration reference](../reference/configuration.md)
- [`rsigma ruleset list`](../cli/ruleset/list.md), [`show`](../cli/ruleset/show.md), [`build`](../cli/ruleset/build.md), and [`diff`](../cli/ruleset/diff.md)
- [`rsigma rule test`](../cli/rule/test.md)
- [Custom attributes](../reference/custom-attributes.md)
