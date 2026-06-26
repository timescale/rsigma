# Configuration

`rsigma engine daemon`, `rsigma engine eval`, `rsigma rule backtest`, `rsigma rule coverage`, `rsigma rule scorecard`, and `rsigma rule visibility` can be driven by a YAML config file in addition to CLI flags and environment variables. This page describes the schema, the discovery chain, and the precedence model that decides which value wins when more than one layer sets the same key.

The same machinery is exposed through the [`rsigma config` group](../cli/config/init.md) for scaffolding, validation, introspection, and reload.

## Precedence

From highest to lowest:

1. **CLI flags** on the command line (e.g. `--rules /tmp/r`).
2. **Environment variables**: uniform `RSIGMA_<SECTION>__<KEY>` (see [Environment layer](#environment-layer)) plus the legacy clap-bound names listed in [Environment Variables](environment-variables.md).
3. **Project config**: `./rsigma.yaml` (or `./rsigma.yml`) in the current directory, then the nearest `.rsigmarc` found by walking up from the current directory.
4. **User config**: `$XDG_CONFIG_HOME/rsigma/config.yaml` (defaulting to `~/.config/rsigma/config.yaml`).
5. **System config**: `/etc/rsigma/config.yaml`.
6. **Compiled defaults** baked into the binary.

Higher layers override lower ones **per leaf**, not whole sections; a project `.rsigmarc` that only sets `eval.rules` does not erase the rest of the user config. This matches the [clig.dev guidance](https://clig.dev/#configuration) and is what most modern CLIs implement.

Use [`rsigma config show`](../cli/config/show.md) to see the resolved value for every key with the layer that supplied it.

## Discovery

All layers that exist are loaded and merged. There is no first-match-wins fallback: a file at `/etc/rsigma/config.yaml` is always loaded if it exists, even when a project `rsigma.yaml` is also present.

Passing `--config <PATH>` replaces the discovery chain entirely: only that file is loaded (and a bad path is a hard error, so misspellings surface immediately).

The `~/.config/rsigma` location is computed by honouring `XDG_CONFIG_HOME` explicitly rather than `dirs::config_dir()`, so on macOS the path stays under `~/.config/rsigma` instead of `~/Library/Application Support/`. The `rsigma install` workflow uses the same layout.

## Format

A minimal example, with every supported top-level section:

```yaml
# yaml-language-server: $schema=https://timescale.github.io/rsigma/rsigma.schema.json
version: 1

global:
  log_format: text         # text | json (maps to --log-format)
  output_format: json      # json | ndjson | table | csv | tsv (maps to --output-format)
  color: auto              # auto | always | never (maps to --color)

daemon:
  rules: /etc/rsigma/rules
  pipelines: [ecs_windows]
  sources: [/etc/rsigma/sources]
  # alert_pipeline: /etc/rsigma/alert-pipeline.yml   # dedup (see the Alert Pipeline guide)
  api:
    addr: "0.0.0.0:9090"
  input:
    source: stdin
    format: auto
    buffer_size: 10000
  output:
    sinks: [stdout]
    drain_timeout: 5
    # webhooks: [/etc/rsigma/webhooks/]   # template-driven HTTP sinks
  correlation:
    action: alert
    event_mode: none
    max_events: 10
    max_state_entries: 100000   # hard cap across all correlations and groups
    # max_group_entries: 10000  # per-group window-state cap; unset = unbounded
  state:
    save_interval: 30
  engine:
    bloom_prefilter: false
    match_detail: off
    observe_fields: false
    egress_policy: default
  tap:
    enabled: false          # opt-in: enable GET /api/v1/tap (or pass --enable-tap)
    buffer_events: 8192     # per-session buffer; a full buffer drops events (counted)
    max_sessions: 2         # concurrent capture sessions (a session over the cap gets 409)
    max_duration: 5m        # largest accepted ?duration (a longer one gets 400)
  tail:
    enabled: false          # opt-in: enable GET /api/v1/detections/stream (or --enable-tail)
    buffer_events: 8192     # per-session buffer; a full buffer drops detections (counted)
    max_sessions: 2         # concurrent tail sessions (a session over the cap gets 409)
  schema:
    observe: false          # opt-in: count events per recognized schema (or --observe-schemas)
    routing: false          # opt-in: route each event to its schema's pipeline-set (or --schema-routing)
    # config: /etc/rsigma/schema.yml   # user schema signatures + routing bindings (--schema-config)
    on_unknown: warn        # warn | drop | passthrough | error, for events matching no schema
  logsource_routing:
    enabled: false          # opt-in: conflict-based logsource pruning (or --logsource-routing)
    # field_map:            # event field names per dimension (default product/service/category)
    #   product: product
    # event_logsource:      # static logsource when the field is absent (--event-logsource)
    #   product: windows
    strict: false           # reserved for a future strict subset-routing mode

eval:
  rules: ./rules
  pipelines: [sysmon]
  input_format: auto
  fail_on_detection: false
  schema:
    routing: false          # opt-in: route each event to its schema's pipeline-set (or --schema-routing)
    # config: ./schema.yml
    on_unknown: warn
  logsource_routing:
    enabled: false          # opt-in: conflict-based logsource pruning (or --logsource-routing)
    # field_map:
    #   product: product
    # event_logsource:
    #   product: windows
    strict: false

backtest:
  rules: ./rules
  corpus: [./ci/corpus]
  expectations: ./ci/expectations.yml
  # unexpected: warn   # fail | warn | ignore; unset lets the expectations-file default apply
  input_format: auto

coverage:
  # rules: [./rules]
  # atomics: https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/Indexes/index.yaml
  # baseline: https://raw.githubusercontent.com/SigmaHQ/sigma/master/other/sigma_attack_nav_coverage.json
  # targets: ./threat-model-techniques.txt
  fail_on_gaps: false

scorecard:
  # backtest: ./backtest.json
  # coverage: ./coverage.json
  # metrics: http://localhost:9090/metrics
  # triage: ./triage.json
  fail_on: none
  min_precision: 0.8
  tune_max_precision: 0.5
  retire_max_precision: 0.1
  min_volume: 1
  stale_window: 30
  max_fp_ratio: 0.5

visibility:
  # mapping: ./mapping.json
  fail_on_blind_spots: false
```

Run [`rsigma config init`](../cli/config/init.md) to scaffold a full, commented version. The full machine-readable schema is emitted by [`rsigma config schema`](../cli/config/schema.md).

### Sections

| Section | Used by | Notes |
|---------|---------|-------|
| `global` | every subcommand | `global.log_format`, `global.output_format`, and `global.color`. See [Output Formats](output.md) for the format/color semantics. |
| `daemon` | `engine daemon` | Mirrors every non-secret daemon flag. |
| `daemon.api.tls` | `engine daemon` | Inert unless the binary is built with the `daemon-tls` feature; otherwise `config validate` warns. |
| `daemon.nats` | `engine daemon` | Non-secret NATS knobs (e.g. `consumer_group`). Secrets stay env-only. Inert unless built with `daemon-nats`. |
| `daemon.tap` | `engine daemon` | Live event-tap limits (`enabled`, `buffer_events`, `max_sessions`, `max_duration`). Disabled by default; enable with `enabled: true` or `--enable-tap`. The rest are config-file-only. See [HTTP API: Live event tap](http-api.md#live-event-tap). |
| `daemon.tail` | `engine daemon` | Live detection-tail limits (`enabled`, `buffer_events`, `max_sessions`). Disabled by default; enable with `enabled: true` or `--enable-tail`. The rest are config-file-only. See [HTTP API: Live detection tail](http-api.md#live-detection-tail). |
| `daemon.engine.cross_rule_ac` | `engine daemon` | Inert unless built with `daachorse-index`. |
| `daemon.schema` | `engine daemon` | Schema classification and routing (`observe`, `routing`, `config`, `on_unknown`). All opt-in. See [Schema Routing](../guide/schema-routing.md). |
| `daemon.logsource_routing` | `engine daemon` | Conflict-based logsource pruning (`enabled`, `field_map`, `event_logsource`, reserved `strict`). Opt-in. See [Logsource-Aware Evaluation](../guide/logsource-routing.md). |
| `eval` | `engine eval` | Mirrors the eval flag surface. |
| `eval.schema` | `engine eval` | Schema routing for one-shot eval (`routing`, `config`, `on_unknown`). `observe` has no effect here. |
| `eval.logsource_routing` | `engine eval` | Conflict-based logsource pruning for one-shot eval (`enabled`, `field_map`, `event_logsource`, reserved `strict`). |
| `backtest` | `rule backtest` | `rules`, `corpus`, `expectations`, `unexpected`, `pipelines`, and the syslog input knobs. `unexpected` has no compiled default so the expectations-file default can apply. |
| `coverage` | `rule coverage` | `rules`, `atomics`, `baseline`, `targets`, `fail_on_gaps`. |
| `scorecard` | `rule scorecard` | The two required reports (`backtest`, `coverage`), the verdict thresholds (`min_precision`, `tune_max_precision`, `retire_max_precision`, `min_volume`, `stale_window`, `max_fp_ratio`), the optional inputs (`metrics`, `metrics_window`, `triage`), `fail_on`, and `report`. |
| `visibility` | `rule visibility` | `mapping` (logsource/field to ATT&CK data-source table path or URL; unset uses the bundled default) and `fail_on_blind_spots`. `rules` and `observed` are intentionally absent (they are invocation-specific CLI arguments). |
| `mcp` | `mcp serve` | `mcp.http_addr` (the `--http` bind address; unset means stdio), `mcp.lint_config`, and `mcp.rules_dir`. The auth token is secret and stays flag/env-only. Inert unless built with the `mcp` feature. |

### Secrets policy

The schema deliberately does **not** carry any secret-bearing daemon settings:

- NATS auth (`creds`, `token`, `user`, `password`, `nkey`)
- TLS key password

Supply these via environment variables (or `--flag` for ad-hoc use). Putting them in a checked-in YAML file would silently widen exposure, so the loader has no way to accept them.

## Environment layer

Two parallel schemes are honoured:

1. **Uniform `RSIGMA_<SECTION>__<KEY>` (recommended).** Nested keys use the `__` separator; single underscores stay inside a key. Values are parsed as YAML scalars so types coerce naturally (ints, bools, lists). Examples:

    | Env var | Equivalent config |
    |---------|-------------------|
    | `RSIGMA_DAEMON__API__ADDR=127.0.0.1:9090` | `daemon.api.addr` |
    | `RSIGMA_DAEMON__INPUT__BUFFER_SIZE=20000` | `daemon.input.buffer_size` |
    | `RSIGMA_GLOBAL__LOG_FORMAT=json` | `global.log_format` |
    | `RSIGMA_MCP__HTTP_ADDR=127.0.0.1:9100` | `mcp.http_addr` |

2. **Legacy clap-bound names** with a single underscore (`NATS_CREDS`, `RSIGMA_CONSUMER_GROUP`, `RSIGMA_TLS_KEY_PASSWORD`). These continue to work at the flag layer and are listed in [Environment Variables](environment-variables.md). Secrets are *only* readable this way.

The uniform scheme is detected by the `__` separator, so it never collides with the legacy single-underscore names.

## `--dry-run` and `config show`

[`config show`](../cli/config/show.md) folds `default + file + env` and reports the winning layer for each leaf. To preview what a real command will use, including its flag layer, the daemon, eval, backtest, coverage, scorecard, and visibility commands support `--dry-run`:

```bash
rsigma engine daemon --dry-run
# prints the effective daemon section as YAML, then exits 0
```

In `config show` output the layer is one of `default`, `file`, or `env`. In a command's `--dry-run` view, flag-supplied values appear on top of all three.

## Format versioning

Every config carries `version: 1` at the top level. The loader currently accepts any value (the field is informational), but future migrations will gate on it; treat it as required when authoring new files.

## See also

- [`rsigma config init`](../cli/config/init.md) to scaffold a template.
- [`rsigma config validate`](../cli/config/validate.md) for layered loading with diagnostics.
- [Environment Variables](environment-variables.md) for the legacy single-underscore names and the precedence with CLI flags.
- [Exit codes](exit-codes.md) for the `CONFIG_ERROR` (3) contract used by every config command.
