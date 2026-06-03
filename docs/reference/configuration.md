# Configuration

`rsigma engine daemon` and `rsigma engine eval` can be driven by a YAML config file in addition to CLI flags and environment variables. This page describes the schema, the discovery chain, and the precedence model that decides which value wins when more than one layer sets the same key.

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
  api:
    addr: "0.0.0.0:9090"
  input:
    source: stdin
    format: auto
    buffer_size: 10000
  output:
    sinks: [stdout]
    drain_timeout: 5
  correlation:
    action: alert
    event_mode: none
    max_events: 10
    tenant_field: tenant_id
    missing_tenant: reject
  state:
    save_interval: 30
  engine:
    bloom_prefilter: false
    observe_fields: false
  kafka:
    consumer_group: rsigma-prod
    security_protocol: SASL_SSL
    sasl_mechanism: SCRAM-SHA-256
    offset_reset: earliest

eval:
  rules: ./rules
  pipelines: [sysmon]
  input_format: auto
  fail_on_detection: false
```

Run [`rsigma config init`](../cli/config/init.md) to scaffold a full, commented version. The full machine-readable schema is emitted by [`rsigma config schema`](../cli/config/schema.md).

### Sections

| Section | Used by | Notes |
|---------|---------|-------|
| `global` | every subcommand | `global.log_format`, `global.output_format`, and `global.color`. See [Output Formats](output.md) for the format/color semantics. |
| `daemon` | `engine daemon` | Mirrors every non-secret daemon flag. |
| `daemon.api.tls` | `engine daemon` | Inert unless the binary is built with the `daemon-tls` feature; otherwise `config validate` warns. |
| `daemon.nats` | `engine daemon` | Non-secret NATS knobs (e.g. `consumer_group`). Secrets stay env-only. Inert unless built with `daemon-nats`. |
| `daemon.kafka` | `engine daemon` | Non-secret Kafka knobs (e.g. `consumer_group`, `security_protocol`, `offset_reset`, SSL cert paths). SASL credentials stay env-only. Inert unless built with `daemon-kafka`. |
| `daemon.engine.cross_rule_ac` | `engine daemon` | Inert unless built with `daachorse-index`. |
| `eval` | `engine eval` | Mirrors the eval flag surface. |

### Secrets policy

The schema deliberately does **not** carry any secret-bearing daemon settings:

- NATS auth (`creds`, `token`, `user`, `password`, `nkey`)
- Kafka SASL credentials (`sasl_username`, `sasl_password`)
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

2. **Legacy clap-bound names** with a single underscore (`NATS_CREDS`, `RSIGMA_CONSUMER_GROUP`, `RSIGMA_TLS_KEY_PASSWORD`). These continue to work at the flag layer and are listed in [Environment Variables](environment-variables.md). Secrets are *only* readable this way.

The uniform scheme is detected by the `__` separator, so it never collides with the legacy single-underscore names.

## `--dry-run` and `config show`

[`config show`](../cli/config/show.md) folds `default + file + env` and reports the winning layer for each leaf. To preview what a real command will use, including its flag layer, the daemon and eval support `--dry-run`:

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
