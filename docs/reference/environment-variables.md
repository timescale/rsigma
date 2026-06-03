# Environment Variables

`rsigma` reads two parallel families of environment variables in addition to its CLI flags:

1. **Legacy single-underscore names** bound to specific clap flags (`NATS_CREDS`, `RSIGMA_CONSUMER_GROUP`, `RSIGMA_TLS_KEY_PASSWORD`, …). These are how secrets stay out of process tables and shell history.
2. **Uniform `RSIGMA_<SECTION>__<KEY>`** names that mirror every non-secret config-file key, using `__` as the nesting separator. See [Configuration](configuration.md#environment-layer) for the full scheme and examples.

Every variable here has a corresponding `--flag` that takes precedence.

## Variables

| Variable | Type | Default | Subcommand(s) | Effect |
|----------|------|---------|---------------|--------|
| `RUST_LOG` | `tracing-subscriber` filter directive | `info` | All (always for `engine daemon`; otherwise only when `--log-format` is set) | Controls verbosity of structured diagnostic logs on stderr. See [Observability](../guide/observability.md#rust_log-filter-targets) for the target catalog. |
| `NO_COLOR` | `0`/`1` (presence-only) | unset | All subcommands that emit colored stdout/stderr | Disables ANSI colors when `--color auto`. Follows the [NO_COLOR convention](https://no-color.org/). |
| `RSIGMA_GLOBAL__OUTPUT_FORMAT` | `json`/`ndjson`/`table`/`csv`/`tsv` | unset | All | Default value for `--output-format`. See [Output Formats](output.md). |
| `RSIGMA_GLOBAL__COLOR` | `auto`/`always`/`never` | unset | All | Default value for `--color`. |
| `XDG_CONFIG_HOME` | path | `~/.config` | All | Honoured when locating the user config (`$XDG_CONFIG_HOME/rsigma/config.yaml`). See [Configuration discovery](configuration.md#discovery). |
| `RSIGMA_<SECTION>__<KEY>` | YAML scalar | unset | `engine daemon`, `engine eval` | Uniform env layer for non-secret config keys (e.g. `RSIGMA_DAEMON__API__ADDR`, `RSIGMA_GLOBAL__LOG_FORMAT`). See [Configuration: environment layer](configuration.md#environment-layer). |
| `RSIGMA_CONSUMER_GROUP` | string | unset | `engine daemon` with `--input nats://` | NATS JetStream consumer group name. Equivalent to `--consumer-group`. Multiple daemons sharing the same group name load-balance across a single durable pull consumer. |
| `RSIGMA_TLS_KEY_PASSWORD` | string | unset | `engine daemon` with `--tls-key` | Password for an encrypted TLS key. Currently rejected at startup; reserved for a future release. |
| `NATS_CREDS` | path to `.creds` file | unset | `engine daemon` with NATS source or sink | NATS credentials file (JWT + NKey). Equivalent to `--nats-creds`. |
| `NATS_TOKEN` | string | unset | same | NATS authentication token. Equivalent to `--nats-token`. |
| `NATS_USER` | string | unset | same | NATS username (requires `NATS_PASSWORD`). Equivalent to `--nats-user`. |
| `NATS_PASSWORD` | string | unset | same | NATS password (requires `NATS_USER`). Equivalent to `--nats-password`. |
| `NATS_NKEY` | NKey seed | unset | same | NATS NKey seed authentication. Equivalent to `--nats-nkey`. |
| `KAFKA_BOOTSTRAP_SERVERS` | comma-separated host:port | unset | `engine daemon` with Kafka source or sink | Kafka broker addresses. Equivalent to `--kafka-bootstrap-servers`. |
| `KAFKA_GROUP_ID` | string | `rsigma` | same | Kafka consumer group ID. Equivalent to `--kafka-group-id`. |
| `KAFKA_SECURITY_PROTOCOL` | string | unset | same | Kafka security protocol (`PLAINTEXT`, `SSL`, `SASL_PLAINTEXT`, `SASL_SSL`). Equivalent to `--kafka-security-protocol`. |
| `KAFKA_SASL_MECHANISM` | string | unset | same | Kafka SASL mechanism (`PLAIN`, `SCRAM-SHA-256`, `SCRAM-SHA-512`). Equivalent to `--kafka-sasl-mechanism`. |
| `KAFKA_SASL_USERNAME` | string | unset | same | Kafka SASL username. Equivalent to `--kafka-sasl-username`. |
| `KAFKA_SASL_PASSWORD` | string | unset | same | Kafka SASL password. Equivalent to `--kafka-sasl-password`. |

The five NATS auth variables are mutually exclusive. The first configured method wins, in the order listed in `--nats-*` flag definition. See [NATS Streaming: authentication](../guide/nats-streaming.md#authentication).

The Kafka SASL variables (`KAFKA_SASL_USERNAME`, `KAFKA_SASL_PASSWORD`) are the recommended way to pass credentials without exposing them in shell history. See [Kafka Streaming: authentication](../guide/kafka-streaming.md#authentication).

## Precedence

CLI flags always take precedence. Concretely:

```bash
NATS_TOKEN=foo rsigma engine daemon -r rules/ \
    --input "nats://nats.internal:4222/events.>" \
    --nats-token bar
```

uses `bar`, not `foo`. The env var is convenient for not putting the token in `ps aux` or shell history; the flag is the override.

## Variables NOT read by rsigma

Common variables that `rsigma` does NOT consume, in case operators are wondering why setting them has no effect:

- `SIGMA_RULES_DIR`, `RSIGMA_RULES`: not implemented. Use `--rules` on the command line or `daemon.rules`/`eval.rules` in a config file (or set the corresponding `RSIGMA_DAEMON__RULES` / `RSIGMA_EVAL__RULES`).
- `OTEL_EXPORTER_OTLP_*`: rsigma is an OTLP *receiver*, not an exporter. These env vars apply to the agent publishing logs into rsigma (see [OTLP Integration](../guide/otlp-integration.md)), not to rsigma itself.
- `PROMETHEUS_*`: the daemon exposes `/metrics` on `--api-addr`; no client-side env vars are involved.

## See also

- [NATS Streaming: authentication](../guide/nats-streaming.md#authentication) for the auth-method semantics and TLS flags.
- [Kafka Streaming: authentication](../guide/kafka-streaming.md#authentication) for SASL and mTLS configuration.
- [Observability](../guide/observability.md) for the canonical `RUST_LOG` target list and useful filter recipes.
- [`engine daemon` CLI reference](../cli/engine/daemon.md) for the matching `--flag` versions of every variable.
