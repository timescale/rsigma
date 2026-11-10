---
description: "Every environment variable rsigma reads: secret-bearing names for NATS and TLS, the RSIGMA_SECTION__KEY config overrides, and how CLI flags take precedence."
---

# Environment Variables

`rsigma` reads two parallel families of environment variables in addition to its CLI flags:

1. **Legacy single-underscore names** bound to specific clap flags (`NATS_CREDS`, `RSIGMA_CONSUMER_GROUP`, `RSIGMA_TLS_KEY_PASSWORD`, …). These are how secrets stay out of process tables and shell history.
2. **Uniform `RSIGMA_<SECTION>__<KEY>`** names that mirror every non-secret config-file key, using `__` as the nesting separator. See [Configuration](configuration.md#environment-layer) for the full scheme and examples.

Every variable in the table has a corresponding `--flag` that takes precedence, except `RAYON_NUM_THREADS`, which rayon reads directly and which has no CLI flag.

## Variables

| Variable | Type | Default | Subcommand(s) | Effect |
|----------|------|---------|---------------|--------|
| `RUST_LOG` | `tracing-subscriber` filter directive | `info` | All (always for `engine daemon`; otherwise only when `--log-format` is set) | Controls verbosity of structured diagnostic logs on stderr. See [Observability](../guide/observability.md#rustlog-filter-targets) for the target catalog. |
| `NO_COLOR` | `0`/`1` (presence-only) | unset | All subcommands that emit colored stdout/stderr | Disables ANSI colors when `--color auto`. Follows the [NO_COLOR convention](https://no-color.org/). |
| `RSIGMA_GLOBAL__OUTPUT_FORMAT` | `json`/`ndjson`/`table`/`csv`/`tsv` | unset | All | Default value for `--output-format`. See [Output Formats](output.md). |
| `RSIGMA_GLOBAL__COLOR` | `auto`/`always`/`never` | unset | All | Default value for `--color`. |
| `XDG_CONFIG_HOME` | path | `~/.config` | All | Honored when locating the user config (`$XDG_CONFIG_HOME/rsigma/config.yaml`). See [Configuration discovery](configuration.md#discovery). |
| `RSIGMA_<SECTION>__<KEY>` | YAML scalar | unset | `engine daemon`, `engine eval`, `mcp serve` | Uniform env layer for non-secret config keys (e.g. `RSIGMA_DAEMON__API__ADDR`, `RSIGMA_GLOBAL__LOG_FORMAT`, `RSIGMA_MCP__HTTP_ADDR`). See [Configuration: environment layer](configuration.md#environment-layer). |
| `RSIGMA_MCP_AUTH_TOKEN` | string | unset | `mcp serve --http` | Static bearer token required on every HTTP request (`Authorization: Bearer <token>`). Equivalent to `--auth-token`. Required for a non-loopback bind unless `--allow-unauthenticated` is set; an empty value is refused (exit `3`). {{ added "unreleased" }} Secret: flag/env only, never read from config files. |
| `RSIGMA_MCP_DAEMON_TOKEN` | string | unset | `mcp serve --daemon-url` | Bearer token the MCP server sends to the daemon (`Authorization: Bearer <token>`). Equivalent to `--daemon-token`. Secret: flag/env only, never read from config files. {{ added "0.22.0" }} |
| `RSIGMA_CONSUMER_GROUP` | string | unset | `engine daemon` with `--input nats://` | NATS JetStream consumer group name. Equivalent to `--consumer-group`. Multiple daemons sharing the same group name load-balance across a single durable pull consumer. |
| `RAYON_NUM_THREADS` | integer | unset (rayon uses available parallelism) | `engine daemon` | Worker count for the rayon pool used by detection and formatted-input parsing. The daemon also uses this value, when set, as the worker count behind the default for `RSIGMA_DETECT_INFLIGHT`. See [Performance tuning](../guide/performance-tuning.md). |
| `RSIGMA_DETECT_INFLIGHT` | integer 1-8 | scales with rayon (1 on one worker, up to 5 on eight or more) | `engine daemon` | Maximum detection-only batches evaluated concurrently when the loaded rule set has no correlation rules. Sink and ack order stay sequential via a sequence-numbered reducer. Ignored (forced to 1) when correlation rules are present. |
| `RSIGMA_TLS_KEY_PASSWORD` | string | unset | `engine daemon` with `--tls-key` | Password for an encrypted TLS key. Currently rejected at startup with a clear error; decrypt the key first (`openssl rsa -in key.pem -out key-decrypted.pem`). |
| `RSIGMA_SIGMA_CLI` | path | unset | `backend convert`, `mcp serve` (with `--allow-sigma-cli`) | Override path to the external `sigma` executable used for delegated conversion. |
| `RSIGMA_HUNT_DSN` | string | unset | `hunt run` | PostgreSQL connection string for hunt execution. Equivalent to `--dsn`; keeps the password out of `ps aux` and shell history. Secret: flag/env only, never read from config files. {{ added "0.22.0" }} |
| `RSIGMA_TAXII_BEARER_TOKEN` | string | unset | `taxii sync` (`taxii-sync` feature) | Bearer token for TAXII collection ingest (`Authorization: Bearer …`). Equivalent to `--bearer-token`. Mutually exclusive with basic auth and `--api-key`. Secret: flag/env only. {{ added "0.23.0" }} |
| `RSIGMA_TAXII_BASIC_PASSWORD` | string | unset | `taxii sync` (`taxii-sync` feature) | HTTP Basic password for TAXII ingest. Requires `--basic-user`. Equivalent to `--basic-password`. Mutually exclusive with bearer and API key auth. Secret: flag/env only. {{ added "0.23.0" }} |
| `RSIGMA_TAXII_API_KEY` | string | unset | `taxii sync` (`taxii-sync` feature) | API key header value for TAXII ingest. Equivalent to `--api-key`. Mutually exclusive with bearer and basic auth. Secret: flag/env only. {{ added "0.23.0" }} |
| `RSIGMA_TAXII_CLIENT_P12_PASSWORD` | string | unset | `taxii sync` (`taxii-sync` feature) | Decryption password for `--client-p12` mTLS client identity. Equivalent to `--client-p12-password`. Secret: flag/env only. {{ added "0.23.0" }} |
| `RSIGMA_API_TOKEN` | string | unset | `engine incidents export` | Default bearer token env var for daemon-client auth. Override the variable name with `--auth-token-env`. |
| `NATS_CREDS` | path to `.creds` file | unset | `engine daemon` with NATS source or sink | NATS credentials file (JWT + NKey). Equivalent to `--nats-creds`. |
| `NATS_TOKEN` | string | unset | same | NATS authentication token. Equivalent to `--nats-token`. |
| `NATS_USER` | string | unset | same | NATS username (requires `NATS_PASSWORD`). Equivalent to `--nats-user`. |
| `NATS_PASSWORD` | string | unset | same | NATS password (requires `NATS_USER`). Equivalent to `--nats-password`. |
| `NATS_NKEY` | NKey seed | unset | same | NATS NKey seed authentication. Equivalent to `--nats-nkey`. |

The five NATS auth variables are mutually exclusive. The first configured method wins, in the order listed in `--nats-*` flag definition. See [NATS Streaming: authentication](../guide/nats-streaming.md#authentication).

Config-named secrets are separate: `daemon.api.auth.tokens[].token_env` and webhook `signing.secret_env` and `rotate_secret_env` name arbitrary environment variables resolved at startup. Those names are not fixed on this page.

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

- `SIGMA_RULES_DIR`, `RSIGMA_RULES`: not implemented. Use `--rules` on the command line or `daemon.rules`/`eval.rules` in a config file (or set the corresponding `RSIGMA_DAEMON__RULES`/`RSIGMA_EVAL__RULES`).
- `OTEL_EXPORTER_OTLP_*`: rsigma is an OTLP *receiver*, not an exporter. These env vars apply to the agent publishing logs into rsigma (see [OTLP Integration](../guide/otlp-integration.md)), not to rsigma itself.
- `PROMETHEUS_*`: the daemon exposes `/metrics` on `--api-addr`; no client-side env vars are involved.

## See also

- [NATS Streaming: authentication](../guide/nats-streaming.md#authentication) for the auth-method semantics and TLS flags.
- [Observability](../guide/observability.md) for the canonical `RUST_LOG` target list and useful filter recipes.
- [`engine daemon` CLI reference](../cli/engine/daemon.md) for the matching `--flag` versions of every variable.
