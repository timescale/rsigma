# Environment Variables

`rsigma` reads a small set of environment variables in addition to its CLI flags. Every variable here has a corresponding `--flag` that takes precedence; the env vars exist so secrets and per-host configuration can stay out of process tables and shell history.

## Variables

| Variable | Type | Default | Subcommand(s) | Effect |
|----------|------|---------|---------------|--------|
| `RUST_LOG` | `tracing-subscriber` filter directive | `info` | All (always for `engine daemon`; otherwise only when `--log-format` is set) | Controls verbosity of structured diagnostic logs on stderr. See [Observability](../guide/observability.md#rust_log-filter-targets) for the target catalog. |
| `NO_COLOR` | `0`/`1` (presence-only) | unset | `rule lint` and any subcommand that emits colored stderr | Disables ANSI colors. Follows the [NO_COLOR convention](https://no-color.org/). |
| `RSIGMA_CONSUMER_GROUP` | string | unset | `engine daemon` with `--input nats://` | NATS JetStream consumer group name. Equivalent to `--consumer-group`. Multiple daemons sharing the same group name load-balance across a single durable pull consumer. |
| `NATS_CREDS` | path to `.creds` file | unset | `engine daemon` with NATS source or sink | NATS credentials file (JWT + NKey). Equivalent to `--nats-creds`. |
| `NATS_TOKEN` | string | unset | same | NATS authentication token. Equivalent to `--nats-token`. |
| `NATS_USER` | string | unset | same | NATS username (requires `NATS_PASSWORD`). Equivalent to `--nats-user`. |
| `NATS_PASSWORD` | string | unset | same | NATS password (requires `NATS_USER`). Equivalent to `--nats-password`. |
| `NATS_NKEY` | NKey seed | unset | same | NATS NKey seed authentication. Equivalent to `--nats-nkey`. |

The five NATS auth variables are mutually exclusive. The first configured method wins, in the order listed in `--nats-*` flag definition. See [NATS Streaming: authentication](../guide/nats-streaming.md#authentication).

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

- `SIGMA_RULES_DIR`, `RSIGMA_RULES`, `RSIGMA_CONFIG`: not implemented. Rules and pipelines are always passed via `--rules` and `--pipeline`.
- `OTEL_EXPORTER_OTLP_*`: rsigma is an OTLP *receiver*, not an exporter. These env vars apply to the agent publishing logs into rsigma (see [OTLP Integration](../guide/otlp-integration.md)), not to rsigma itself.
- `PROMETHEUS_*`: the daemon exposes `/metrics` on `--api-addr`; no client-side env vars are involved.

## See also

- [NATS Streaming: authentication](../guide/nats-streaming.md#authentication) for the auth-method semantics and TLS flags.
- [Observability](../guide/observability.md) for the canonical `RUST_LOG` target list and useful filter recipes.
- [`engine daemon` CLI reference](../cli/engine/daemon.md) for the matching `--flag` versions of every variable.
