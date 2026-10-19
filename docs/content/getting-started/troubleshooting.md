# Troubleshooting

Common problems, organized by what you see. Each entry names the message to look for, the cause, and the fix.

## A command or flag does not exist

```text
error: unrecognized subcommand 'daemon'
```

Several command groups are behind [build features](../reference/feature-flags.md): the daemon, NATS, OTLP, TLS, EVTX, hunting, MCP, and TAXII among them. A binary built without a feature does not have its commands or flags. Check what your binary has:

```bash
rsigma --version
# rsigma {{ rsigma.version }}
# features: cef, daachorse-index, daemon, daemon-nats, daemon-otlp, daemon-tls, evtx, hunt-postgres, ...
```

Some commands exist in every build and explain themselves when their feature is missing, for example `hunt run`:

```text
this binary was built without the 'hunt-postgres' feature; rebuild with ...
```

The [prebuilt binaries](installation.md#prebuilt-binaries) and the Docker image are built with every feature. `cargo install rsigma` builds only the default features; add `--features <list>` or `--all-features` for the rest. See [Detecting features at runtime](../reference/feature-flags.md#detecting-features-at-runtime).

## The daemon refuses to start

```text
refusing to bind plaintext on non-loopback address 0.0.0.0:9090; pass --tls-cert/--tls-key to enable TLS, or pass --allow-plaintext to opt out (e.g. when terminating TLS at a sidecar reverse proxy)
```

The API listens on `0.0.0.0:9090` by default, and every build refuses plaintext on a non-loopback address. {{ added "0.25.0" }} Pick one:

- Local use: `--api-addr 127.0.0.1:9090`. Loopback always allows plaintext.
- Serve TLS: `--tls-cert` and `--tls-key` (prebuilt binaries and the image; `cargo install` needs `--features daemon-tls`). See [TLS termination](../reference/security.md#tls-termination-for-the-api-listener).
- TLS is handled elsewhere (a reverse proxy, a service mesh, a private network): `--allow-plaintext`.

```text
refusing to serve the API without authentication on non-loopback address 0.0.0.0:9090; configure bearer tokens (daemon.api.auth or --api-token-env), require client certificates with --tls-client-ca, or pass --allow-unauthenticated to opt out (e.g. when an authenticating proxy fronts the daemon)
```

{{ added "0.25.0" }}

A non-loopback bind also needs authentication. Pick one:

- A bearer token: `--api-token-env RSIGMA_API_TOKEN` with the secret in that variable, or the `daemon.api.auth` block for per-token roles. See [HTTP API: Authentication](../reference/http-api.md#authentication).
- Client certificates: `--tls-client-ca`, so only agents with a CA-signed certificate can connect.
- Authentication is handled elsewhere (an authenticating proxy, a network policy that admits only trusted callers): `--allow-unauthenticated`. The daemon logs a warning at startup.

Other startup failures exit with code `2` (the initial rules could not be loaded) or `3` (a configuration error, such as a missing rules path, a bad pipeline, an invalid input URL, or a TLS or auth misconfiguration). The last line on stderr names the problem. See [exit codes](../cli/engine/daemon.md#exit-codes).

## The daemon exits right after starting

```text
Event source exhausted, engine shutting down
```

The default input is `stdin`, and the daemon stops when standard input closes. Under systemd, in a detached container, or with `&` in a non-interactive shell, it closes immediately. Use a long-lived input: `--input http`, a `nats://` URL, or a `unix://` socket.

## Some rules are missing

```text
Warning: 1 parse errors while loading rules
```

`engine eval` prints this on stderr, and the daemon logs `Parse errors while loading rules` at `WARN`. The rules that parse still load and run, and the daemon still reports ready on `/readyz`, so a broken file can go unnoticed. Compare the loaded count from `rsigma engine status` with what you expect, and get the reason per file with:

```bash
rsigma rule validate -v rules/
```

```text
Parse errors:
  - Unknown modifier 'contians'
```

Run `rule validate` and [`rule lint`](../cli/rule/lint.md) in CI so a broken rule fails the build instead of disappearing at load time. See [CI/CD](../guide/ci-cd.md).

## A rule does not match an event it should

Ask the engine why, with [`engine explain`](../cli/engine/explain.md):

```bash
rsigma engine explain -r rules/shadow-copy-deletion.yml \
  -e '{"process":{"executable":"C:\\Windows\\System32\\vssadmin.exe","command_line":"vssadmin delete shadows /all"}}'
```

```text
Shadow copy deletion with vssadmin (5c7f3e8a-2b41-4d0e-9a6c-1f2e3d4c5b6a): NO MATCH
  FAIL selection
    FAIL Image|endswith "\\vssadmin.exe" (field absent)
    FAIL CommandLine|one_of "delete, shadows" (field absent)
```

`field absent` almost always means the rule and the event use different field names. Sigma rules use Sysmon-style names (`CommandLine`, `Image`); this event is ECS (`process.command_line`). A [processing pipeline](../guide/processing-pipelines.md) renames the rule's fields to match your data:

```bash
rsigma engine eval -r rules/ -p ecs_windows -e @events.ndjson
```

To see the field names a ruleset expects after a pipeline, run `rsigma rule fields --rules rules/ -p ecs_windows`. To see which schema an event is in, run [`rsigma engine classify`](../cli/engine/classify.md).

When every field is present but the verdict is still `NO MATCH`, the per-item lines show which value failed. Also check for a Sigma filter rule in the same directory (a document with a top-level `filter:` block, like the ones [`rule tune`](../guide/rule-tuning.md) emits) that suppresses the rule, and for [logsource routing](../guide/logsource-routing.md), which skips rules whose logsource conflicts with the event's.

## A correlation never fires

- **Timestamps.** Correlation windows use the event time, read from the first of `@timestamp`, `timestamp`, `EventTime`, `TimeCreated`, and `eventTime` that is present. If your events carry time in another field, add `--timestamp-field <FIELD>`. Without any timestamp, the daemon uses the wall clock, which compresses a replay of old events into the moment it runs; use `--timestamp-fallback skip` for replays.
- **Group keys.** Every event that should count toward one correlation needs the same values in the `group-by` fields, after the pipeline has renamed them.
- **Backtests.** `rule backtest` resets correlation state per corpus file, so the events of one incident have to be in the same file.
- **Several daemons.** With a NATS consumer group, each replica keeps its own correlation state, so events for one group key can land on different replicas and never meet. See [consumer groups](../guide/nats-streaming.md#consumer-groups).

## Rule changes are not picked up

The daemon's file watcher reloads when a `.yml` or `.yaml` file changes anywhere under the rules path, or when a pipeline file changes. It does not watch enrichers, dynamic sources, or TLS files, and it does not see Kubernetes ConfigMap updates reliably. For those, trigger the reload yourself:

```bash
kill -HUP <daemon-pid>          # Unix
rsigma config reload            # any platform, through the API
```

When a reload fails (for example, a new rule does not parse), the daemon keeps serving the previous rules, `/readyz` returns `503`, and `rsigma_reloads_failed_total` goes up. The log line after `Reloading rules and pipelines...` names the failure. Fix the file and the next change reloads cleanly.

## The API returns 401 or 403

```json
{"error":"missing or invalid bearer token"}
```

Authentication is on (`--api-token-env` or `daemon.api.auth`), and the request carried no token or an unknown one. Send `Authorization: Bearer <token>`. `rsigma engine status` and `rsigma config reload` do not send a token; to use them against an authenticated daemon, grant the permissions they need to requests without a token through `anonymous_permissions`, and only on a trusted network. `403` means the token is valid but its role lacks the route's permission; the [endpoint summary](../reference/http-api.md#endpoint-summary) lists the permission per route. `/healthz` and `/readyz` never require a token.

## A setting is not taking effect

Settings merge from several places: CLI flags, environment variables, a project `rsigma.yaml` or `.rsigmarc` in the current directory or a parent, the user config, and `/etc/rsigma/config.yaml`. A forgotten project file in the working directory is a common surprise. Show every resolved value and the layer it came from:

```bash
rsigma config show
```

```text
daemon.api.addr = 0.0.0.0:9090  (default)
...
```

`--config <PATH>` replaces the discovery chain with a single file, and `rsigma engine daemon --dry-run` prints the effective daemon section without starting anything. See [Configuration File](../reference/configuration.md).

## Still stuck

Raise the log level for the component you are debugging, for example `RUST_LOG="info,rsigma::daemon::reload=debug"` for reloads; the [Observability](../guide/observability.md) guide lists the log targets. If the behavior looks like a bug, [open an issue](https://{{ rsigma.repo_url | replace("https://", "") }}/issues) with the `rsigma --version` output, the rule, and an event that reproduces it.
