# systemd

Run the streaming daemon as a hardened systemd service on a Linux host: one config file, a state directory for correlation state, `systemctl reload` for hot reload, and a graceful drain on stop.

## Install the binary

Install a release archive as described in [Installation](../getting-started/installation.md#prebuilt-binaries), so the binary lives at `/usr/local/bin/rsigma`:

```bash
curl -fsSL -o rsigma.tar.gz \
  https://github.com/timescale/rsigma/releases/download/v{{ rsigma.version }}/rsigma-x86_64-unknown-linux-gnu.tar.gz
tar -xzf rsigma.tar.gz
sudo install -m 0755 rsigma /usr/local/bin/rsigma
```

## Lay out the files

| Path | Contents | Written by |
|------|----------|------------|
| `/etc/rsigma/config.yaml` | Daemon configuration. | You |
| `/etc/rsigma/rules/` | Sigma rules (a directory tree of `.yml` files). | You, or a sync job |
| `/etc/rsigma/pipelines/` | Processing pipelines, if you use any. | You |
| `/etc/rsigma/rsigma.env` | Secrets such as the API token, mode `0600`. | You |
| `/var/lib/rsigma/` | SQLite state database. | The daemon |
| `/var/log/rsigma/` | File sinks (detections, dead-letter queue). | The daemon |

The unit below uses `DynamicUser=yes`, so systemd creates `/var/lib/rsigma` and `/var/log/rsigma` with the right ownership on first start. Everything under `/etc/rsigma` only needs to be readable.

A minimal `/etc/rsigma/config.yaml`:

```yaml
# yaml-language-server: $schema=https://rsigma.io/rsigma.schema.json
version: 1

global:
  log_format: json

daemon:
  rules: /etc/rsigma/rules
  # pipelines: [/etc/rsigma/pipelines/ecs.yml]
  api:
    addr: "127.0.0.1:9090"
  input:
    source: http
  output:
    sinks: ["file:///var/log/rsigma/detections.ndjson"]
    drain_timeout: 30
  state:
    db: /var/lib/rsigma/state.db
    save_interval: 30
```

Pick an input that keeps the daemon running: the default `stdin` source ends when standard input closes, which under systemd is immediately. Use `http`, a `nats://` URL, or a `unix://` socket. The default `stdout` sink works too (detections land in the journal next to the logs), but a file, NATS, or OTLP sink keeps detections separate from operational logs.

Check the file before starting the service:

```bash
rsigma config validate --config /etc/rsigma/config.yaml
rsigma engine daemon --config /etc/rsigma/config.yaml --dry-run
```

`config validate` reports schema errors, and `--dry-run` prints the effective `daemon` section without binding a port. See the [Configuration File](../reference/configuration.md) reference for every key.

## The unit file

Save as `/etc/systemd/system/rsigma.service`:

```ini
[Unit]
Description=rsigma streaming detection daemon
Documentation=https://rsigma.io/deployment/systemd/
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/rsigma engine daemon --config /etc/rsigma/config.yaml
ExecReload=/bin/kill -HUP $MAINPID
EnvironmentFile=-/etc/rsigma/rsigma.env
WorkingDirectory=/var/lib/rsigma

# Graceful drain: SIGTERM, then wait longer than daemon.output.drain_timeout.
KillSignal=SIGTERM
TimeoutStopSec=45

# Restart on crashes, but not on rules (2) or configuration (3) errors.
Restart=on-failure
RestartSec=5
RestartPreventExitStatus=2 3

DynamicUser=yes
StateDirectory=rsigma
LogsDirectory=rsigma
UMask=0077

NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectClock=yes
ProtectHostname=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectProc=invisible
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

Notes on the choices:

- `--config` replaces the [discovery chain](../reference/configuration.md#discovery), so a stray `rsigma.yaml` in the working directory or a user config cannot change what the service runs.
- `ExecReload` sends `SIGHUP`, which reloads rules, pipelines, enrichers, and TLS material, and re-resolves dynamic sources. A reload that fails keeps the previous rules running and turns `/readyz` into `503` until the next successful reload.
- The file watcher also reloads on `.yml`/`.yaml` changes under `daemon.rules` and on changes to pipeline files, so `systemctl reload` is mostly for changes the watcher does not see (enrichers, TLS certificates, sources).
- `TimeoutStopSec` must exceed `daemon.output.drain_timeout`; otherwise systemd sends `SIGKILL` before the final state snapshot is written.
- `RestartPreventExitStatus=2 3` stops a restart loop on a broken rule set or config. Fix the file, then `systemctl start rsigma`. See [exit codes](../cli/engine/daemon.md#exit-codes).
- `RestrictAddressFamilies` keeps `AF_UNIX` for `unix://` inputs, sinks, and the API socket.

Enable and start it:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now rsigma
systemctl status rsigma
```

`systemd-analyze security rsigma` scores the sandbox if you want to tighten it further.

## Verify

```bash
curl -s http://127.0.0.1:9090/healthz
curl -s http://127.0.0.1:9090/readyz
# {"status":"ready","rules_loaded":true}

curl -s -X POST http://127.0.0.1:9090/api/v1/events \
  -H 'Content-Type: application/json' \
  -d '{"CommandLine":"cmd /c whoami"}'
# {"accepted":1}

rsigma engine status
journalctl -u rsigma -f
```

`rsigma engine status` reads `daemon.api.addr` from the system config at `/etc/rsigma/config.yaml`, so it finds the service without flags when run on the same host.

## Expose the API

The config above binds loopback. To accept events or scrapes from other hosts, bind a routable address and either serve TLS from the daemon or put a TLS-terminating proxy in front and opt in to plaintext:

```yaml
daemon:
  api:
    addr: "0.0.0.0:9090"
    tls:
      cert: /etc/rsigma/tls/server.crt
      key: /etc/rsigma/tls/server.key
```

The daemon refuses to start on a non-loopback address without TLS or `--allow-plaintext`, and without authentication or `--allow-unauthenticated`. {{ added "0.25.0" }} Renewed certificates are picked up on `systemctl reload rsigma`. See [TLS termination](../reference/security.md#tls-termination-for-the-api-listener).

A routable bind needs [bearer-token authentication](../reference/security.md#daemon-api-authentication) (or client certificates with `tls.client_ca`). Put the secret in the environment file, which only root can read:

```bash
sudo install -m 0600 /dev/null /etc/rsigma/rsigma.env
echo "RSIGMA_API_TOKEN=$(openssl rand -hex 32)" | sudo tee /etc/rsigma/rsigma.env >/dev/null
```

Then add `--api-token-env RSIGMA_API_TOKEN` to `ExecStart`. `/healthz` and `/readyz` stay open for probes; `/metrics` and every other route require the token.

## Upgrades

Replace the binary and restart. Correlation, alert-pipeline, and risk state is written to `daemon.state.db` on shutdown and loaded on startup, so open correlation windows survive the restart:

```bash
sudo install -m 0755 rsigma /usr/local/bin/rsigma
sudo systemctl restart rsigma
```

## See also

- [Docker](docker.md) for the container image and its hardening flags.
- [Kubernetes](kubernetes.md) for running the image in a cluster.
- [`engine daemon`](../cli/engine/daemon.md) for every flag and its config key.
- [Streaming Detection](../guide/streaming-detection.md) for the daemon walkthrough.
- [Observability](../guide/observability.md) for metrics, logs, and alerting recipes.
