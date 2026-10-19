# Docker

`rsigma` ships as a multi-arch container image at `ghcr.io/timescale/rsigma`. Images are built from the Alpine-based builder in the repo-root [Dockerfile](https://github.com/timescale/rsigma/blob/main/Dockerfile), scanned by Grype (critical CVEs gate the push), signed with keyless cosign, and shipped with an SPDX SBOM plus SLSA Build L3 provenance attestations. The runtime image runs `FROM scratch` with no shell and no package manager.

## Image

| Property | Value |
|----------|-------|
| Registry | `ghcr.io/timescale/rsigma` |
| Tags | `latest`, `{{ rsigma.version }}`, and the minor line (for example `0.20`) on every release |
| Architectures | `linux/amd64`, `linux/arm64` |
| Base image | `FROM scratch` (no shell, no package manager) |
| User | `65534:65534` (`nobody:nogroup`) |
| Entrypoint | `/rsigma` |
| Features | built with `--all-features` (see [Feature Flags](../reference/feature-flags.md)), including `daemon`, `mcp`, `daemon-nats`, `daemon-otlp`, `daemon-tls`, `logfmt`, `cef`, `evtx`, and `daachorse-index` |

## Pull and run

```bash
docker pull ghcr.io/timescale/rsigma:latest
docker run --rm ghcr.io/timescale/rsigma:latest --help
```

Any `rsigma` subcommand works as the container argument:

```bash
docker run --rm -v "$PWD/rules:/rules:ro" \
    ghcr.io/timescale/rsigma:latest \
    rule validate /rules/
```

## Pin to a release tag

Production deployments should pin to a specific version, not `latest`:

```bash
docker run --rm ghcr.io/timescale/rsigma:{{ rsigma.version }} --version
```

For full immutability, pin by image digest. Pull `inspect` to find the digest, then reference it directly:

```bash
docker buildx imagetools inspect ghcr.io/timescale/rsigma:{{ rsigma.version }}
# Note the Digest line, then:
docker run --rm ghcr.io/timescale/rsigma@sha256:<digest> --version
```

## Verify the signature

The image is signed keylessly via Sigstore/Fulcio OIDC. Verify with [cosign](https://docs.sigstore.dev/cosign/system_config/installation/):

```bash
cosign verify \
    --certificate-identity-regexp 'github.com/timescale/rsigma' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    ghcr.io/timescale/rsigma:latest
```

A successful verification proves the image was built by `timescale/rsigma`'s GitHub Actions and not tampered with after publication. Run this as part of your container admission flow or before promoting an image into production.

The image also ships with a SLSA Build L3 provenance attestation:

```bash
gh attestation verify \
    --owner timescale \
    oci://ghcr.io/timescale/rsigma:latest
```

## Hardened runtime flags

The image runs as non-root from a `FROM scratch` base; layer your container runtime on top with the standard Linux hardening flags:

```bash
docker run --rm \
    --read-only \
    --cap-drop=ALL \
    --security-opt=no-new-privileges:true \
    --tmpfs /tmp:rw,size=64m,mode=1777 \
    -e RSIGMA_API_TOKEN \
    -v "$PWD/rules:/rules:ro" \
    -v "$PWD/pipelines:/pipelines:ro" \
    -p 9090:9090 \
    ghcr.io/timescale/rsigma:latest \
    engine daemon -r /rules/ -p /pipelines/ecs.yml --input http \
    --api-addr 0.0.0.0:9090 --allow-plaintext \
    --api-token-env RSIGMA_API_TOKEN
```

Inside a container the API has to bind a non-loopback address to be reachable through the published port, and the daemon refuses a plaintext non-loopback bind unless you pass `--tls-cert`/`--tls-key` or `--allow-plaintext`. The examples on this page use `--allow-plaintext` and publish the port on the host's loopback or behind a TLS-terminating proxy; see [TLS termination](../reference/security.md#tls-termination-for-the-api-listener) to serve TLS from the daemon itself.

{{ added "0.25.0" }}

A non-loopback bind also needs authentication, so the examples pass `--api-token-env RSIGMA_API_TOKEN` and forward the secret from the host with `-e RSIGMA_API_TOKEN` (generate one with `openssl rand -hex 32`). Clients send it as `Authorization: Bearer <token>`; `GET /healthz` and `GET /readyz` stay open for probes. Use the `daemon.api.auth` config block for per-client roles, `--tls-client-ca` for certificate-based authentication, or `--allow-unauthenticated` only when an authenticating proxy fronts the container. See [Daemon API authentication](../reference/security.md#daemon-api-authentication).

| Flag | Why |
|------|-----|
| `--read-only` | Root filesystem is immutable. Combined with `--tmpfs /tmp` for any scratch writes. |
| `--cap-drop=ALL` | Remove every Linux capability. rsigma never needs to bind below port 1024, modify network stacks, or trace processes. |
| `--security-opt=no-new-privileges:true` | Refuse setuid binaries gaining new capabilities. Defense in depth on top of the cap-drop. |
| `--tmpfs /tmp:...` | Read/write scratch space (only needed if you bind-mount `--state-db` writes to `/tmp`). |
| `-v ...:ro` | Mount rules and pipelines read-only. The daemon's file watcher still picks up changes. |

For correlation state persistence with `--state-db`, mount a writable directory and pick an input source that keeps the daemon alive (the default `stdin` source exits when the TTY closes, so use `--input http` or `--input nats://...` for a long-running container):

```bash
docker run --rm \
    --read-only \
    --cap-drop=ALL \
    --security-opt=no-new-privileges:true \
    -e RSIGMA_API_TOKEN \
    -v "$PWD/rules:/rules:ro" \
    -v "$PWD/state:/state:rw" \
    -p 9090:9090 \
    ghcr.io/timescale/rsigma:latest \
    engine daemon -r /rules/ \
    --input http \
    --state-db /state/correlation.db \
    --api-addr 0.0.0.0:9090 --allow-plaintext \
    --api-token-env RSIGMA_API_TOKEN
```

On Linux hosts, the bind-mounted `$PWD/state` directory must be writable by uid `65534` (`nobody`). Either `chown -R 65534:65534 ./state` before starting, or use a Docker-managed volume (`-v rsigma-state:/state`) which Docker creates with the correct ownership.

## docker compose

A self-contained compose file for the streaming daemon with file-based persistence:

```yaml
services:
  rsigma:
    image: ghcr.io/timescale/rsigma:{{ rsigma.version }}
    read_only: true
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    user: "65534:65534"
    command:
      - engine
      - daemon
      - --rules
      - /rules/
      - --pipeline
      - /pipelines/ecs.yml
      - --input
      - http
      - --state-db
      - /state/correlation.db
      - --api-addr
      - 0.0.0.0:9090
      - --allow-plaintext
      - --api-token-env
      - RSIGMA_API_TOKEN
    environment:
      RSIGMA_API_TOKEN: ${RSIGMA_API_TOKEN:?set RSIGMA_API_TOKEN to the API bearer token}
    ports:
      - "127.0.0.1:9090:9090"
    volumes:
      - ./rules:/rules:ro
      - ./pipelines:/pipelines:ro
      - rsigma-state:/state:rw
    tmpfs:
      - /tmp:rw,size=64m,mode=1777
    healthcheck:
      # /rsigma is the entrypoint; use the binary as the health command.
      # The container has no shell, so this exec form is required.
      test: ["CMD", "/rsigma", "--version"]
      interval: 30s
      timeout: 5s
      retries: 3
    restart: unless-stopped

volumes:
  rsigma-state:
```

The healthcheck above only verifies the binary runs. For a real readiness probe, scrape `GET /readyz` from outside the container (Prometheus, an orchestrator's probe, or a sidecar). The `FROM scratch` image has no `curl` or `wget` for in-container HTTP checks.

## OTLP and NATS

Both feature paths require nothing extra at the image level (the published image is built `--all-features`). For NATS, point `--input nats://...` at the broker and pass credentials via `--nats-creds` or `NATS_CREDS`:

```bash
docker run --rm \
    -e NATS_CREDS=/etc/rsigma/nats.creds \
    -e RSIGMA_API_TOKEN \
    -v "$PWD/rules:/rules:ro" \
    -v "$PWD/nats.creds:/etc/rsigma/nats.creds:ro" \
    ghcr.io/timescale/rsigma:{{ rsigma.version }} \
    engine daemon -r /rules/ \
    --input "nats://nats.internal:4222/events.>" \
    --api-addr 0.0.0.0:9090 --allow-plaintext \
    --api-token-env RSIGMA_API_TOKEN
```

For OTLP, expose port 9090 (HTTP/REST + OTLP/HTTP + gRPC all share one listener) and point upstream agents at `http://<host>:9090/v1/logs`. See [OTLP Integration](../guide/otlp-integration.md) for agent-side recipes.

## Building from source

For non-standard feature combinations or local development, build the image with `docker buildx`:

```bash
git clone https://github.com/timescale/rsigma.git
cd rsigma
docker buildx build -t rsigma:local --load .
docker run --rm rsigma:local --version
```

The Dockerfile uses two cargo build layers: one that compiles only the dependency graph (so `Cargo.toml` edits don't invalidate the full build) and one that compiles the workspace itself. Cold builds take ~5 minutes on a current laptop; subsequent builds with unchanged dependencies finish in well under a minute.

## What's NOT in the image

The image ships only the runtime `rsigma` binary. It does not include:

- `rsigma-lsp` (the LSP server). Install separately for editor integration; see [Editors](../editors/vscode.md).
- The repo's `.cargo`, `target`, or any source files.
- A shell, busybox, or any package manager. Operations that require entering the container (debugging, ad-hoc inspection) need a sidecar or a different image base.

If you need a shell-equipped variant, build locally with the alternative Alpine base referenced in the Dockerfile comments:

```dockerfile
# Swap the runtime stage:
FROM docker/library/alpine:3.21
```

## See also

- [Kubernetes](kubernetes.md) for running the image in a cluster with probes, a state volume, and a restricted security context.
- [systemd](systemd.md) for running the binary as a hardened host service.
- [Streaming Detection](../guide/streaming-detection.md) for daemon configuration that the container runs.
- [Observability](../guide/observability.md) for the metrics endpoint exposed by the running container.
- [Security Hardening](../reference/security.md) for the supply-chain controls (cosign, SLSA, SBOM, Grype scan gate).
- [Feature Flags](../reference/feature-flags.md) for what `--all-features` includes.
- The [Dockerfile](https://github.com/timescale/rsigma/blob/main/Dockerfile) for the build pipeline.
