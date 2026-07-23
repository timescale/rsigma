# TAXII live integration harness

Docker stack (Wiremock + Caddy + CoreDNS) for live TLS, mTLS, and DNS SRV tests.

## Prerequisites

- Docker + Compose v2
- OpenSSL CLI (`generate-certs.sh`)
- Rust toolchain (workspace MSRV)
- Run commands from the **repository root** unless noted

## Quick start

**1. Start the stack**

```bash
./crates/rstix/tests/taxii-live/run-live-tests.sh
```

Generates certs (if missing) and runs `docker compose up`. Also adds `dane.taxii.test` and `taxii.test` to `/etc/hosts` (may prompt for sudo).

**2. Run live tests**

```bash
cargo test -p rstix --features taxii --test taxii_live -- --ignored --nocapture
```

No environment variables. URLs and cert paths are defined in `tests/taxii_live.rs`.

## Harness URLs

| Listener | URL |
| -------- | --- |
| TLS | `https://127.0.0.1:8443` |
| mTLS | `https://localhost:8444` (use `localhost`, not the IP — Caddy strict SNI) |
| TLS 1.3 only | `https://127.0.0.1:8445` |
| DANE | `https://dane.taxii.test:8443` (TLSA via CoreDNS; live test uses `dane_require_dnssec(false)` — unsigned zone) |
| SRV | `_taxii2._tcp.taxii.test` via CoreDNS `127.0.0.1:5353` |

## Commands

```bash
cargo test -p rstix --features taxii --test taxii_live -- --ignored --nocapture
```

## Manual equivalent

```bash
cd crates/rstix/tests/taxii-live
./generate-certs.sh
docker compose up -d --wait
cd ../../../..
cargo test -p rstix --features taxii --test taxii_live -- --ignored --nocapture
```

## After updating harness files

If `Caddyfile`, `docker-compose.yml`, CoreDNS config, or the zone changed, recreate the stack so CoreDNS reloads TLSA answers:

```bash
./crates/rstix/tests/taxii-live/run-live-tests.sh
```

Or manually:

```bash
cd crates/rstix/tests/taxii-live
./generate-certs.sh
docker compose up -d --force-recreate caddy coredns
```

## Same machine vs remote Docker

The harness assumes the Rust client and Docker stack run on the **same host** (`127.0.0.1` / `localhost`). Remote Docker requires adjusting URLs, firewall, cert SANs, and the zone file.

## Stop stack

```bash
cd crates/rstix/tests/taxii-live
docker compose down
```

Regenerate certs: `rm -rf fixtures/certs && ./generate-certs.sh`
