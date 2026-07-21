# TAXII live integration harness

Optional Docker stack for **real** TLS / mTLS / DNS SRV tests. Wiremock tests (`cargo test -p rstix --features taxii --test taxii_client`, **59** tests) cover HTTP semantics on plain HTTP and are what CI runs.

## Prerequisites

- Docker + Compose v2
- OpenSSL CLI (`generate-certs.sh`)
- Rust toolchain (workspace MSRV)
- Run commands from the **repository root** unless noted

## Quick start (two steps)

**1. Start the stack**

```bash
./crates/rstix/tests/taxii-live/run-live-tests.sh
```

This script only generates certs (if missing) and runs `docker compose up`. It does **not** run Rust tests (despite the script name).

**2. Run live tests**

```bash
cargo test -p rstix --features taxii --test taxii_live -- --ignored --nocapture
```

No environment variables. URLs, cert paths, and CoreDNS (`127.0.0.1:5353`) are hard-coded in `tests/taxii_live.rs` via `CARGO_MANIFEST_DIR` and `TaxiiClientConfig::dns_nameserver()`.

## Baked-in URLs (do not change unless you edit tests + Caddyfile)

| Test | URL | Why |
| ---- | --- | --- |
| TLS | `https://127.0.0.1:8443` | SPKI pin; no mTLS |
| mTLS | `https://localhost:8444` | Caddy mTLS enables strict SNI — **IP Host returns HTTP 421** |
| SRV | `_taxii2._tcp.taxii.test` → `https://localhost:8443/taxii2/` | CoreDNS on `127.0.0.1:5353`; SRV target is `localhost` |

## What each live test proves

| Test | Verified behavior |
| ---- | ----------------- |
| `live_https_discovery_over_tls` | rustls HTTPS, SPKI pin, discovery JSON |
| `live_mtls_discovery` | Client cert accepted, discovery JSON |
| `live_discover_via_srv` | SRV via CoreDNS, discovery JSON |

## Not covered here

- DANE live (library + unit tests only)
- TLS 1.3 version assertion in Rust (use `openssl s_client -connect 127.0.0.1:8443 -tls1_3` manually)
- PKCS#12 (`taxii-native-tls` feature)
- Default workspace CI
- TAXII Channels (spec §6 RESERVED — not in client)

## Manual equivalent

```bash
cd crates/rstix/tests/taxii-live
./generate-certs.sh
docker compose up -d --wait
cd ../../../..
cargo test -p rstix --features taxii --test taxii_live -- --ignored --nocapture
```

## After updating harness files

If you pulled changes to `Caddyfile`, `docker-compose.yml`, or the CoreDNS zone, recreate Caddy so config reloads:

```bash
cd crates/rstix/tests/taxii-live
docker compose up -d --force-recreate caddy
```

## Same machine vs remote Docker

The tests assume the Rust client and Docker stack run on the **same host** (`127.0.0.1` / `localhost`). If Docker runs elsewhere, you must adjust URLs, firewall, cert SANs, and the zone file yourself — that path is not automated.

## Stop stack

```bash
cd crates/rstix/tests/taxii-live
docker compose down
```

Regenerate certs: `rm -rf fixtures/certs && ./generate-certs.sh`
