# TAXII live integration harness

Zero-config local TLS / mTLS / DNS SRV tests against Docker (Wiremock + Caddy + CoreDNS).

## Quick start

**1. Start the stack** (from repo root):

```bash
./crates/rstix/tests/taxii-live/run-live-tests.sh
```

This generates certs (if missing) and starts Docker Compose (`wiremock`, `caddy`, `coredns`).

**2. Run the tests** (from repo root):

```bash
cargo test -p rstix --features taxii --test taxii_live -- --ignored --nocapture
```

No environment variables required. Paths, URLs, and CoreDNS (`127.0.0.1:5353`) are baked into the tests via `CARGO_MANIFEST_DIR` and `TaxiiClientConfig::dns_nameserver()`.

## What each test proves

| Test | Proves |
| ---- | ------ |
| `live_https_discovery_over_tls` | HTTPS to `:8443`, SPKI pin, discovery JSON |
| `live_mtls_discovery` | Client cert to `localhost:8444`, discovery JSON |
| `live_discover_via_srv` | SRV via CoreDNS `:5353` → `https://localhost:8443/taxii2/` |

**Not covered:** DANE live, TLS 1.3 version assertion in Rust, PKCS#12, default CI.

## Manual steps (equivalent to the script)

```bash
cd crates/rstix/tests/taxii-live
./generate-certs.sh
docker compose up -d --wait
cd ../../../..
cargo test -p rstix --features taxii --test taxii_live -- --ignored --nocapture
```

## Stop stack

```bash
cd crates/rstix/tests/taxii-live
docker compose down
```

Regenerate certs: `rm -rf fixtures/certs && ./generate-certs.sh`

## VM (git Option A)

```bash
git clone <repo-url> rsigma && cd rsigma
git checkout feat/rstix-taxii-client
./crates/rstix/tests/taxii-live/run-live-tests.sh
cargo test -p rstix --features taxii --test taxii_live -- --ignored --nocapture
```

Client and Docker on the same VM → no IP or env changes needed.
