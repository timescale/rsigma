#!/usr/bin/env bash
# Generate certs and start the Docker stack for live TAXII tests.
# Does NOT run cargo test — see tests/taxii-live/README.md step 2.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"

"$ROOT/generate-certs.sh"
docker compose -f "$ROOT/docker-compose.yml" up -d --wait --force-recreate

if command -v dig >/dev/null 2>&1; then
  if ! dig @127.0.0.1 -p 5353 +time=2 +tries=1 +short _8443._tcp.dane.taxii.test TLSA | grep -q .; then
    echo "CoreDNS TLSA lookup failed for _8443._tcp.dane.taxii.test" >&2
    echo "Check: docker compose -f $ROOT/docker-compose.yml logs coredns" >&2
    exit 1
  fi
  echo "CoreDNS TLSA lookup OK."
fi

echo "Stack ready. From repo root run:"
echo "  cargo test -p rstix --features taxii --test taxii_live -- --ignored --nocapture"
echo "  cargo test -p rstix --features taxii-native-tls --test taxii_live -- --ignored --nocapture"
