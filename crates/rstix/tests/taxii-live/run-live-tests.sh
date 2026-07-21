#!/usr/bin/env bash
# Generate certs and start the Docker stack for live TAXII tests.
# Does NOT run cargo test — see tests/taxii-live/README.md step 2.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"

ensure_hosts_entries() {
  local hosts="/etc/hosts"
  add_host() {
    local line="$1"
    local name="$2"
    if grep -qE "[[:space:]]${name}([[:space:]]|$)" "$hosts" 2>/dev/null; then
      return 0
    fi
    if [[ -w "$hosts" ]]; then
      echo "$line" >>"$hosts"
    elif command -v sudo >/dev/null 2>&1; then
      echo "$line" | sudo tee -a "$hosts" >/dev/null
    else
      echo "Add this line to $hosts (needs root):" >&2
      echo "  $line" >&2
      exit 1
    fi
  }
  add_host "127.0.0.1 dane.taxii.test" "dane.taxii.test"
  add_host "127.0.0.1 taxii.test" "taxii.test"
}

"$ROOT/generate-certs.sh"
ensure_hosts_entries
docker compose -f "$ROOT/docker-compose.yml" up -d --wait --force-recreate

if command -v dig >/dev/null 2>&1; then
  dig @127.0.0.1 -p 5353 +time=2 +tries=1 +short _taxii2._tcp.taxii.test SRV | grep -q . || {
    echo "CoreDNS SRV lookup failed for _taxii2._tcp.taxii.test" >&2
    exit 1
  }
  dig @127.0.0.1 -p 5353 +time=2 +tries=1 +short _8443._tcp.dane.taxii.test TLSA | grep -q . || {
    echo "CoreDNS TLSA lookup failed for _8443._tcp.dane.taxii.test" >&2
    exit 1
  }
  echo "CoreDNS SRV and TLSA lookups OK."
fi

echo "Stack ready. From repo root run:"
echo "  cargo test -p rstix --features taxii --test taxii_live -- --ignored --nocapture"
echo "  cargo test -p rstix --features taxii --test taxii_live -- --ignored --nocapture"
