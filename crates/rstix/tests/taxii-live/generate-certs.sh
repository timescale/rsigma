#!/usr/bin/env bash
# Generate a local CA, server cert (taxii.test + localhost + dane.taxii.test), client cert
# for mTLS tests (PEM and PKCS#12), and CoreDNS TLSA records for DANE tests.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
CERT_DIR="$ROOT/fixtures/certs"
ZONE_FILE="$ROOT/coredns/taxii.test.zone"
COREFILE="$ROOT/coredns/Corefile"
mkdir -p "$CERT_DIR"

CA_KEY="$CERT_DIR/ca-key.pem"
CA_PEM="$CERT_DIR/ca.pem"
SERVER_KEY="$CERT_DIR/server-key.pem"
SERVER_PEM="$CERT_DIR/server.pem"
CLIENT_KEY="$CERT_DIR/client-key.pem"
CLIENT_PEM="$CERT_DIR/client.pem"
CLIENT_P12="$CERT_DIR/client.p12"
PKCS12_PASSWORD="rstix-live"

write_zone() {
  local serial="$1"
  local tlsa_hex="$2"
  cat >"$ZONE_FILE" <<EOF
\$ORIGIN taxii.test.
\$TTL 3600

@       IN  SOA  ns.taxii.test. admin.taxii.test. (
                ${serial} ; serial
                3600       ; refresh
                600        ; retry
                86400      ; expire
                3600 )     ; minimum
@       IN  NS   ns.taxii.test.
@       IN  A    127.0.0.1
ns      IN  A    127.0.0.1
dane    IN  A    127.0.0.1
_taxii2._tcp  IN  SRV  10 100 8443 localhost.
_8443._tcp.dane.taxii.test. 3600 IN TLSA 3 1 1 ${tlsa_hex}
EOF
}

write_corefile() {
  cat >"$COREFILE" <<'EOF'
taxii.test {
	file /etc/coredns/taxii.test.zone
	reload 5s
	log
	errors
}
EOF
}

compute_tlsa_hex() {
  openssl x509 -in "$SERVER_PEM" -pubkey -noout \
    | openssl pkey -pubin -outform der \
    | openssl dgst -sha256 -hex \
    | awk '{print $2}'
}

write_pkcs12() {
  openssl pkcs12 -export -out "$CLIENT_P12" \
    -inkey "$CLIENT_KEY" -in "$CLIENT_PEM" -certfile "$CA_PEM" \
    -passout "pass:${PKCS12_PASSWORD}"
}

fix_cert_permissions() {
  # Caddy (root in container) and the local Rust test runner must both read these files.
  chmod 644 "$CA_PEM" "$SERVER_PEM" "$CLIENT_PEM" "$CLIENT_KEY" 2>/dev/null || true
  chmod 600 "$CA_KEY" "$SERVER_KEY" "$CLIENT_P12" 2>/dev/null || true
}

if [[ -f "$CA_PEM" ]]; then
  echo "Certificates already exist in $CERT_DIR (delete to regenerate with new SANs)."
else
  openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
    -keyout "$CA_KEY" -out "$CA_PEM" \
    -subj "/CN=RSTIX TAXII Live Test CA"

  cat >"$CERT_DIR/server.cnf" <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no
[req_distinguished_name]
CN = taxii.test
[v3_req]
subjectAltName = @alt_names
[alt_names]
DNS.1 = taxii.test
DNS.2 = localhost
DNS.3 = dane.taxii.test
IP.1 = 127.0.0.1
EOF

  openssl req -newkey rsa:2048 -nodes -keyout "$SERVER_KEY" -out "$CERT_DIR/server.csr" \
    -config "$CERT_DIR/server.cnf"

  openssl x509 -req -in "$CERT_DIR/server.csr" -CA "$CA_PEM" -CAkey "$CA_KEY" -CAcreateserial \
    -out "$SERVER_PEM" -days 825 -sha256 -extensions v3_req -extfile "$CERT_DIR/server.cnf"

  openssl req -newkey rsa:2048 -nodes -keyout "$CLIENT_KEY" -out "$CERT_DIR/client.csr" \
    -subj "/CN=rstix-taxii-live-client"

  openssl x509 -req -in "$CERT_DIR/client.csr" -CA "$CA_PEM" -CAkey "$CA_KEY" -CAcreateserial \
    -out "$CLIENT_PEM" -days 825 -sha256

  echo "Wrote CA, server, and client material under $CERT_DIR"
fi

if [[ ! -f "$SERVER_PEM" ]]; then
  echo "missing $SERVER_PEM" >&2
  exit 1
fi

TLSA_HEX="$(compute_tlsa_hex)"
SOA_SERIAL="$(date -u +%Y%m%d%H)"
write_zone "$SOA_SERIAL" "$TLSA_HEX"
write_corefile
write_pkcs12
fix_cert_permissions
echo "Updated CoreDNS zone ($ZONE_FILE), Corefile ($COREFILE), and PKCS#12 ($CLIENT_P12)"
