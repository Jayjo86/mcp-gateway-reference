#!/usr/bin/env bash
# Generate a self-signed cert for the gateway's local https on :8443.
# Writes certs/gateway.crt and certs/gateway.key (gitignored).
#
# MCP clients will reject a self-signed cert unless you trust it. Easiest path:
#   - install mkcert (https://github.com/FiloSottile/mkcert) and run `mkcert -install`,
#     then re-run this script — it uses mkcert if available.
#   - or add certs/gateway.crt to your OS/Node trust store manually.
set -euo pipefail

cd "$(dirname "$0")/.."
mkdir -p certs

if command -v mkcert >/dev/null 2>&1; then
  echo "Using mkcert..."
  mkcert -cert-file certs/gateway.crt -key-file certs/gateway.key localhost 127.0.0.1 ::1
else
  echo "mkcert not found — generating a self-signed cert with openssl."
  echo "(MCP clients may reject it; consider installing mkcert.)"
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout certs/gateway.key -out certs/gateway.crt \
    -days 365 -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
fi

echo
echo "Done. Add to .env:"
echo "  GATEWAY_TLS_CERT=/certs/gateway.crt"
echo "  GATEWAY_TLS_KEY=/certs/gateway.key"
