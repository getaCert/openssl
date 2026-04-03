#!/bin/bash
# generate-mtls.sh — Generate a CA + server cert + client cert for mTLS testing
#
# Usage:
#   ./generate-mtls.sh example.com
#   ./generate-mtls.sh example.com my-client-app
#
# This creates everything you need to test mutual TLS authentication.
#
# Or test instantly: https://getacert.com/mtls

set -euo pipefail

DOMAIN="${1:?Usage: $0 <server-domain> [client-name]}"
CLIENT="${2:-client}"
OUTDIR="./mtls"

mkdir -p "$OUTDIR"

echo "=== Generating mTLS certificate set ==="
echo ""

# --- CA ---
echo "[1/4] Creating CA..."
openssl genrsa -out "$OUTDIR/ca.key" 4096 2>/dev/null
openssl req -x509 -new -nodes \
    -key "$OUTDIR/ca.key" \
    -sha256 -days 3650 \
    -out "$OUTDIR/ca.pem" \
    -subj "/CN=mTLS Test CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,digitalSignature,cRLSign,keyCertSign"

# --- Server cert ---
echo "[2/4] Creating server certificate for ${DOMAIN}..."
openssl genrsa -out "$OUTDIR/server.key" 2048 2>/dev/null
openssl req -new \
    -key "$OUTDIR/server.key" \
    -out "$OUTDIR/server.csr" \
    -subj "/CN=${DOMAIN}" \
    -addext "subjectAltName=DNS:${DOMAIN},DNS:localhost,IP:127.0.0.1"

openssl x509 -req \
    -in "$OUTDIR/server.csr" \
    -CA "$OUTDIR/ca.pem" -CAkey "$OUTDIR/ca.key" -CAcreateserial \
    -out "$OUTDIR/server.pem" -days 365 -sha256 \
    -copy_extensions copyall \
    -extfile <(printf "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth") 2>/dev/null

# --- Client cert ---
echo "[3/4] Creating client certificate for ${CLIENT}..."
openssl genrsa -out "$OUTDIR/client.key" 2048 2>/dev/null
openssl req -new \
    -key "$OUTDIR/client.key" \
    -out "$OUTDIR/client.csr" \
    -subj "/CN=${CLIENT}/O=mTLS Test"

openssl x509 -req \
    -in "$OUTDIR/client.csr" \
    -CA "$OUTDIR/ca.pem" -CAkey "$OUTDIR/ca.key" -CAserial "$OUTDIR/ca.srl" \
    -out "$OUTDIR/client.pem" -days 365 -sha256 \
    -extfile <(printf "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth") 2>/dev/null

# --- PKCS#12 bundles ---
echo "[4/4] Creating PKCS#12 bundles..."
openssl pkcs12 -export -out "$OUTDIR/client.p12" \
    -inkey "$OUTDIR/client.key" -in "$OUTDIR/client.pem" -certfile "$OUTDIR/ca.pem" \
    -passout pass:password 2>/dev/null

# Clean up CSRs and serial
rm -f "$OUTDIR"/*.csr "$OUTDIR"/*.srl

echo ""
echo "=== mTLS certificate set ready ==="
echo ""
echo "  Output dir: $OUTDIR/"
echo ""
echo "  CA:     $OUTDIR/ca.pem          — Trust anchor (import into clients and servers)"
echo "  Server: $OUTDIR/server.pem      — Server certificate"
echo "          $OUTDIR/server.key      — Server private key"
echo "  Client: $OUTDIR/client.pem      — Client certificate"
echo "          $OUTDIR/client.key      — Client private key"
echo "          $OUTDIR/client.p12      — Client PKCS#12 bundle (password: password)"
echo ""
echo "  --- nginx config ---"
echo ""
echo "  server {"
echo "      listen 443 ssl;"
echo "      server_name ${DOMAIN};"
echo "      ssl_certificate     $OUTDIR/server.pem;"
echo "      ssl_certificate_key $OUTDIR/server.key;"
echo "      ssl_client_certificate $OUTDIR/ca.pem;"
echo "      ssl_verify_client on;"
echo "  }"
echo ""
echo "  --- Test with curl ---"
echo ""
echo "  curl --cert $OUTDIR/client.pem --key $OUTDIR/client.key --cacert $OUTDIR/ca.pem https://${DOMAIN}"
echo ""
echo "  --- Test with Python ---"
echo ""
echo "  import requests"
echo "  requests.get('https://${DOMAIN}', cert=('$OUTDIR/client.pem', '$OUTDIR/client.key'), verify='$OUTDIR/ca.pem')"
echo ""
