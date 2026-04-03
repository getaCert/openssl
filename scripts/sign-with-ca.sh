#!/bin/bash
# sign-with-ca.sh — Sign a certificate using your local CA
#
# Usage:
#   ./sign-with-ca.sh example.com
#   ./sign-with-ca.sh example.com 365
#   ./sign-with-ca.sh example.com 365 rsa4096
#
# Requires: Run generate-ca.sh first to create the CA.
#
# Or skip all of this: https://getacert.com/casign

set -euo pipefail

DOMAIN="${1:?Usage: $0 <domain> [days] [keytype]}"
DAYS="${2:-365}"
KEYTYPE="${3:-rsa2048}"
CADIR="./ca"
OUTDIR="./certs/${DOMAIN}"

# Check CA exists
if [ ! -f "$CADIR/ca.key" ] || [ ! -f "$CADIR/ca.pem" ]; then
    echo "Error: CA not found at $CADIR/"
    echo "Run ./scripts/generate-ca.sh first."
    exit 1
fi

mkdir -p "$OUTDIR"

# Generate key
case "$KEYTYPE" in
    rsa2048)
        openssl genrsa -out "$OUTDIR/server.key" 2048 2>/dev/null
        ;;
    rsa4096)
        openssl genrsa -out "$OUTDIR/server.key" 4096 2>/dev/null
        ;;
    ecdsa|ec|p256)
        openssl ecparam -genkey -name prime256v1 -noout -out "$OUTDIR/server.key"
        ;;
    ecdsa384|p384)
        openssl ecparam -genkey -name secp384r1 -noout -out "$OUTDIR/server.key"
        ;;
    ed25519)
        openssl genpkey -algorithm Ed25519 -out "$OUTDIR/server.key"
        ;;
    *)
        echo "Unknown key type: $KEYTYPE (options: rsa2048, rsa4096, ecdsa, ecdsa384, ed25519)"
        exit 1
        ;;
esac

# Generate CSR
openssl req -new \
    -key "$OUTDIR/server.key" \
    -out "$OUTDIR/server.csr" \
    -subj "/CN=${DOMAIN}" \
    -addext "subjectAltName=DNS:${DOMAIN},DNS:www.${DOMAIN},DNS:localhost,IP:127.0.0.1"

# Sign with CA
openssl x509 -req \
    -in "$OUTDIR/server.csr" \
    -CA "$CADIR/ca.pem" \
    -CAkey "$CADIR/ca.key" \
    -CAserial "$CADIR/ca.srl" \
    -out "$OUTDIR/server.pem" \
    -days "$DAYS" \
    -sha256 \
    -copy_extensions copyall \
    -extfile <(printf "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth")

# Create PKCS#12 bundle
openssl pkcs12 -export \
    -out "$OUTDIR/server.p12" \
    -inkey "$OUTDIR/server.key" \
    -in "$OUTDIR/server.pem" \
    -certfile "$CADIR/ca.pem" \
    -passout pass:password

# Create full chain file
cat "$OUTDIR/server.pem" "$CADIR/ca.pem" > "$OUTDIR/fullchain.pem"

echo ""
echo "=== CA-signed certificate generated ==="
echo ""
echo "  Domain:      $DOMAIN"
echo "  Key type:    $KEYTYPE"
echo "  Valid for:   $DAYS days"
echo "  Signed by:   $(openssl x509 -in $CADIR/ca.pem -noout -subject | sed 's/subject=//')"
echo "  Output dir:  $OUTDIR/"
echo ""
echo "  Files:"
echo "    $OUTDIR/server.key      — Private key"
echo "    $OUTDIR/server.pem      — Certificate"
echo "    $OUTDIR/server.csr      — CSR"
echo "    $OUTDIR/server.p12      — PKCS#12 bundle (password: password)"
echo "    $OUTDIR/fullchain.pem   — Certificate + CA chain"
echo ""
echo "  Quick start:"
echo "    nginx:   ssl_certificate $OUTDIR/fullchain.pem; ssl_certificate_key $OUTDIR/server.key;"
echo "    curl:    curl --cacert $CADIR/ca.pem https://$DOMAIN"
echo ""
