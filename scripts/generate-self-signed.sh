#!/bin/bash
# generate-self-signed.sh — Generate a self-signed certificate with SANs
#
# Usage:
#   ./generate-self-signed.sh example.com
#   ./generate-self-signed.sh example.com 365
#   ./generate-self-signed.sh example.com 365 rsa4096
#   ./generate-self-signed.sh example.com 365 ecdsa
#
# Or skip the command line entirely: https://getacert.com/selfsign

set -euo pipefail

DOMAIN="${1:?Usage: $0 <domain> [days] [keytype]}"
DAYS="${2:-30}"
KEYTYPE="${3:-rsa2048}"
OUTDIR="./certs/${DOMAIN}"

mkdir -p "$OUTDIR"

# Generate key based on type
case "$KEYTYPE" in
    rsa2048)
        openssl genrsa -out "$OUTDIR/server.key" 2048
        ;;
    rsa4096)
        openssl genrsa -out "$OUTDIR/server.key" 4096
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
        echo "Unknown key type: $KEYTYPE"
        echo "Options: rsa2048, rsa4096, ecdsa, ecdsa384, ed25519"
        exit 1
        ;;
esac

# Generate certificate with SANs
openssl req -x509 -new -nodes \
    -key "$OUTDIR/server.key" \
    -out "$OUTDIR/server.pem" \
    -days "$DAYS" \
    -subj "/CN=${DOMAIN}" \
    -addext "subjectAltName=DNS:${DOMAIN},DNS:www.${DOMAIN},DNS:localhost,IP:127.0.0.1" \
    -addext "basicConstraints=CA:FALSE" \
    -addext "keyUsage=digitalSignature,keyEncipherment" \
    -addext "extendedKeyUsage=serverAuth"

# Generate CSR (useful if you later want to get it CA-signed)
openssl req -new \
    -key "$OUTDIR/server.key" \
    -out "$OUTDIR/server.csr" \
    -subj "/CN=${DOMAIN}" \
    -addext "subjectAltName=DNS:${DOMAIN},DNS:www.${DOMAIN}"

# Create PKCS#12 bundle (for browsers, Java, Windows)
openssl pkcs12 -export \
    -out "$OUTDIR/server.p12" \
    -inkey "$OUTDIR/server.key" \
    -in "$OUTDIR/server.pem" \
    -passout pass:password

echo ""
echo "=== Certificate generated ==="
echo ""
echo "  Domain:      $DOMAIN"
echo "  Key type:    $KEYTYPE"
echo "  Valid for:   $DAYS days"
echo "  Output dir:  $OUTDIR/"
echo ""
echo "  Files:"
echo "    $OUTDIR/server.key   — Private key"
echo "    $OUTDIR/server.pem   — Certificate"
echo "    $OUTDIR/server.csr   — CSR"
echo "    $OUTDIR/server.p12   — PKCS#12 bundle (password: password)"
echo ""
echo "  Quick start:"
echo "    nginx:   ssl_certificate $OUTDIR/server.pem; ssl_certificate_key $OUTDIR/server.key;"
echo "    python:  python -m http.server --certfile $OUTDIR/server.pem --keyfile $OUTDIR/server.key 8443"
echo "    node:    https.createServer({cert: fs.readFileSync('$OUTDIR/server.pem'), key: fs.readFileSync('$OUTDIR/server.key')})"
echo ""
echo "  View details:"
echo "    openssl x509 -in $OUTDIR/server.pem -text -noout"
echo ""
