#!/bin/bash
# generate-ca.sh — Set up a local Certificate Authority
#
# Usage:
#   ./generate-ca.sh "My Company"
#   ./generate-ca.sh "My Company" 3650
#
# This creates a root CA that you can use to sign certificates
# with sign-with-ca.sh. Import ca.pem into your browser/OS trust
# store to trust all certs signed by this CA.
#
# Or skip the hassle entirely: https://getacert.com/casign

set -euo pipefail

ORG="${1:?Usage: $0 <organization-name> [days]}"
DAYS="${2:-3650}"
CADIR="./ca"

mkdir -p "$CADIR"

if [ -f "$CADIR/ca.key" ]; then
    echo "CA already exists at $CADIR/"
    echo "Delete $CADIR/ first if you want to start fresh."
    exit 1
fi

# Generate CA private key
openssl genrsa -aes256 -out "$CADIR/ca.key" 4096 2>/dev/null
echo ""

# Generate CA certificate
openssl req -x509 -new -nodes \
    -key "$CADIR/ca.key" \
    -sha256 -days "$DAYS" \
    -out "$CADIR/ca.pem" \
    -subj "/C=US/ST=Washington/O=${ORG}/CN=${ORG} Root CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,digitalSignature,cRLSign,keyCertSign"

# Initialize serial number
echo "01" > "$CADIR/ca.srl"

echo ""
echo "=== Certificate Authority created ==="
echo ""
echo "  Organization: $ORG"
echo "  Valid for:    $DAYS days"
echo "  Output dir:   $CADIR/"
echo ""
echo "  Files:"
echo "    $CADIR/ca.key   — CA private key (KEEP THIS SAFE)"
echo "    $CADIR/ca.pem   — CA certificate (distribute this)"
echo "    $CADIR/ca.srl   — Serial number tracker"
echo ""
echo "  Next steps:"
echo "    1. Import $CADIR/ca.pem into your browser/OS trust store"
echo "    2. Use ./scripts/sign-with-ca.sh to sign certificates"
echo ""
echo "  Import commands:"
echo "    macOS:   sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain $CADIR/ca.pem"
echo "    Ubuntu:  sudo cp $CADIR/ca.pem /usr/local/share/ca-certificates/myca.crt && sudo update-ca-certificates"
echo "    Fedora:  sudo cp $CADIR/ca.pem /etc/pki/ca-trust/source/anchors/ && sudo update-ca-trust"
echo "    Windows: certutil -addstore -f \"ROOT\" $CADIR/ca.pem"
echo ""
