#!/bin/bash
# test-mtls.sh — Test mTLS connections with curl
#
# Usage:
#   ./test-mtls.sh https://api.example.com
#   ./test-mtls.sh https://api.example.com ./mtls
#   ./test-mtls.sh https://api.example.com ./mtls verbose
#
# Expects client.pem, client.key, and ca.pem in the cert directory.
# Generate these with: ./scripts/generate-mtls.sh
#
# Or test mTLS instantly: https://getacert.com/mtls

set -euo pipefail

URL="${1:?Usage: $0 <url> [cert-dir] [verbose]}"
CERTDIR="${2:-./mtls}"
VERBOSE="${3:-}"

# Check files exist
for f in client.pem client.key ca.pem; do
    if [ ! -f "$CERTDIR/$f" ]; then
        echo "Error: $CERTDIR/$f not found"
        echo "Run ./scripts/generate-mtls.sh first, or specify the cert directory:"
        echo "  $0 $URL /path/to/certs"
        exit 1
    fi
done

VERBOSE_FLAG=""
if [ -n "$VERBOSE" ]; then
    VERBOSE_FLAG="-v"
fi

echo "=== mTLS Connection Test ==="
echo ""
echo "  URL:     $URL"
echo "  Client:  $CERTDIR/client.pem"
echo "  CA:      $CERTDIR/ca.pem"
echo ""

# Test the connection
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    --cert "$CERTDIR/client.pem" \
    --key "$CERTDIR/client.key" \
    --cacert "$CERTDIR/ca.pem" \
    $VERBOSE_FLAG \
    "$URL" 2>/dev/null) || true

if [ "$HTTP_CODE" = "000" ]; then
    echo "  Result:  Connection failed"
    echo ""
    echo "  Retrying with verbose output..."
    echo ""
    curl -v \
        --cert "$CERTDIR/client.pem" \
        --key "$CERTDIR/client.key" \
        --cacert "$CERTDIR/ca.pem" \
        "$URL" 2>&1 | grep -E "SSL|TLS|error|alert|subject|issuer|verify" | sed 's/^/  /'
    exit 1
fi

echo "  Result:  HTTP $HTTP_CODE"
echo ""

# Show response if verbose or if non-200
if [ -n "$VERBOSE" ] || [ "$HTTP_CODE" != "200" ]; then
    echo "  --- Response ---"
    curl -s \
        --cert "$CERTDIR/client.pem" \
        --key "$CERTDIR/client.key" \
        --cacert "$CERTDIR/ca.pem" \
        "$URL" | head -50 | sed 's/^/  /'
    echo ""
fi

# Also test with PKCS#12 if available
if [ -f "$CERTDIR/client.p12" ]; then
    echo "  --- PKCS#12 test ---"
    P12_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        --cert-type P12 \
        --cert "$CERTDIR/client.p12:password" \
        --cacert "$CERTDIR/ca.pem" \
        "$URL" 2>/dev/null) || true
    echo "  PKCS#12: HTTP $P12_CODE"
    echo ""
fi

echo "  --- Manual curl commands ---"
echo ""
echo "  # With PEM files"
echo "  curl --cert $CERTDIR/client.pem --key $CERTDIR/client.key --cacert $CERTDIR/ca.pem $URL"
echo ""
echo "  # With PKCS#12"
echo "  curl --cert-type P12 --cert $CERTDIR/client.p12:password --cacert $CERTDIR/ca.pem $URL"
echo ""
echo "  # Verbose (see TLS handshake)"
echo "  curl -v --cert $CERTDIR/client.pem --key $CERTDIR/client.key --cacert $CERTDIR/ca.pem $URL"
echo ""
