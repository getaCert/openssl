#!/bin/bash
# check-cert.sh — Check a remote server's SSL certificate
#
# Usage:
#   ./check-cert.sh example.com
#   ./check-cert.sh example.com 8443
#   ./check-cert.sh mail.example.com 587 smtp
#
# Or use the web version: https://getacert.com/check

set -euo pipefail

HOST="${1:?Usage: $0 <hostname> [port] [starttls-protocol]}"
PORT="${2:-443}"
STARTTLS="${3:-}"

STARTTLS_FLAG=""
if [ -n "$STARTTLS" ]; then
    STARTTLS_FLAG="-starttls $STARTTLS"
fi

echo "=== SSL Certificate Check: ${HOST}:${PORT} ==="
echo ""

# Get certificate
CERT=$(echo | openssl s_client -connect "${HOST}:${PORT}" -servername "$HOST" $STARTTLS_FLAG 2>/dev/null)

if [ -z "$CERT" ]; then
    echo "Error: Could not connect to ${HOST}:${PORT}"
    exit 1
fi

# Extract cert for parsing
CERT_PEM=$(echo "$CERT" | sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p')

if [ -z "$CERT_PEM" ]; then
    echo "Error: No certificate received from ${HOST}:${PORT}"
    exit 1
fi

# Subject and Issuer
echo "--- Identity ---"
echo "$CERT_PEM" | openssl x509 -noout -subject -issuer 2>/dev/null | sed 's/^/  /'
echo ""

# SANs
echo "--- Subject Alternative Names ---"
SANS=$(echo "$CERT_PEM" | openssl x509 -noout -ext subjectAltName 2>/dev/null | tail -1)
if [ -n "$SANS" ]; then
    echo "$SANS" | tr ',' '\n' | sed 's/^ */  /'
else
    echo "  (none)"
fi
echo ""

# Validity
echo "--- Validity ---"
echo "$CERT_PEM" | openssl x509 -noout -dates 2>/dev/null | sed 's/^/  /'

# Days remaining
ENDDATE=$(echo "$CERT_PEM" | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
if command -v python3 &>/dev/null; then
    DAYS_LEFT=$(python3 -c "
from datetime import datetime
end = datetime.strptime('$ENDDATE', '%b %d %H:%M:%S %Y %Z')
print((end - datetime.utcnow()).days)
" 2>/dev/null || echo "?")
    echo "  Days remaining: $DAYS_LEFT"
fi
echo ""

# Key info
echo "--- Key ---"
echo "$CERT_PEM" | openssl x509 -noout -text 2>/dev/null | grep "Public Key Algorithm" | sed 's/^ */  /'
echo "$CERT_PEM" | openssl x509 -noout -text 2>/dev/null | grep "Public-Key:" | sed 's/^ */  /'
echo ""

# Fingerprint
echo "--- Fingerprint ---"
echo "  SHA-256: $(echo "$CERT_PEM" | openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)"
echo ""

# Protocol and cipher
echo "--- Connection ---"
echo "$CERT" | grep -E "Protocol|Cipher" | head -2 | sed 's/^ */  /'
echo ""

# Chain
echo "--- Certificate Chain ---"
echo "$CERT" | grep -E "^ *[0-9]+ s:" | sed 's/^ */  /'
echo ""

# Expiry warning
if [ "$DAYS_LEFT" != "?" ] 2>/dev/null; then
    if [ "$DAYS_LEFT" -lt 0 ] 2>/dev/null; then
        echo "  *** EXPIRED $((DAYS_LEFT * -1)) days ago ***"
    elif [ "$DAYS_LEFT" -lt 30 ] 2>/dev/null; then
        echo "  *** WARNING: Expires in $DAYS_LEFT days ***"
    fi
fi
