#!/bin/bash
# curl-ssl-examples.sh — Common curl SSL/TLS examples
#
# Not really meant to be run directly — more of a reference you can
# copy commands from. But it works as a demo if you have certs handy.
#
# Web-based alternative: https://getacert.com

set -euo pipefail

cat << 'EXAMPLES'
=============================================================
  curl SSL/TLS Cheat Sheet
=============================================================

--- Basic HTTPS ---

  # Standard HTTPS request
  curl https://example.com

  # Skip certificate verification (dev only!)
  curl -k https://localhost:8443
  curl --insecure https://self-signed.example.com

  # Trust a specific CA
  curl --cacert ca.pem https://internal.example.com

  # Trust a directory of CA certs
  curl --capath /etc/ssl/certs/ https://example.com


--- Client Certificates (mTLS) ---

  # PEM certificate + key (separate files)
  curl --cert client.pem --key client.key https://api.example.com

  # PEM certificate + key (single file, key included)
  curl --cert combined.pem https://api.example.com

  # PKCS#12 / PFX bundle
  curl --cert-type P12 --cert client.p12:password https://api.example.com

  # DER-encoded certificate
  curl --cert-type DER --cert client.der --key client.key https://api.example.com

  # Client cert + custom CA
  curl --cert client.pem --key client.key --cacert ca.pem https://api.example.com


--- TLS Version Control ---

  # Force TLS 1.2
  curl --tlsv1.2 --tls-max 1.2 https://example.com

  # Force TLS 1.3
  curl --tlsv1.3 https://example.com

  # Minimum TLS 1.2 (allow 1.2 or 1.3)
  curl --tlsv1.2 https://example.com


--- Cipher Control ---

  # Use a specific cipher
  curl --ciphers 'ECDHE-RSA-AES256-GCM-SHA384' https://example.com

  # TLS 1.3 ciphers
  curl --tls13-ciphers 'TLS_AES_256_GCM_SHA384' https://example.com


--- Debugging ---

  # Verbose output (shows TLS handshake)
  curl -v https://example.com

  # Show only SSL/TLS info
  curl -v https://example.com 2>&1 | grep -i -E "ssl|tls|cert|cipher|subject|issuer"

  # Show timing breakdown
  curl -o /dev/null -w "\
    DNS:        %{time_namelookup}s\n\
    Connect:    %{time_connect}s\n\
    TLS:        %{time_appconnect}s\n\
    First byte: %{time_starttransfer}s\n\
    Total:      %{time_total}s\n\
    TLS version: %{ssl_verify_result}\n" \
    https://example.com

  # Write TLS session details to a file
  curl --trace tls-debug.txt https://example.com

  # Show just headers
  curl -I https://example.com

  # Check HSTS header
  curl -sI https://example.com | grep -i strict-transport


--- Certificate Pinning ---

  # Pin by SHA-256 hash of the public key
  curl --pinnedpubkey "sha256//YhKJKSzoTt2b5FP18fvpHo7fJYqQCjAa3HWY3tvRMwE=" https://example.com

  # Pin by certificate file
  curl --pinnedpubkey server.pem https://example.com


--- Download Certificates ---

  # Save a server's certificate
  echo | openssl s_client -connect example.com:443 -servername example.com 2>/dev/null | \
    sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' > server.pem

  # Save the full chain
  echo | openssl s_client -connect example.com:443 -servername example.com -showcerts 2>/dev/null | \
    sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' > chain.pem


--- Common Patterns ---

  # POST JSON with client cert
  curl --cert client.pem --key client.key \
    -H "Content-Type: application/json" \
    -d '{"key": "value"}' \
    https://api.example.com/endpoint

  # Upload a file with mTLS
  curl --cert client.pem --key client.key \
    -F "file=@document.pdf" \
    https://api.example.com/upload

  # Health check with cert + timeout
  curl --cert client.pem --key client.key --cacert ca.pem \
    --connect-timeout 5 --max-time 10 \
    -s -o /dev/null -w "%{http_code}" \
    https://api.example.com/health


--- getaCert.com API Examples ---

  # Generate a self-signed certificate
  curl -X POST https://getacert.com/api/v1/self-signed \
    -H "Authorization: Bearer gac_your_portal_key" \
    -H "Content-Type: application/json" \
    -d '{"cn": "www.example.com", "days": 365}'

  # Generate a CA-signed certificate
  curl -X POST https://getacert.com/api/v1/ca-signed \
    -H "Authorization: Bearer gac_your_portal_key" \
    -H "Content-Type: application/json" \
    -d '{"cn": "www.example.com", "days": 365}'

  # Decode a certificate (no auth required)
  curl -X POST https://getacert.com/api/v1/decode \
    -H "Content-Type: application/json" \
    -d '{"pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"}'

  # Get a portal key: https://getacert.com/portal ($9.99 one-time)

=============================================================
EXAMPLES
