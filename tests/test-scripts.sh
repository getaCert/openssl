#!/bin/bash
# test-scripts.sh — Test all helper scripts
#
# Usage:
#   ./tests/test-scripts.sh
#
# Requires: openssl, curl (optional for mTLS server test)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)/scripts"
WORK_DIR=$(mktemp -d)
PASS=0
FAIL=0
ERRORS=""

cleanup() {
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

# Move into temp dir so scripts create files there
cd "$WORK_DIR"

pass() {
    PASS=$((PASS + 1))
    echo "  PASS: $1"
}

fail() {
    FAIL=$((FAIL + 1))
    ERRORS="${ERRORS}\n  FAIL: $1"
    echo "  FAIL: $1"
}

assert_file_exists() {
    if [ -f "$1" ]; then
        return 0
    else
        return 1
    fi
}

assert_valid_cert() {
    openssl x509 -in "$1" -noout 2>/dev/null
}

assert_valid_key() {
    openssl rsa -in "$1" -check -noout 2>/dev/null || \
    openssl ec -in "$1" -check -noout 2>/dev/null || \
    openssl pkey -in "$1" -check -noout 2>/dev/null
}

assert_valid_csr() {
    openssl req -in "$1" -verify -noout 2>&1 | grep -q "verify OK"
}

assert_valid_p12() {
    openssl pkcs12 -in "$1" -info -nokeys -passin pass:password -noout 2>/dev/null
}

assert_cert_cn() {
    local cn
    cn=$(openssl x509 -in "$1" -noout -subject 2>/dev/null | grep -o "CN *= *[^,/]*" | sed 's/CN *= *//')
    [ "$cn" = "$2" ]
}

assert_cert_has_san() {
    openssl x509 -in "$1" -noout -ext subjectAltName 2>/dev/null | grep -qi "$2"
}

assert_cert_is_ca() {
    openssl x509 -in "$1" -noout -text 2>/dev/null | grep -q "CA:TRUE"
}

assert_cert_signed_by() {
    openssl verify -CAfile "$2" "$1" 2>/dev/null | grep -q "OK"
}

assert_key_matches_cert() {
    local key_mod cert_mod
    key_mod=$(openssl pkey -in "$1" -pubout 2>/dev/null | openssl md5)
    cert_mod=$(openssl x509 -in "$2" -pubkey -noout 2>/dev/null | openssl md5)
    [ "$key_mod" = "$cert_mod" ]
}

echo ""
echo "=== OpenSSL Cheat Sheet — Script Tests ==="
echo ""
echo "Working directory: $WORK_DIR"
echo ""

# ============================================================
echo "--- generate-self-signed.sh ---"
# ============================================================

# Test RSA 2048 (default)
echo ""
echo "  [RSA 2048]"
"$SCRIPT_DIR/generate-self-signed.sh" test.example.com 30 rsa2048 > /dev/null 2>&1
if assert_file_exists certs/test.example.com/server.key; then pass "key created"; else fail "key not created"; fi
if assert_file_exists certs/test.example.com/server.pem; then pass "cert created"; else fail "cert not created"; fi
if assert_file_exists certs/test.example.com/server.csr; then pass "CSR created"; else fail "CSR not created"; fi
if assert_file_exists certs/test.example.com/server.p12; then pass "PKCS#12 created"; else fail "PKCS#12 not created"; fi
if assert_valid_cert certs/test.example.com/server.pem; then pass "cert is valid PEM"; else fail "cert is not valid PEM"; fi
if assert_valid_key certs/test.example.com/server.key; then pass "key is valid"; else fail "key is not valid"; fi
if assert_valid_csr certs/test.example.com/server.csr; then pass "CSR is valid"; else fail "CSR is not valid"; fi
if assert_valid_p12 certs/test.example.com/server.p12; then pass "PKCS#12 is valid"; else fail "PKCS#12 is not valid"; fi
if assert_cert_cn certs/test.example.com/server.pem "test.example.com"; then pass "CN is correct"; else fail "CN is wrong"; fi
if assert_cert_has_san certs/test.example.com/server.pem "test.example.com"; then pass "SAN includes domain"; else fail "SAN missing domain"; fi
if assert_cert_has_san certs/test.example.com/server.pem "127.0.0.1"; then pass "SAN includes 127.0.0.1"; else fail "SAN missing 127.0.0.1"; fi
if assert_key_matches_cert certs/test.example.com/server.key certs/test.example.com/server.pem; then pass "key matches cert"; else fail "key does not match cert"; fi
rm -rf certs/test.example.com

# Test RSA 4096
echo ""
echo "  [RSA 4096]"
"$SCRIPT_DIR/generate-self-signed.sh" rsa4096.test 365 rsa4096 > /dev/null 2>&1
if assert_valid_cert certs/rsa4096.test/server.pem; then pass "RSA 4096 cert valid"; else fail "RSA 4096 cert invalid"; fi
KEY_BITS=$(openssl rsa -in certs/rsa4096.test/server.key -text -noout 2>/dev/null | grep "Private-Key" | grep -oE "[0-9]+" | head -1)
if [ "$KEY_BITS" = "4096" ]; then pass "key is 4096 bits"; else fail "key is not 4096 bits (got $KEY_BITS)"; fi
rm -rf certs/rsa4096.test

# Test ECDSA
echo ""
echo "  [ECDSA P-256]"
"$SCRIPT_DIR/generate-self-signed.sh" ecdsa.test 365 ecdsa > /dev/null 2>&1
if assert_valid_cert certs/ecdsa.test/server.pem; then pass "ECDSA cert valid"; else fail "ECDSA cert invalid"; fi
if assert_valid_key certs/ecdsa.test/server.key; then pass "ECDSA key valid"; else fail "ECDSA key invalid"; fi
if openssl ec -in certs/ecdsa.test/server.key -text -noout 2>/dev/null | grep -q "prime256v1\|P-256"; then pass "key is P-256"; else fail "key is not P-256"; fi
rm -rf certs/ecdsa.test

# Test ECDSA P-384
echo ""
echo "  [ECDSA P-384]"
"$SCRIPT_DIR/generate-self-signed.sh" ecdsa384.test 365 ecdsa384 > /dev/null 2>&1
if assert_valid_cert certs/ecdsa384.test/server.pem; then pass "ECDSA P-384 cert valid"; else fail "ECDSA P-384 cert invalid"; fi
if openssl ec -in certs/ecdsa384.test/server.key -text -noout 2>/dev/null | grep -q "secp384r1\|P-384"; then pass "key is P-384"; else fail "key is not P-384"; fi
rm -rf certs/ecdsa384.test

# Test Ed25519
echo ""
echo "  [Ed25519]"
"$SCRIPT_DIR/generate-self-signed.sh" ed25519.test 365 ed25519 > /dev/null 2>&1
if assert_valid_cert certs/ed25519.test/server.pem; then pass "Ed25519 cert valid"; else fail "Ed25519 cert invalid"; fi
if assert_valid_key certs/ed25519.test/server.key; then pass "Ed25519 key valid"; else fail "Ed25519 key invalid"; fi
rm -rf certs/ed25519.test

# Test invalid key type
echo ""
echo "  [Invalid key type]"
if "$SCRIPT_DIR/generate-self-signed.sh" bad.test 30 badtype > /dev/null 2>&1; then fail "should reject invalid key type"; else pass "rejects invalid key type"; fi

# Test custom days
echo ""
echo "  [Custom duration]"
"$SCRIPT_DIR/generate-self-signed.sh" days.test 7 > /dev/null 2>&1
EXPIRY_DATE=$(openssl x509 -in certs/days.test/server.pem -noout -enddate 2>/dev/null | cut -d= -f2)
if [ -n "$EXPIRY_DATE" ]; then pass "custom duration accepted"; else fail "custom duration failed"; fi
rm -rf certs/days.test

# ============================================================
echo ""
echo "--- generate-ca.sh ---"
# ============================================================

echo ""
echo "  [Create CA]"
CA_PASS=testpassword "$SCRIPT_DIR/generate-ca.sh" "Test Organization" 3650 > /dev/null 2>&1
if assert_file_exists ca/ca.key; then pass "CA key created"; else fail "CA key not created"; fi
if assert_file_exists ca/ca.pem; then pass "CA cert created"; else fail "CA cert not created"; fi
if assert_file_exists ca/ca.srl; then pass "CA serial created"; else fail "CA serial not created"; fi
if assert_valid_cert ca/ca.pem; then pass "CA cert is valid PEM"; else fail "CA cert is not valid PEM"; fi
if assert_cert_is_ca ca/ca.pem; then pass "cert has CA:TRUE"; else fail "cert missing CA:TRUE"; fi
if assert_cert_cn ca/ca.pem "Test Organization Root CA"; then pass "CA CN is correct"; else fail "CA CN is wrong"; fi

# Test duplicate CA prevention
echo ""
echo "  [Duplicate CA prevention]"
if CA_PASS=testpassword "$SCRIPT_DIR/generate-ca.sh" "Duplicate" > /dev/null 2>&1; then fail "should reject duplicate CA"; else pass "rejects duplicate CA"; fi

# ============================================================
echo ""
echo "--- sign-with-ca.sh ---"
# ============================================================

echo ""
echo "  [Sign RSA cert]"
CA_PASS=testpassword "$SCRIPT_DIR/sign-with-ca.sh" signed.example.com 365 rsa2048 > /dev/null 2>&1
if assert_file_exists certs/signed.example.com/server.pem; then pass "signed cert created"; else fail "signed cert not created"; fi
if assert_file_exists certs/signed.example.com/server.key; then pass "signed key created"; else fail "signed key not created"; fi
if assert_file_exists certs/signed.example.com/fullchain.pem; then pass "fullchain created"; else fail "fullchain not created"; fi
if assert_valid_cert certs/signed.example.com/server.pem; then pass "signed cert is valid"; else fail "signed cert is invalid"; fi
if assert_cert_cn certs/signed.example.com/server.pem "signed.example.com"; then pass "signed CN is correct"; else fail "signed CN is wrong"; fi
if assert_cert_signed_by certs/signed.example.com/server.pem ca/ca.pem; then pass "cert verified against CA"; else fail "cert does not verify against CA"; fi
if assert_key_matches_cert certs/signed.example.com/server.key certs/signed.example.com/server.pem; then pass "key matches signed cert"; else fail "key does not match signed cert"; fi
if assert_cert_has_san certs/signed.example.com/server.pem "signed.example.com"; then pass "signed cert has SAN"; else fail "signed cert missing SAN"; fi

# Verify fullchain
echo ""
echo "  [Fullchain validation]"
CHAIN_CERTS=$(grep -c "BEGIN CERTIFICATE" certs/signed.example.com/fullchain.pem)
if [ "$CHAIN_CERTS" -eq 2 ]; then pass "fullchain has 2 certs"; else fail "fullchain has $CHAIN_CERTS certs (expected 2)"; fi
rm -rf certs/signed.example.com

# Test ECDSA signing
echo ""
echo "  [Sign ECDSA cert]"
CA_PASS=testpassword "$SCRIPT_DIR/sign-with-ca.sh" ecdsa-signed.test 365 ecdsa > /dev/null 2>&1
if assert_cert_signed_by certs/ecdsa-signed.test/server.pem ca/ca.pem; then pass "ECDSA cert verified against CA"; else fail "ECDSA cert does not verify"; fi
rm -rf certs/ecdsa-signed.test

# Test missing CA
echo ""
echo "  [Missing CA detection]"
rm -rf ca
if "$SCRIPT_DIR/sign-with-ca.sh" noCA.test > /dev/null 2>&1; then fail "should fail without CA"; else pass "fails without CA"; fi

# ============================================================
echo ""
echo "--- generate-mtls.sh ---"
# ============================================================

echo ""
echo "  [Generate mTLS set]"
"$SCRIPT_DIR/generate-mtls.sh" mtls.example.com my-service > /dev/null 2>&1
if assert_file_exists mtls/ca.pem; then pass "mTLS CA created"; else fail "mTLS CA not created"; fi
if assert_file_exists mtls/ca.key; then pass "mTLS CA key created"; else fail "mTLS CA key not created"; fi
if assert_file_exists mtls/server.pem; then pass "mTLS server cert created"; else fail "mTLS server cert not created"; fi
if assert_file_exists mtls/server.key; then pass "mTLS server key created"; else fail "mTLS server key not created"; fi
if assert_file_exists mtls/client.pem; then pass "mTLS client cert created"; else fail "mTLS client cert not created"; fi
if assert_file_exists mtls/client.key; then pass "mTLS client key created"; else fail "mTLS client key not created"; fi
if assert_file_exists mtls/client.p12; then pass "mTLS client PKCS#12 created"; else fail "mTLS client PKCS#12 not created"; fi

# Validate all certs
if assert_valid_cert mtls/ca.pem; then pass "mTLS CA cert valid"; else fail "mTLS CA cert invalid"; fi
if assert_valid_cert mtls/server.pem; then pass "mTLS server cert valid"; else fail "mTLS server cert invalid"; fi
if assert_valid_cert mtls/client.pem; then pass "mTLS client cert valid"; else fail "mTLS client cert invalid"; fi
if assert_cert_is_ca mtls/ca.pem; then pass "mTLS CA has CA:TRUE"; else fail "mTLS CA missing CA:TRUE"; fi

# Verify trust chain
if assert_cert_signed_by mtls/server.pem mtls/ca.pem; then pass "server cert signed by CA"; else fail "server cert not signed by CA"; fi
if assert_cert_signed_by mtls/client.pem mtls/ca.pem; then pass "client cert signed by CA"; else fail "client cert not signed by CA"; fi

# Check CNs
if assert_cert_cn mtls/server.pem "mtls.example.com"; then pass "server CN correct"; else fail "server CN wrong"; fi
if assert_cert_cn mtls/client.pem "my-service"; then pass "client CN correct"; else fail "client CN wrong"; fi

# Check server has serverAuth, client has clientAuth
if openssl x509 -in mtls/server.pem -noout -text 2>/dev/null | grep -q "TLS Web Server Authentication"; then pass "server has serverAuth"; else fail "server missing serverAuth"; fi
if openssl x509 -in mtls/client.pem -noout -text 2>/dev/null | grep -q "TLS Web Client Authentication"; then pass "client has clientAuth"; else fail "client missing clientAuth"; fi

# Check server SANs
if assert_cert_has_san mtls/server.pem "mtls.example.com"; then pass "server has domain SAN"; else fail "server missing domain SAN"; fi
if assert_cert_has_san mtls/server.pem "localhost"; then pass "server has localhost SAN"; else fail "server missing localhost SAN"; fi

# Verify PKCS#12
if assert_valid_p12 mtls/client.p12; then pass "client PKCS#12 valid"; else fail "client PKCS#12 invalid"; fi

# No CSR or SRL files left behind
if ls mtls/*.csr 2>/dev/null | grep -q .; then fail "CSR files not cleaned up"; else pass "CSR files cleaned up"; fi
if ls mtls/*.srl 2>/dev/null | grep -q .; then fail "SRL files not cleaned up"; else pass "SRL files cleaned up"; fi

rm -rf mtls

# ============================================================
echo ""
echo "--- check-cert.sh ---"
# ============================================================

echo ""
echo "  [Check remote cert]"
OUTPUT=$("$SCRIPT_DIR/check-cert.sh" google.com 2>&1) || true
if echo "$OUTPUT" | grep -q "SSL Certificate Check"; then pass "script runs"; else fail "script did not run"; fi
# Network-dependent checks — skip if no cert data (e.g., corporate proxy)
if echo "$OUTPUT" | grep -q "Identity\|Subject\|subject"; then
    pass "shows cert info"
    if echo "$OUTPUT" | grep -qi "google"; then pass "found Google in cert"; else fail "did not find Google in cert"; fi
else
    echo "  SKIP: no cert data (network/proxy issue)"
fi

# Test unreachable host
echo ""
echo "  [Unreachable host]"
if "$SCRIPT_DIR/check-cert.sh" definitely.not.a.real.host.example 2>/dev/null; then fail "should fail on unreachable host"; else pass "fails on unreachable host"; fi

# ============================================================
echo ""
echo "--- test-mtls.sh ---"
# ============================================================

echo ""
echo "  [Missing certs detection]"
if "$SCRIPT_DIR/test-mtls.sh" https://localhost ./nonexistent 2>/dev/null; then fail "should fail with missing certs"; else pass "fails with missing cert dir"; fi

# ============================================================
echo ""
echo "--- curl-ssl-examples.sh ---"
# ============================================================

echo ""
echo "  [Prints reference]"
OUTPUT=$("$SCRIPT_DIR/curl-ssl-examples.sh" 2>&1)
if echo "$OUTPUT" | grep -q "Client Certificates"; then pass "shows mTLS section"; else fail "missing mTLS section"; fi
if echo "$OUTPUT" | grep -q "getaCert.com"; then pass "shows getaCert examples"; else fail "missing getaCert examples"; fi
if echo "$OUTPUT" | grep -q "TLS Version"; then pass "shows TLS version section"; else fail "missing TLS version section"; fi

# ============================================================
echo ""
echo "==========================================="
echo ""
echo "  Results: $PASS passed, $FAIL failed"
echo ""
if [ $FAIL -gt 0 ]; then
    echo "  Failures:"
    echo -e "$ERRORS"
    echo ""
    exit 1
else
    echo "  All tests passed!"
    echo ""
fi
