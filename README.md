# OpenSSL Cheat Sheet

[![License: CC BY 4.0](https://img.shields.io/badge/License-CC_BY_4.0-lightgrey.svg)](https://creativecommons.org/licenses/by/4.0/)

The most common OpenSSL commands in one place — generate keys, create certificates, decode, convert, troubleshoot, and test SSL/TLS. Bookmark this and never Google an OpenSSL command again.

> **Want to skip the command line?** [getaCert.com](https://getacert.com) does all of this from your browser — no installs, no flags to memorize. Free since 2005.

---

## Table of Contents

- [Generate Private Keys](#generate-private-keys)
- [Generate a CSR](#generate-a-csr)
- [Generate a Self-Signed Certificate](#generate-a-self-signed-certificate)
- [Wildcard and Multi-Domain Certificates](#wildcard-and-multi-domain-certificates)
- [Decode and View Certificates](#decode-and-view-certificates)
- [Decode and View CSRs](#decode-and-view-csrs)
- [Check a Remote Server's Certificate](#check-a-remote-servers-certificate)
- [Convert Certificate Formats](#convert-certificate-formats)
- [PKCS#12 / PFX Bundles](#pkcs12--pfx-bundles)
- [Verify and Validate](#verify-and-validate)
- [CA Operations](#ca-operations)
- [mTLS (Mutual TLS)](#mtls-mutual-tls)
- [Testing with curl](#testing-with-curl)
- [Common Errors and Fixes](#common-errors-and-fixes)
- [OpenSSL Gotchas](#openssl-gotchas)
- [Quick Reference Table](#quick-reference-table)
- [Helper Scripts](#helper-scripts)

---

## Generate Private Keys

### RSA

```bash
# RSA 2048-bit (standard, widely compatible)
openssl genrsa -out server.key 2048

# RSA 4096-bit (stronger, slower handshake)
openssl genrsa -out server.key 4096

# RSA with passphrase protection
openssl genrsa -aes256 -out server.key 2048
```

### ECDSA

```bash
# ECDSA P-256 (fast, small key, widely supported — recommended)
openssl ecparam -genkey -name prime256v1 -noout -out server.key

# ECDSA P-384 (stronger, slightly slower)
openssl ecparam -genkey -name secp384r1 -noout -out server.key

# List all available curves
openssl ecparam -list_curves
```

### Ed25519

```bash
# Ed25519 (smallest key, fastest — not supported by all software yet)
openssl genpkey -algorithm Ed25519 -out server.key
```

### Key management

```bash
# Remove passphrase from a key
openssl rsa -in encrypted.key -out decrypted.key

# Add passphrase to an unencrypted key
openssl rsa -aes256 -in decrypted.key -out encrypted.key

# View key details (RSA)
openssl rsa -in server.key -text -noout

# View key details (ECDSA)
openssl ec -in server.key -text -noout

# Check key length
openssl rsa -in server.key -text -noout | grep "Private-Key"
```

### Which key type should I use?

| Type | Key Size | TLS Handshake | Compatibility | Best For |
|------|----------|--------------|---------------|----------|
| RSA 2048 | 2048 bits | ~5ms | Everything | Maximum compatibility |
| RSA 4096 | 4096 bits | ~15ms | Everything | High security requirements |
| ECDSA P-256 | 256 bits | ~1ms | Modern clients | Performance + security |
| ECDSA P-384 | 384 bits | ~2ms | Modern clients | Government / compliance |
| Ed25519 | 256 bits | <1ms | Limited | Cutting edge, internal use |

---

## Generate a CSR

### Interactive (prompts for each field)

```bash
openssl req -new -key server.key -out server.csr
```

### One-liner with subject

```bash
openssl req -new -key server.key -out server.csr \
  -subj "/C=US/ST=Washington/L=Seattle/O=My Company/CN=www.example.com"
```

### CSR with Subject Alternative Names (SANs)

```bash
openssl req -new -key server.key -out server.csr \
  -subj "/CN=www.example.com" \
  -addext "subjectAltName=DNS:www.example.com,DNS:example.com,DNS:api.example.com"
```

### Generate key and CSR in one step

```bash
openssl req -new -newkey rsa:2048 -nodes -keyout server.key -out server.csr \
  -subj "/C=US/ST=Washington/L=Seattle/O=My Company/CN=www.example.com"
```

### CSR with config file (for complex SANs)

Create `csr.cnf`:
```ini
[req]
default_bits = 2048
prompt = no
distinguished_name = dn
req_extensions = v3_req

[dn]
C = US
ST = Washington
L = Seattle
O = My Company
CN = www.example.com

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = www.example.com
DNS.2 = example.com
DNS.3 = api.example.com
DNS.4 = *.example.com
IP.1 = 10.0.0.1
IP.2 = 192.168.1.100
```

```bash
openssl req -new -key server.key -out server.csr -config csr.cnf
```

> **Easier way:** Paste your CSR at [getaCert.com/signcsr](https://getacert.com/signcsr) to get it signed instantly, or generate a complete certificate set at [getaCert.com/selfsign](https://getacert.com/selfsign) — key, CSR, cert, and PKCS#12 in one click.

---

## Generate a Self-Signed Certificate

### Basic (30 days)

```bash
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout server.key -out server.pem -days 30 \
  -subj "/CN=www.example.com"
```

### With SANs (required by Chrome and modern browsers)

```bash
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout server.key -out server.pem -days 365 \
  -subj "/CN=www.example.com" \
  -addext "subjectAltName=DNS:www.example.com,DNS:localhost,IP:127.0.0.1"
```

### Localhost development certificate

```bash
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout localhost.key -out localhost.pem -days 365 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,DNS:*.localhost,IP:127.0.0.1,IP:::1"
```

### With full subject details and extensions

```bash
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout server.key -out server.pem -days 365 \
  -subj "/C=US/ST=Washington/L=Seattle/O=My Company/OU=Engineering/CN=www.example.com" \
  -addext "subjectAltName=DNS:www.example.com,DNS:example.com" \
  -addext "basicConstraints=CA:FALSE" \
  -addext "keyUsage=digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth"
```

### From an existing key and CSR

```bash
openssl x509 -req -in server.csr -signkey server.key -out server.pem -days 365
```

### ECDSA self-signed cert (one step)

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout server.key -out server.pem -days 365 \
  -subj "/CN=www.example.com" \
  -addext "subjectAltName=DNS:www.example.com"
```

> **Easier way:** [getaCert.com/selfsign](https://getacert.com/selfsign) generates the key, CSR, certificate, and PKCS#12 bundle in one click. Supports RSA 2048/4096, ECDSA P-256/P-384, and Ed25519.

---

## Wildcard and Multi-Domain Certificates

### Wildcard certificate

```bash
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout wildcard.key -out wildcard.pem -days 365 \
  -subj "/CN=*.example.com" \
  -addext "subjectAltName=DNS:*.example.com,DNS:example.com"
```

> **Note:** Wildcard certs cover `*.example.com` (one level) but NOT `example.com` itself — always include both in the SAN.

### Multi-domain (UCC/SAN) certificate

```bash
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout multi.key -out multi.pem -days 365 \
  -subj "/CN=example.com" \
  -addext "subjectAltName=DNS:example.com,DNS:www.example.com,DNS:app.example.com,DNS:api.example.com,DNS:other-domain.com"
```

### Mixed wildcard + specific domains

```bash
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout combo.key -out combo.pem -days 365 \
  -subj "/CN=example.com" \
  -addext "subjectAltName=DNS:example.com,DNS:*.example.com,DNS:other-domain.com,DNS:*.other-domain.com"
```

> **Easier way:** [getaCert.com/selfsign](https://getacert.com/selfsign) supports up to 3 SAN domains + 1 IP address per certificate, with wildcard support.

---

## Decode and View Certificates

### View all certificate details

```bash
openssl x509 -in server.pem -text -noout
```

### View just the subject and issuer

```bash
openssl x509 -in server.pem -subject -issuer -noout
```

### View expiry dates

```bash
openssl x509 -in server.pem -dates -noout
```

### Check if a certificate is expired

```bash
openssl x509 -in server.pem -checkend 0 -noout
# Exit code 0 = still valid, 1 = expired

# Check if it expires within 30 days
openssl x509 -in server.pem -checkend 2592000 -noout
```

### View SANs

```bash
openssl x509 -in server.pem -noout -ext subjectAltName
```

### View serial number and fingerprint

```bash
openssl x509 -in server.pem -serial -fingerprint -noout

# SHA-256 fingerprint (more common now)
openssl x509 -in server.pem -fingerprint -sha256 -noout
```

### View certificate purpose / key usage

```bash
openssl x509 -in server.pem -purpose -noout
```

### View certificate in a specific format

```bash
# Output as DER (binary)
openssl x509 -in server.pem -outform DER -out server.der

# Output just the public key
openssl x509 -in server.pem -pubkey -noout
```

> **Easier way:** Paste any PEM certificate at [getaCert.com/viewcert](https://getacert.com/viewcert) to see all fields in a clean, readable format.

---

## Decode and View CSRs

### View CSR details

```bash
openssl req -in server.csr -text -noout
```

### Verify a CSR's signature

```bash
openssl req -in server.csr -verify -noout
```

### View just the subject

```bash
openssl req -in server.csr -subject -noout
```

### Extract the public key from a CSR

```bash
openssl req -in server.csr -pubkey -noout
```

> **Easier way:** Paste any CSR at [getaCert.com/decodecsr](https://getacert.com/decodecsr) to view all parsed fields including SANs, key type, and signature algorithm.

---

## Check a Remote Server's Certificate

### View a server's certificate

```bash
openssl s_client -connect example.com:443 -servername example.com </dev/null 2>/dev/null | \
  openssl x509 -text -noout
```

### Check expiry date

```bash
echo | openssl s_client -connect example.com:443 -servername example.com 2>/dev/null | \
  openssl x509 -noout -dates
```

### View the full certificate chain

```bash
openssl s_client -connect example.com:443 -servername example.com -showcerts </dev/null
```

### Check a specific port

```bash
# HTTPS (443)
openssl s_client -connect example.com:443 </dev/null

# SMTP with STARTTLS (587)
openssl s_client -connect mail.example.com:587 -starttls smtp </dev/null

# IMAP with STARTTLS (143)
openssl s_client -connect mail.example.com:143 -starttls imap </dev/null

# FTP with STARTTLS (21)
openssl s_client -connect ftp.example.com:21 -starttls ftp </dev/null

# MySQL (3306)
openssl s_client -connect db.example.com:3306 -starttls mysql </dev/null

# PostgreSQL (5432)
openssl s_client -connect db.example.com:5432 -starttls postgres </dev/null
```

### Test TLS version support

```bash
# Test TLS 1.2
openssl s_client -connect example.com:443 -tls1_2 </dev/null 2>&1 | head -5

# Test TLS 1.3
openssl s_client -connect example.com:443 -tls1_3 </dev/null 2>&1 | head -5
```

### View negotiated cipher and protocol

```bash
echo | openssl s_client -connect example.com:443 2>/dev/null | \
  grep -E "Protocol|Cipher"
```

### Check certificate with SNI (Server Name Indication)

```bash
# Important for shared hosting — without -servername you may get the wrong cert
openssl s_client -connect 93.184.216.34:443 -servername example.com </dev/null 2>/dev/null | \
  openssl x509 -noout -subject -issuer
```

### One-liner: check days until expiry

```bash
echo | openssl s_client -connect example.com:443 -servername example.com 2>/dev/null | \
  openssl x509 -noout -enddate | cut -d= -f2 | \
  xargs -I{} bash -c 'echo $(( ($(date -d "{}" +%s) - $(date +%s)) / 86400 )) days'
```

> **Easier way:** [getaCert.com/check](https://getacert.com/check) checks any domain's certificate, chain, TLS version, cipher suites, and HSTS status — all from your browser with a clean visual output.

---

## Convert Certificate Formats

### PEM to DER

```bash
# Certificate
openssl x509 -in cert.pem -outform DER -out cert.der

# Private key
openssl rsa -in key.pem -outform DER -out key.der
```

### DER to PEM

```bash
# Certificate
openssl x509 -in cert.der -inform DER -outform PEM -out cert.pem

# Private key
openssl rsa -in key.der -inform DER -outform PEM -out key.pem
```

### PEM to PKCS#7

```bash
# Single certificate
openssl crl2pkcs7 -nocrl -certfile cert.pem -out cert.p7b

# With CA chain
openssl crl2pkcs7 -nocrl -certfile cert.pem -certfile ca.pem -out cert.p7b
```

### PKCS#7 to PEM

```bash
openssl pkcs7 -in cert.p7b -print_certs -out cert.pem
```

### PEM key to PKCS#8

```bash
# Unencrypted
openssl pkcs8 -topk8 -in server.key -out server-pkcs8.key -nocrypt

# Encrypted
openssl pkcs8 -topk8 -in server.key -out server-pkcs8.key -v2 aes-256-cbc
```

### Convert to Java KeyStore (JKS)

```bash
# Step 1: Create PKCS#12
openssl pkcs12 -export -out keystore.p12 \
  -inkey server.key -in server.pem -certfile ca.pem \
  -passout pass:changeit

# Step 2: Import into JKS
keytool -importkeystore \
  -srckeystore keystore.p12 -srcstoretype PKCS12 -srcstorepass changeit \
  -destkeystore keystore.jks -deststoretype JKS -deststorepass changeit
```

> **Easier way:** [getaCert.com/convert](https://getacert.com/convert) converts between PEM, DER, and PKCS#7 formats — upload your file and download the result.

---

## PKCS#12 / PFX Bundles

### Create a PKCS#12 bundle

```bash
# Basic (cert + key)
openssl pkcs12 -export -out cert.p12 \
  -inkey server.key -in server.pem \
  -passout pass:mypassword

# With CA chain (recommended)
openssl pkcs12 -export -out cert.p12 \
  -inkey server.key -in server.pem -certfile ca.pem \
  -passout pass:mypassword

# With a friendly name (shows up in Windows cert manager)
openssl pkcs12 -export -out cert.p12 \
  -inkey server.key -in server.pem -certfile ca.pem \
  -name "My Server Certificate" \
  -passout pass:mypassword
```

### Extract from PKCS#12

```bash
# Extract certificate
openssl pkcs12 -in cert.p12 -clcerts -nokeys -out cert.pem -passin pass:mypassword

# Extract private key (decrypted)
openssl pkcs12 -in cert.p12 -nocerts -nodes -out server.key -passin pass:mypassword

# Extract CA certificates
openssl pkcs12 -in cert.p12 -cacerts -nokeys -out ca.pem -passin pass:mypassword

# Extract everything
openssl pkcs12 -in cert.p12 -out everything.pem -nodes -passin pass:mypassword
```

### View PKCS#12 contents

```bash
openssl pkcs12 -in cert.p12 -info -nodes -passin pass:mypassword
```

---

## Verify and Validate

### Verify a certificate against a CA

```bash
openssl verify -CAfile ca.pem server.pem
```

### Verify a certificate chain

```bash
openssl verify -CAfile root-ca.pem -untrusted intermediate.pem server.pem
```

### Verify against the system trust store

```bash
openssl verify server.pem
```

### Check that a private key matches a certificate

```bash
# If the outputs match, the key and cert are a pair
openssl x509 -in server.pem -noout -modulus | openssl md5
openssl rsa -in server.key -noout -modulus | openssl md5
```

### Check that a CSR matches a private key

```bash
openssl req -in server.csr -noout -modulus | openssl md5
openssl rsa -in server.key -noout -modulus | openssl md5
```

### Check that a CSR matches a certificate

```bash
openssl x509 -in server.pem -noout -modulus | openssl md5
openssl req -in server.csr -noout -modulus | openssl md5
```

> **Easier way:** [getaCert.com/chaincheck](https://getacert.com/chaincheck) validates your full certificate chain, detects ordering issues, and identifies missing intermediates.

---

## CA Operations

### Create a root CA

```bash
# Generate CA private key (keep this safe!)
openssl genrsa -aes256 -out ca.key 4096

# Generate CA certificate (10 years)
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 \
  -out ca.pem -subj "/C=US/ST=Washington/O=My Organization/CN=My Root CA"
```

### Sign a CSR with your CA

```bash
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key \
  -CAcreateserial -out server.pem -days 365 -sha256
```

### Sign with SANs preserved

```bash
# The -copy_extensions flag copies SANs from the CSR to the certificate
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key \
  -CAcreateserial -out server.pem -days 365 -sha256 \
  -copy_extensions copyall
```

### Sign with explicit extensions

```bash
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key \
  -CAcreateserial -out server.pem -days 365 -sha256 \
  -extfile <(printf "subjectAltName=DNS:www.example.com,DNS:example.com\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth")
```

### Create an intermediate CA

```bash
# Generate intermediate key
openssl genrsa -aes256 -out intermediate.key 4096

# Generate intermediate CSR
openssl req -new -key intermediate.key -out intermediate.csr \
  -subj "/C=US/ST=Washington/O=My Organization/CN=My Intermediate CA"

# Sign with root CA
openssl x509 -req -in intermediate.csr -CA ca.pem -CAkey ca.key \
  -CAcreateserial -out intermediate.pem -days 1825 -sha256 \
  -extfile <(printf "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,digitalSignature,cRLSign,keyCertSign")

# Create the chain file
cat intermediate.pem ca.pem > chain.pem
```

> **Managing a CA with OpenSSL is painful.** Serial numbers, index files, config files, revocation lists — it's a lot of overhead for signing a few certs. [getaCert.com](https://getacert.com) handles all of this for you, including a [REST API](https://getacert.com/about) for programmatic cert generation with a single HTTP request.

---

## mTLS (Mutual TLS)

Mutual TLS requires both the server and client to present certificates. Useful for service-to-service authentication, API security, and zero-trust architectures.

### Generate a client certificate

```bash
# Generate client key
openssl genrsa -out client.key 2048

# Generate client CSR
openssl req -new -key client.key -out client.csr \
  -subj "/CN=my-service/O=My Company"

# Sign with your CA
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca.key \
  -CAcreateserial -out client.pem -days 365 -sha256 \
  -extfile <(printf "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth")

# Create PKCS#12 for the client
openssl pkcs12 -export -out client.p12 \
  -inkey client.key -in client.pem -certfile ca.pem \
  -passout pass:clientpass
```

### Configure nginx for mTLS

```nginx
server {
    listen 443 ssl;
    server_name api.example.com;

    ssl_certificate     /etc/ssl/server.pem;
    ssl_certificate_key /etc/ssl/server.key;

    # mTLS: require client certificate
    ssl_client_certificate /etc/ssl/ca.pem;
    ssl_verify_client on;

    # Optional: pass client CN to backend
    proxy_set_header X-Client-CN $ssl_client_s_dn_cn;
}
```

### Test mTLS with curl

```bash
# With PEM files
curl --cert client.pem --key client.key --cacert ca.pem https://api.example.com

# With PKCS#12
curl --cert-type P12 --cert client.p12:clientpass --cacert ca.pem https://api.example.com
```

> **Easier way:** [getaCert.com/mtls](https://getacert.com/mtls) provides a live mTLS test endpoint with paired certificate generation — generate a client cert and test mutual TLS in seconds.

---

## Testing with curl

### Test with a self-signed certificate

```bash
# Skip certificate verification (development only!)
curl -k https://localhost:8443

# Better: trust your CA certificate
curl --cacert ca.pem https://localhost:8443
```

### Test with client certificate authentication

```bash
curl --cert client.pem --key client.key https://api.example.com
```

### View TLS handshake details

```bash
curl -v --trace-time https://example.com 2>&1 | grep -E "SSL|TLS|subject|issuer|expire"
```

### Test specific TLS versions

```bash
# Force TLS 1.2
curl --tlsv1.2 --tls-max 1.2 https://example.com

# Force TLS 1.3
curl --tlsv1.3 https://example.com
```

### Download a server's certificate with curl

```bash
# Save the server certificate
echo | openssl s_client -connect example.com:443 -servername example.com 2>/dev/null | \
  sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' > server.pem
```

---

## Common Errors and Fixes

### `unable to load certificate`

```
unable to load certificate
140234873498560:error:0906D06C:PEM routines:PEM_read_bio:no start line
```

**Cause:** The file is not in PEM format, or it's DER-encoded.

```bash
# Convert DER to PEM
openssl x509 -in cert.der -inform DER -out cert.pem

# Or check if the file is actually PEM
file cert.pem
head -1 cert.pem   # Should show -----BEGIN CERTIFICATE-----
```

### `unable to get local issuer certificate`

```
error 20 at 0 depth lookup: unable to get local issuer certificate
```

**Cause:** The CA certificate is missing from the trust chain.

```bash
# Verify with the CA cert explicitly
openssl verify -CAfile ca.pem server.pem

# Or build the full chain
cat server.pem intermediate.pem root.pem > fullchain.pem
```

### `certificate has expired`

```
error 10 at 0 depth lookup: certificate has expired
```

```bash
# Check the actual dates
openssl x509 -in server.pem -noout -dates

# Check days remaining
openssl x509 -in server.pem -checkend 0 -noout && echo "Valid" || echo "Expired"
```

### `key values mismatch`

**Cause:** The private key doesn't match the certificate.

```bash
# Compare modulus hashes — they must match
openssl x509 -in server.pem -noout -modulus | openssl md5
openssl rsa -in server.key -noout -modulus | openssl md5
```

### `self-signed certificate` or `self-signed certificate in certificate chain`

**Cause:** The server is sending a self-signed cert or the root CA is in the chain (it shouldn't be).

```bash
# Check who signed the certificate
openssl x509 -in server.pem -noout -issuer -subject

# If issuer == subject, it's self-signed
```

### `certificate is not yet valid`

**Cause:** The certificate's `notBefore` date is in the future. Often a system clock issue.

```bash
# Check the not-before date
openssl x509 -in server.pem -noout -startdate

# Check your system clock
date -u
```

### `wrong version number` or `unsupported protocol`

**Cause:** Connecting with TLS to a non-TLS port, or TLS version mismatch.

```bash
# Make sure you're connecting to the right port
openssl s_client -connect example.com:443 </dev/null

# For STARTTLS services, specify the protocol
openssl s_client -connect mail.example.com:587 -starttls smtp </dev/null
```

### `no peer certificate available`

**Cause:** The server didn't present a certificate. Could be wrong port, wrong hostname, or the server isn't configured for TLS.

```bash
# Use -servername for SNI
openssl s_client -connect example.com:443 -servername example.com </dev/null
```

### `Mac verify error: invalid password?`

**Cause:** Wrong password for a PKCS#12 file.

```bash
# Try with the correct password
openssl pkcs12 -in cert.p12 -info -passin pass:correctpassword

# Common default passwords: "password", "changeit", "" (empty)
openssl pkcs12 -in cert.p12 -info -passin pass:
```

---

## OpenSSL Gotchas

Things that trip everyone up:

1. **Chrome requires SANs** — Since 2017, Chrome ignores the CN field. You must have `subjectAltName` or Chrome will show `NET::ERR_CERT_COMMON_NAME_INVALID`. Always use `-addext "subjectAltName=..."`.

2. **Wildcard certs don't cover the apex domain** — `*.example.com` covers `www.example.com` and `api.example.com`, but NOT `example.com`. Include both: `DNS:*.example.com,DNS:example.com`.

3. **Wildcard certs only cover one level** — `*.example.com` does NOT cover `sub.api.example.com`. You need a separate cert or `*.api.example.com`.

4. **`-nodes` means "no DES"** — It's "no-DES", not "nodes". It means don't encrypt the private key. Without it, OpenSSL prompts for a passphrase.

5. **Certificate chain order matters** — The correct order is: server cert → intermediate(s) → root CA. Many servers get this wrong. Some clients are forgiving, others aren't.

6. **`openssl s_client` needs `-servername` for SNI** — Without it, you might get the wrong certificate on shared hosting or CDNs.

7. **DER files have no standard extension** — You'll see `.der`, `.cer`, `.crt` — they could be PEM or DER. Always check with `file cert.cer` or look for `-----BEGIN`.

8. **OpenSSL 3.x changed default providers** — Some legacy algorithms (MD5, older ciphers) require `-legacy` or `-provider legacy` in OpenSSL 3.x.

9. **`-CAcreateserial` creates a `.srl` file** — When signing with a CA, OpenSSL tracks serial numbers in a `.srl` file. Use `-CAcreateserial` the first time, then it auto-increments.

10. **PEM files can contain multiple certs** — A PEM file can hold the cert chain, private key, and CA certs all in one file. Order matters for chain files.

> **More gotchas:** [getaCert.com/gotchas](https://getacert.com/gotchas) has detailed articles on common SSL/TLS pitfalls with solutions.

---

## Quick Reference Table

| Task | Command |
|------|---------|
| Generate RSA 2048 key | `openssl genrsa -out key.pem 2048` |
| Generate ECDSA P-256 key | `openssl ecparam -genkey -name prime256v1 -noout -out key.pem` |
| Generate Ed25519 key | `openssl genpkey -algorithm Ed25519 -out key.pem` |
| Remove key passphrase | `openssl rsa -in enc.key -out dec.key` |
| Generate CSR | `openssl req -new -key key.pem -out req.csr -subj "/CN=example.com"` |
| Generate CSR with SANs | Add `-addext "subjectAltName=DNS:example.com,DNS:www.example.com"` |
| Self-signed cert | `openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 365 -subj "/CN=example.com" -addext "subjectAltName=DNS:example.com"` |
| Localhost dev cert | `openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 365 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"` |
| View certificate | `openssl x509 -in cert.pem -text -noout` |
| View expiry | `openssl x509 -in cert.pem -noout -dates` |
| Check if expired | `openssl x509 -in cert.pem -checkend 0 -noout` |
| View CSR | `openssl req -in req.csr -text -noout` |
| Check remote cert | `echo \| openssl s_client -connect host:443 -servername host 2>/dev/null \| openssl x509 -text -noout` |
| PEM → DER | `openssl x509 -in cert.pem -outform DER -out cert.der` |
| DER → PEM | `openssl x509 -in cert.der -inform DER -out cert.pem` |
| PEM → PKCS#7 | `openssl crl2pkcs7 -nocrl -certfile cert.pem -out cert.p7b` |
| Create PKCS#12 | `openssl pkcs12 -export -out cert.p12 -inkey key.pem -in cert.pem -certfile ca.pem` |
| Extract cert from P12 | `openssl pkcs12 -in cert.p12 -clcerts -nokeys -out cert.pem` |
| Extract key from P12 | `openssl pkcs12 -in cert.p12 -nocerts -nodes -out key.pem` |
| Verify cert chain | `openssl verify -CAfile ca.pem cert.pem` |
| Key matches cert? | Compare: `openssl x509 -modulus \| md5` vs `openssl rsa -modulus \| md5` |
| Sign CSR with CA | `openssl x509 -req -in req.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out cert.pem -days 365` |
| Test mTLS | `curl --cert client.pem --key client.key --cacert ca.pem https://host` |

---

## Helper Scripts

This repo includes ready-to-use bash scripts in the [`scripts/`](scripts/) directory. Clone the repo and run them directly:

```bash
git clone https://github.com/getaCert/openssl-cheatsheet.git
cd openssl-cheatsheet
```

| Script | What It Does |
|--------|-------------|
| [`generate-self-signed.sh`](scripts/generate-self-signed.sh) | Generate a self-signed cert with SANs, key, CSR, and PKCS#12 |
| [`generate-ca.sh`](scripts/generate-ca.sh) | Set up a local Certificate Authority |
| [`sign-with-ca.sh`](scripts/sign-with-ca.sh) | Sign a certificate using your local CA |
| [`generate-mtls.sh`](scripts/generate-mtls.sh) | Generate a full mTLS set (CA + server + client certs) |
| [`test-mtls.sh`](scripts/test-mtls.sh) | Test an mTLS connection with curl (PEM + PKCS#12) |
| [`check-cert.sh`](scripts/check-cert.sh) | Check a remote server's SSL certificate |
| [`curl-ssl-examples.sh`](scripts/curl-ssl-examples.sh) | curl SSL/TLS reference (client certs, pinning, debugging, TLS versions) |

### Examples

```bash
# Generate a self-signed cert for localhost dev
./scripts/generate-self-signed.sh localhost 365 ecdsa

# Set up a CA and sign a cert
./scripts/generate-ca.sh "My Company"
./scripts/sign-with-ca.sh api.internal.com 365 rsa2048

# Generate everything for mTLS testing
./scripts/generate-mtls.sh api.example.com my-service

# Check a remote server
./scripts/check-cert.sh google.com
./scripts/check-cert.sh mail.google.com 587 smtp
```

All scripts support RSA 2048/4096, ECDSA P-256/P-384, and Ed25519. Output goes to `./certs/<domain>/`.

> **Or skip all of this** and use [getaCert.com](https://getacert.com) — same result, zero setup.

---

## About

This cheat sheet is maintained by [getaCert.com](https://getacert.com) — free SSL certificate tools since 2005.

**No installs. No command line. Just your certificate.**

| Tool | What It Does |
|------|-------------|
| [Self-Signed Certificate](https://getacert.com/selfsign) | Generate key + CSR + cert + PKCS#12 instantly |
| [CA-Signed Certificate](https://getacert.com/casign) | Get a cert signed by the getaCert CA |
| [Sign a CSR](https://getacert.com/signcsr) | Paste your CSR, get it signed |
| [Decode Certificate](https://getacert.com/viewcert) | View any PEM certificate's details |
| [Decode CSR](https://getacert.com/decodecsr) | View any CSR's details |
| [SSL Domain Checker](https://getacert.com/check) | Inspect any domain's cert, chain, and TLS config |
| [Certificate Converter](https://getacert.com/convert) | Convert between PEM, DER, and PKCS#7 |
| [Chain Validator](https://getacert.com/chaincheck) | Validate certificate chain ordering |
| [SSL Config Generator](https://getacert.com/sslconfig) | Generate nginx/Apache/HAProxy TLS configs |
| [mTLS Test Endpoint](https://getacert.com/mtls) | Test mutual TLS with generated client certs |
| [Let's Encrypt Proxy](https://getacert.com/letsencrypt) | Get free browser-trusted certs via Let's Encrypt |
| [REST API](https://getacert.com/about) | Generate certs programmatically |

### getaCert Portal

Unlimited certificate generation, saved cert history, REST API access, and up to 10-year validity — all for a **one-time payment of $9.99** (no subscription).

[Get Portal Access →](https://getacert.com/portal)

## Contributing

Found an error? Know a useful OpenSSL command that's missing? PRs welcome.

## License

This cheat sheet is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Share it, fork it, print it out and tape it to your monitor.
