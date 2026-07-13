#!/bin/bash
set -euo pipefail

CERT_DIR="./cert"
DAYS=365
KEY_SIZE=2048

echo "=== SAMLGuard Certificate Generator ==="
echo ""

mkdir -p "$CERT_DIR"

echo "[1/4] Generating SAML signing certificate..."
openssl req -x509 -newkey rsa:$KEY_SIZE \
    -keyout "$CERT_DIR/saml-signing.key" \
    -out "$CERT_DIR/saml-signing.crt" \
    -days $DAYS -nodes \
    -subj "/CN=SAMLGuard Signing/O=SAMLGuard/C=US"

echo "[2/4] Generating TLS server certificate..."
openssl req -x509 -newkey rsa:$KEY_SIZE \
    -keyout "$CERT_DIR/server.key" \
    -out "$CERT_DIR/server.crt" \
    -days $DAYS -nodes \
    -subj "/CN=samlguard.example.com/O=SAMLGuard/C=US" \
    -addext "subjectAltName=DNS:samlguard.example.com,DNS:localhost,IP:127.0.0.1"

echo "[3/4] Generating JWT signing keys..."
openssl genpkey -algorithm RSA -out "$CERT_DIR/jwt-private.pem" -pkeyopt rsa_keygen_bits:$KEY_SIZE
openssl rsa -pubout -in "$CERT_DIR/jwt-private.pem" -out "$CERT_DIR/jwt-public.pem"

echo "[4/4] Generating MFA encryption key..."
MFA_KEY=$(openssl rand -hex 32)
echo "$MFA_KEY" > "$CERT_DIR/mfa-encryption.key"

echo ""
echo "=== Certificates generated successfully ==="
echo ""
echo "Files created in $CERT_DIR/:"
ls -la "$CERT_DIR/"
echo ""
echo "MFA Encryption Key: $MFA_KEY"
echo ""
echo "IMPORTANT: These are self-signed certificates for development only."
echo "For production, use certificates from a trusted Certificate Authority."
echo ""
echo "Set the following environment variable for Docker:"
echo "  export MFA_ENCRYPTION_KEY=$MFA_KEY"
