#!/bin/bash
set -euo pipefail

echo "=== SAMLGuard Development Setup ==="
echo ""

# Check prerequisites
command -v go >/dev/null 2>&1 || { echo "ERROR: Go is required but not installed."; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo "ERROR: OpenSSL is required but not installed."; exit 1; }

echo "[1/4] Generating certificates..."
bash scripts/generate-certs.sh

echo "[2/4] Downloading Go dependencies..."
go mod tidy

echo "[3/4] Creating data directory..."
mkdir -p ./data

echo "[4/4] Running database migrations..."
echo "Migrations will run automatically on first service start."

echo ""
echo "=== Setup complete ==="
echo ""
echo "Quick start commands:"
echo ""
echo "  # Run all services with Docker:"
echo "  export MFA_ENCRYPTION_KEY=\$(cat cert/mfa-encryption.key)"
echo "  docker-compose up --build"
echo ""
echo "  # Or run individually for development:"
echo "  go run ./cmd/gateway"
echo "  go run ./cmd/auth"
echo "  go run ./cmd/mfa"
echo "  go run ./cmd/session"
echo "  go run ./cmd/audit"
echo ""
echo "  # Run tests:"
echo "  go test ./... -v"
