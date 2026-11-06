#!/usr/bin/env bash
set -euo pipefail

# SAMLGuard Linux Automated Installation Script
# Usage: sudo ./install.sh [binary_path]

BINARY_SRC="${1:-./bin/samlguard}"

if [[ $EUID -ne 0 ]]; then
   echo "Error: This script must be run as root." >&2
   exit 1
fi

if [[ ! -f "$BINARY_SRC" ]]; then
    echo "Error: Binary not found at $BINARY_SRC" >&2
    exit 1
fi

echo "==> Creating dedicated system user 'samlguard'..."
if ! id -u samlguard >/dev/null 2>&1; then
    useradd -r -s /bin/false -d /var/lib/samlguard -c "SAMLGuard Service User" samlguard
fi

echo "==> Setting up directories..."
mkdir -p /usr/local/bin
mkdir -p /etc/samlguard/cert
mkdir -p /var/lib/samlguard

echo "==> Installing binary to /usr/local/bin/samlguard..."
install -m 0755 "$BINARY_SRC" /usr/local/bin/samlguard

# Allow unprivileged binding to ports 80/443 if libcap tools installed
if command -v setcap >/dev/null 2>&1; then
    setcap 'cap_net_bind_service=+ep' /usr/local/bin/samlguard || true
fi

echo "==> Installing default configuration if missing..."
if [[ ! -f /etc/samlguard/config.yaml ]]; then
    if [[ -f ./configs/config.yaml.example ]]; then
        cp ./configs/config.yaml.example /etc/samlguard/config.yaml
    elif [[ -f ./configs/config.yaml ]]; then
        cp ./configs/config.yaml /etc/samlguard/config.yaml
    fi
fi

echo "==> Configuring filesystem permissions..."
chown -R root:root /usr/local/bin/samlguard
chown -R samlguard:samlguard /etc/samlguard
chown -R samlguard:samlguard /var/lib/samlguard
chmod 0700 /etc/samlguard
chmod 0700 /var/lib/samlguard
if [[ -f /etc/samlguard/config.yaml ]]; then
    chmod 0600 /etc/samlguard/config.yaml
fi

echo "==> Installing systemd service..."
if [[ -f ./scripts/linux/samlguard.service ]]; then
    cp ./scripts/linux/samlguard.service /etc/systemd/system/samlguard.service
    chmod 0644 /etc/systemd/system/samlguard.service
    systemctl daemon-reload
    echo "==> SAMLGuard service installed successfully."
    echo "    To start:   sudo systemctl start samlguard"
    echo "    To enable:  sudo systemctl enable samlguard"
    echo "    To status:  sudo systemctl status samlguard"
fi

echo "==> Installation complete."

