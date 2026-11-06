#!/usr/bin/env bash
set -euo pipefail

# SAMLGuard Linux Uninstallation Script
# Usage: sudo ./uninstall.sh [--purge-data]

if [[ $EUID -ne 0 ]]; then
   echo "Error: This script must be run as root." >&2
   exit 1
fi

echo "==> Stopping and disabling samlguard service..."
if systemctl is-active --quiet samlguard; then
    systemctl stop samlguard
fi
if systemctl is-enabled --quiet samlguard 2>/dev/null; then
    systemctl disable samlguard
fi

echo "==> Removing systemd unit..."
rm -f /etc/systemd/system/samlguard.service
systemctl daemon-reload

echo "==> Removing binary..."
rm -f /usr/local/bin/samlguard

PURGE="${1:-}"
if [[ "$PURGE" == "--purge-data" ]]; then
    echo "==> Purging configuration and data directories..."
    rm -rf /etc/samlguard
    rm -rf /var/lib/samlguard
    if id -u samlguard >/dev/null 2>&1; then
        userdel samlguard || true
    fi
    echo "==> All SAMLGuard data purged."
else
    echo "==> Binary and service removed."
    echo "    Configuration (/etc/samlguard) and Database (/var/lib/samlguard) preserved."
    echo "    (Use --purge-data to remove data and system user)."
fi

