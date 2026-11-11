#!/usr/bin/env bash
set -euo pipefail

# SAMLGuard Linux Automated Upgrade Script
# Usage:
#   sudo ./upgrade.sh [release.tar.gz | binary_path] [--wbm path/to/samlguard-webmin.wbm.gz]
#
# Preserves /etc/samlguard/config.yaml, /etc/samlguard/cert/*, and /var/lib/samlguard/samlguard.db.
# Creates timestamped backups and rolls back automatically if the new binary fails to start.

TARGET_BIN="/usr/local/bin/samlguard"
CONFIG_FILE="/etc/samlguard/config.yaml"
DB_FILE="/var/lib/samlguard/samlguard.db"
UNIT_DEST="/etc/systemd/system/samlguard.service"
SERVICE_NAME="samlguard"

SOURCE_ARG=""
WBM_ARG=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --wbm)
            WBM_ARG="${2:-}"
            shift 2
            ;;
        -h|--help)
            echo "Usage: sudo $0 [release.tar.gz | binary_path] [--wbm path/to/samlguard-webmin.wbm.gz]"
            exit 0
            ;;
        *)
            if [[ -z "$SOURCE_ARG" ]]; then
                SOURCE_ARG="$1"
            else
                echo "Error: Unexpected argument: $1" >&2
                exit 1
            fi
            shift
            ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root (use sudo)." >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -z "$SOURCE_ARG" ]]; then
    if [[ -f "./bin/samlguard" ]]; then
        SOURCE_ARG="./bin/samlguard"
    elif [[ -f "$SCRIPT_DIR/../../bin/samlguard" ]]; then
        SOURCE_ARG="$SCRIPT_DIR/../../bin/samlguard"
    else
        echo "Error: Specify a SAMLGuard .tar.gz archive or binary path." >&2
        exit 1
    fi
fi

if [[ ! -f "$SOURCE_ARG" ]]; then
    echo "Error: Source artifact not found at '$SOURCE_ARG'." >&2
    exit 1
fi

TMP_DIR="$(mktemp -d)"
cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

NEW_BIN=""
NEW_UNIT=""

if [[ "$SOURCE_ARG" == *.tar.gz || "$SOURCE_ARG" == *.tgz ]]; then
    echo "==> Extracting release archive $SOURCE_ARG..."
    tar -xzf "$SOURCE_ARG" -C "$TMP_DIR"
    NEW_BIN="$(find "$TMP_DIR" -type f -name 'samlguard' | head -n 1 || true)"
    NEW_UNIT="$(find "$TMP_DIR" -type f -name 'samlguard.service' | head -n 1 || true)"
else
    NEW_BIN="$SOURCE_ARG"
    if [[ -f "$SCRIPT_DIR/samlguard.service" ]]; then
        NEW_UNIT="$SCRIPT_DIR/samlguard.service"
    fi
fi

if [[ -z "$NEW_BIN" || ! -f "$NEW_BIN" ]]; then
    echo "Error: Could not find 'samlguard' binary inside '$SOURCE_ARG'." >&2
    exit 1
fi

chmod 0755 "$NEW_BIN"
echo "==> Verifying new binary..."
NEW_VERSION="$("$NEW_BIN" -version 2>&1 || true)"
if [[ -z "$NEW_VERSION" ]]; then
    echo "Error: Candidate binary failed '-version' verification. Aborting." >&2
    exit 1
fi
echo "    Candidate: $NEW_VERSION"

TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
BIN_BACKUP=""
if [[ -f "$TARGET_BIN" ]]; then
    BIN_BACKUP="/usr/local/bin/samlguard.bak.$TIMESTAMP"
    echo "==> Backing up existing binary to $BIN_BACKUP..."
    cp -p "$TARGET_BIN" "$BIN_BACKUP"
fi

if [[ -f "$DB_FILE" ]]; then
    DB_BACKUP="/var/lib/samlguard/samlguard.db.bak.$TIMESTAMP"
    echo "==> Backing up database to $DB_BACKUP..."
    cp -p "$DB_FILE" "$DB_BACKUP"
    chown samlguard:samlguard "$DB_BACKUP" 2>/dev/null || true
    chmod 0600 "$DB_BACKUP"
fi

WAS_ACTIVE=0
if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet "$SERVICE_NAME"; then
    WAS_ACTIVE=1
    echo "==> Stopping $SERVICE_NAME service..."
    systemctl stop "$SERVICE_NAME"
fi

echo "==> Installing new binary to $TARGET_BIN..."
install -m 0755 -o root -g root "$NEW_BIN" "$TARGET_BIN"
if command -v setcap >/dev/null 2>&1; then
    setcap 'cap_net_bind_service=+ep' "$TARGET_BIN" || true
fi

if [[ -n "$NEW_UNIT" && -f "$NEW_UNIT" ]]; then
    echo "==> Updating systemd unit $UNIT_DEST..."
    cp "$NEW_UNIT" "$UNIT_DEST"
    chmod 0644 "$UNIT_DEST"
    systemctl daemon-reload
fi

if [[ -n "$WBM_ARG" ]]; then
    if [[ ! -f "$WBM_ARG" ]]; then
        echo "Warning: Webmin module package '$WBM_ARG' not found; skipping Webmin upgrade." >&2
    else
        INSTALLER=""
        for candidate in /usr/share/webmin/install-module.pl /usr/libexec/webmin/install-module.pl; do
            if [[ -f "$candidate" ]]; then
                INSTALLER="$candidate"
                break
            fi
        done
        if [[ -n "$INSTALLER" ]]; then
            echo "==> Upgrading Webmin module from $WBM_ARG..."
            perl "$INSTALLER" "$WBM_ARG"
            if [[ -d /etc/webmin ]]; then
                grep -q '^samlguard=' /etc/webmin/webmin.catnames 2>/dev/null || echo 'samlguard=SAMLGuard' >> /etc/webmin/webmin.catnames
                for mod in samlguard_status samlguard_setup samlguard_certs samlguard_logs samlguard_about; do
                    if grep -q "^${mod}=" /etc/webmin/webmin.cats 2>/dev/null; then
                        sed -i "s/^${mod}=.*/${mod}=samlguard/" /etc/webmin/webmin.cats
                    else
                        echo "${mod}=samlguard" >> /etc/webmin/webmin.cats
                    fi
                done
            fi
        else
            echo "Warning: Webmin install-module.pl not found; skipping Webmin upgrade." >&2
        fi
    fi
fi

if command -v systemctl >/dev/null 2>&1 && [[ -f "$UNIT_DEST" ]]; then
    echo "==> Starting $SERVICE_NAME service..."
    if ! systemctl start "$SERVICE_NAME"; then
        echo "Error: Failed to start $SERVICE_NAME with new binary!" >&2
        if [[ -n "$BIN_BACKUP" && -f "$BIN_BACKUP" ]]; then
            echo "==> Rolling back to $BIN_BACKUP..."
            install -m 0755 -o root -g root "$BIN_BACKUP" "$TARGET_BIN"
            if command -v setcap >/dev/null 2>&1; then
                setcap 'cap_net_bind_service=+ep' "$TARGET_BIN" || true
            fi
            if [[ $WAS_ACTIVE -eq 1 ]]; then
                systemctl start "$SERVICE_NAME" || true
            fi
        fi
        exit 1
    fi
    sleep 1
    systemctl --no-pager --lines=5 status "$SERVICE_NAME" || true
fi

if command -v curl >/dev/null 2>&1 && [[ -f "$CONFIG_FILE" ]]; then
    PORT="$(grep -E '^[[:space:]]*port:[[:space:]]*[0-9]+' "$CONFIG_FILE" | head -n 1 | awk -F: '{print $2}' | tr -d '[:space:]' || true)"
    PORT="${PORT:-8443}"
    SCHEME="http"
    if grep -qE '^[[:space:]]*(enabled|tls_enabled):[[:space:]]*true' "$CONFIG_FILE"; then
        SCHEME="https"
    fi
    echo "==> Health check (${SCHEME}://127.0.0.1:${PORT}/health):"
    curl -sk --max-time 3 "${SCHEME}://127.0.0.1:${PORT}/health" || true
    echo ""
fi

echo "==> Upgrade complete ($NEW_VERSION)."

