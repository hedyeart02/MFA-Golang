#!/usr/bin/env bash
set -euo pipefail

# Installs the SAMLGuard Webmin module package (.wbm.gz) from the command line.
# Usage: sudo ./install-webmin-module.sh [path/to/samlguard-webmin.wbm.gz]

WBM_PATH="${1:-./dist/samlguard-webmin.wbm.gz}"

if [[ $EUID -ne 0 ]]; then
   echo "Error: This script must be run as root." >&2
   exit 1
fi

if [[ ! -f "$WBM_PATH" ]]; then
    echo "Error: Webmin package not found at $WBM_PATH" >&2
    exit 1
fi

INSTALLER=""
for candidate in /usr/share/webmin/install-module.pl /usr/libexec/webmin/install-module.pl; do
    if [[ -f "$candidate" ]]; then
        INSTALLER="$candidate"
        break
    fi
done

if [[ -z "$INSTALLER" ]]; then
    echo "Error: Could not find Webmin's install-module.pl under /usr/share/webmin or /usr/libexec/webmin." >&2
    exit 1
fi

echo "==> Installing Webmin module from $WBM_PATH..."
perl "$INSTALLER" "$WBM_PATH"

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

echo "==> Done. Click 'Refresh Modules' in the Webmin sidebar to see the SAMLGuard category."
