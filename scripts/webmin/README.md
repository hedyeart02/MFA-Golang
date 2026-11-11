# SAMLGuard Webmin Module

This directory provides a Webmin module package (`samlguard-webmin.wbm.gz`) that adds a dedicated **`SAMLGuard`** section to the Webmin sidebar with five modules:

- **About** (`samlguard_about`) — Version, file paths, and standalone endpoint links
- **Certificates** (`samlguard_certs`) — Inspect X.509 certificates and upload certs/keys to `/etc/samlguard/cert`
- **Debug** (`samlguard_logs`) — View/filter/download `journalctl -u samlguard` logs and socket diagnostics
- **Setup** (`samlguard_setup`) — View summary and edit `/etc/samlguard/config.yaml`
- **Status** (`samlguard_status`) — Start/stop/restart/enable `samlguard.service`, health check, and link to `/admin/settings`

> **Architecture note:** Just like EcoStruxure IT Advisor, SAMLGuard itself still runs as a standalone Linux `systemd` service (`samlguard.service`) on its own port (default `8443`). This Webmin package manages that standalone service from Webmin (`:10000`).

## 1. Build the `.wbm.gz` package

From the repository root:

```bash
go run ./scripts/webmin/build-wbm.go
```

This creates `dist/samlguard-webmin.wbm.gz` with Unix LF line endings and `0755` permissions on all `.cgi` / `.pl` scripts.

## 2. Install the standalone SAMLGuard service on Linux

On the target Linux server (if not already installed):

```bash
sudo ./scripts/linux/install.sh ./bin/samlguard-linux-amd64
```

Remember to configure `/etc/samlguard/config.yaml` (e.g., use a free port such as `8443` or `18080` if co-hosted with IT Advisor on port `443`).

## 3. Install the Webmin module

### Option A — Upload in Webmin Browser UI
1. Log in to Webmin (`https://<server>:10000`).
2. Go to **Webmin** -> **Webmin Configuration** -> **Webmin Modules**.
3. Select **From uploaded file**, choose `dist/samlguard-webmin.wbm.gz`, and click **Install Module**.
4. Click **Refresh Modules** in the bottom-left sidebar.
5. Expand **SAMLGuard** in the left sidebar (`About`, `Certificates`, `Debug`, `Setup`, `Status`).

### Option B — Install via SSH
```bash
sudo bash scripts/webmin/install-webmin-module.sh ./dist/samlguard-webmin.wbm.gz
```
Then click **Refresh Modules** in the Webmin sidebar.

## 4. Upgrading SAMLGuard Later

### Option A — One-Click Upgrade inside Webmin UI
1. Open **SAMLGuard** -> **Status** in the Webmin sidebar.
2. Under **Upgrade SAMLGuard Application**, upload `dist/samlguard-vX.Y.Z-linux-amd64.tar.gz` (or `arm64`, or a raw `samlguard` binary) and click **Upload & Upgrade SAMLGuard**.
   - Webmin automatically verifies the new binary (`-version`), backs up `/usr/local/bin/samlguard` and `samlguard.db`, swaps the binary, reapplies `cap_net_bind_service`, restarts `samlguard.service`, and rolls back if startup fails.

### Option B — One-Command CLI Upgrade via SSH
```bash
sudo bash scripts/linux/upgrade.sh ./dist/samlguard-v1.0.2-linux-amd64.tar.gz --wbm ./dist/samlguard-webmin.wbm.gz
```
