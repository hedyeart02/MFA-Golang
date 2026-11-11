# SAMLGuard Multi-Platform Deployment Guide

SAMLGuard compiles with `CGO_ENABLED=0` into standalone native binaries with zero runtime dependencies. It supports production deployments across **Windows (AMD64)**, **Linux (AMD64)**, and **Linux (ARM64)**, plus optional **Webmin** management on Linux servers.

---

## 1. Platform Support Matrix

| Target | GOOS / GOARCH | Package Artifact | Native Service Controller |
|--------|---------------|------------------|---------------------------|
| Windows Server / 10 / 11 | `windows/amd64` | `samlguard-v<VER>-windows-amd64.zip` | Windows Service Control Manager (`SAMLGuard`) |
| Linux x86_64 (Debian, Ubuntu, RHEL, Rocky) | `linux/amd64` | `samlguard-v<VER>-linux-amd64.tar.gz` | `systemd` (`samlguard.service`) + Webmin |
| Linux aarch64 (ARM64 Servers / Raspberry Pi / AWS Graviton) | `linux/arm64` | `samlguard-v<VER>-linux-arm64.tar.gz` | `systemd` (`samlguard.service`) + Webmin |

---

## 2. Building Release Packages

### Automated All-Platform Release Script

From Windows PowerShell in the project root:

```powershell
# Compiles windows/amd64, linux/amd64, linux/arm64 + SHA-256 dist/checksums.txt
powershell -ExecutionPolicy Bypass -File .\scripts\build-release.ps1 -Version "1.0.3"

# Builds the Webmin sidebar suite archive (dist/samlguard-webmin.wbm.gz)
go run ./scripts/webmin/build-wbm.go -src scripts/webmin/modules -out dist/samlguard-webmin.wbm.gz
```

### Manual Cross-Compilation (Linux / macOS / Windows)

```bash
# Windows AMD64
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w -X main.Version=v1.0.3" -o bin/samlguard.exe ./cmd/samlguard

# Linux AMD64
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w -X main.Version=v1.0.3" -o bin/samlguard-linux-amd64 ./cmd/samlguard

# Linux ARM64
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-s -w -X main.Version=v1.0.3" -o bin/samlguard-linux-arm64 ./cmd/samlguard
```

---

## 3. Generating Certificates & Cryptographic Keys

SAMLGuard requires:
- **TLS Server Certificate & Key** (`server.crt` / `server.key`) when terminating HTTPS natively
- **SAML Signing Certificate & Key** (`saml-signing.crt` / `saml-signing.key`) for signing downstream assertions
- **Upstream IdP Certificate** (`upstream-idp.crt`) exported from Microsoft Entra ID / Okta / Keycloak
- **AES-256 Encryption Key** (64 hex characters) for `mfa.encryption_key`

### Cross-Platform Go Generator (No OpenSSL Needed)

```bash
go run ./scripts/generate-certs.go
```

### OpenSSL Generator (Linux / macOS / Git Bash)

```bash
bash ./scripts/generate-certs.sh
```

> **Production Note:** Replace self-signed `server.crt` / `server.key` with CA-signed certificates matching your FQDN.

---

## 4. Windows Server Deployment (Windows SCM Service)

### First-Time Installation

Extract `samlguard-v1.0.3-windows-amd64.zip` and run PowerShell **as Administrator**:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\scripts\windows\install-service.ps1 -BinarySource .\bin\samlguard.exe
```

What `install-service.ps1` configures:
- Binary installed to `C:\Program Files\SAMLGuard\samlguard.exe`
- Data, config, and certs placed in `C:\ProgramData\SAMLGuard\` (`config.yaml`, `cert\`, `data\samlguard.db`)
- NTFS ACLs locked exclusively to `Administrators` and `SYSTEM`
- Native Windows Service `SAMLGuard` registered with `Automatic` startup, `Tcpip` dependency, and automatic 5-second crash recovery
- Launch command: `"C:\Program Files\SAMLGuard\samlguard.exe" -config "C:\ProgramData\SAMLGuard\config.yaml"`

### Configuring, Starting, & Managing on Windows

1. Edit `C:\ProgramData\SAMLGuard\config.yaml` with your port (e.g., `8443`), certificates, `encryption_key`, and `server_pepper`.
2. Open the Windows Firewall port (if accessed remotely):
   ```powershell
   New-NetFirewallRule -DisplayName "SAMLGuard HTTPS" -Direction Inbound -Protocol TCP -LocalPort 8443 -Action Allow
   ```
3. Start the service:
   ```powershell
   Start-Service -Name SAMLGuard
   Get-Service -Name SAMLGuard
   ```

### Upgrading on Windows

```powershell
Stop-Service -Name SAMLGuard -Force
Copy-Item .\bin\samlguard.exe "C:\Program Files\SAMLGuard\samlguard.exe" -Force
Start-Service -Name SAMLGuard
```

### Uninstalling on Windows

```powershell
# Remove binary & service registration (preserves C:\ProgramData\SAMLGuard)
.\scripts\windows\uninstall-service.ps1

# Remove everything including config & database
.\scripts\windows\uninstall-service.ps1 -PurgeData
```

---

## 5. Linux Deployment (`systemd`)

### First-Time Installation (AMD64 or ARM64)

Extract the matching `samlguard-v1.0.3-linux-<arch>.tar.gz` bundle on your Linux server and run:

```bash
sudo ./scripts/linux/install.sh ./bin/samlguard
```

What `install.sh` configures:
- Dedicated unprivileged system user & group `samlguard` (`/bin/false`)
- Binary installed to `/usr/local/bin/samlguard` with `setcap 'cap_net_bind_service=+ep'` (allows binding ports `< 1024` safely)
- Restricted directories: `/etc/samlguard` (`0700`, `config.yaml` `0600`) and `/var/lib/samlguard` (`0700`)
- Sandboxed `systemd` service `/etc/systemd/system/samlguard.service` (`ProtectSystem=strict`, `NoNewPrivileges=true`, `ReadWritePaths=/var/lib/samlguard`, `ReadOnlyPaths=/etc/samlguard`)

### Starting & Verifying on Linux

```bash
# Edit bootstrap YAML config
sudo nano /etc/samlguard/config.yaml

# Enable and start service
sudo systemctl enable --now samlguard
sudo systemctl status samlguard
sudo journalctl -u samlguard -f
```

> **Co-hosting with EcoStruxure IT Advisor:** IT Advisor typically occupies port `443`. Configure `server.port: 8443` in `/etc/samlguard/config.yaml` and update `saml.entity_id` / `saml.sso_url` to use `:8443`.

### Automated One-Command Upgrade on Linux

`scripts/linux/upgrade.sh` verifies `-version` on the new binary, creates timestamped backups of `/usr/local/bin/samlguard` and `/var/lib/samlguard/samlguard.db`, swaps the binary cleanly, restarts `samlguard.service`, and rolls back automatically if startup fails:

```bash
sudo bash scripts/linux/upgrade.sh ./dist/samlguard-v1.0.3-linux-amd64.tar.gz --wbm ./dist/samlguard-webmin.wbm.gz
```

### Uninstalling on Linux

```bash
# Preserve /etc/samlguard and /var/lib/samlguard
sudo ./scripts/linux/uninstall.sh

# Full removal including config, SQLite DB, and samlguard user
sudo ./scripts/linux/uninstall.sh --purge-data
```

---

## 6. Webmin Integration (Linux)

If Webmin (`:10000`) is running on your Linux host, install `dist/samlguard-webmin.wbm.gz` via **Webmin -> Webmin Configuration -> Webmin Modules** (or `sudo bash scripts/webmin/install-webmin-module.sh ./dist/samlguard-webmin.wbm.gz`), then click **Refresh Modules**.

This adds a dedicated **SAMLGuard** section in the Webmin sidebar containing:
- **About** (`samlguard_about`) — Version & endpoint links
- **Certificates** (`samlguard_certs`) — Inspect and upload TLS/SAML/IdP certs into `/etc/samlguard/cert`
- **Debug** (`samlguard_logs`) — Filter/download `journalctl -u samlguard` logs & inspect SQLite/port sockets
- **Setup** (`samlguard_setup`) — View/edit bootstrap `/etc/samlguard/config.yaml`
- **Status** (`samlguard_status`) — Start/stop/restart/enable daemon, probe `/health`, link to Admin Console (`/admin/settings`), and run **One-Click Application Upgrades** (`upgrade.cgi`) by uploading any new `.tar.gz` release or binary directly in the browser.

See [Webmin Module Guide](../scripts/webmin/README.md) for detailed Webmin operations.

---

## 7. Post-Deployment Setup Checklist

1. Browse to `https://<server>:8443/admin/login` (or `:8080` in non-TLS dev mode).
2. Log in with initial credentials **`admin` / `admin`** and set a strong administrator password when prompted.
3. Under **Identity Providers** & **Service Providers**, set your upstream IdP Entity ID, SSO URL, and downstream ITA ACS URL, then click **Save Configuration** (saved immediately to `gateway_settings` in `samlguard.db`).
4. Under **System Settings**, configure SMTP and click **Send Test Email** to verify Email OTP delivery.
5. Under **Customers / Authorized Users**, synchronize EcoStruxure IT Advisor users (`Sync Users`) or add accounts manually.
6. Import `https://<server>:8443/saml/metadata/idp` into IT Advisor, and `https://<server>:8443/saml/metadata/sp` into Entra ID / Okta / Keycloak.

