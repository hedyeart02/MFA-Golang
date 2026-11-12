# SAMLGuard

**Enterprise Pure-Go SAML 2.0 MFA Proxy Gateway (`v1.1.0`)**

SAMLGuard is a standalone, cross-platform SAML 2.0 Identity Provider Proxy (Proxy IdP) written in Go (`CGO_ENABLED=0`). It sits between Service Providers — such as **Schneider Electric EcoStruxure™ IT Advisor** — and upstream Enterprise Identity Providers (Microsoft Entra ID, Okta, Keycloak, ADFS), enforcing Multi-Factor Authentication (TOTP, Email OTP, and/or SMS OTP) and user authorization before issuing a signed SAML 2.0 assertion downstream.

## Key Capabilities

- **Single Self-Contained Pure-Go Binary** — Embedded HTML templates, static assets, and pure-Go SQLite (`modernc.org/sqlite`); zero external runtime dependencies or CGO required.
- **Multi-Platform & Multi-Architecture** — Official release builds for **Windows (AMD64)**, **Linux (AMD64)**, and **Linux (ARM64)**.
- **Native OS Service Integration** — Runs natively under **Windows Service Control Manager (SCM)** on Windows and **`systemd`** on Linux, plus an integrated **Webmin management suite** (`.wbm.gz`).
- **SAML 2.0 Proxy Federation** — Handles HTTP-Redirect and HTTP-POST bindings, XML signature & schema validation, replay protection, role/group claim mapping, and signed SAML assertions.
- **Multi-Factor Authentication** — Activate one or multiple OTP methods simultaneously with interactive sign-in method selection: Authenticator app **TOTP** (QR enrollment, AES-256-GCM encrypted secrets at rest), **Email OTP** (HMAC-SHA256 digests, SMTP STARTTLS/TLS), and **SMS OTP** (Cloud APIs: Twilio, iSMS, Vonage; Hardware Appliances: SendQuick, SMSEagle, MultiTech iSMS, Teltonika RUT/TRB, Custom HTTP/JSON relays).
- **EcoStruxure™ IT Advisor & Multi-App SAML Branding** — Optional API user whitelist synchronization, access control management, and **Custom Theme & Branding Profiles** (per-application app names, icons, dark/light logos, favicons, accent colors, and backgrounds stored in SQLite).
- **Built-In Admin Console & User Guide** — Web UI at `/admin/settings` and interactive User Guide at `/admin/guide` (`(?)` button) with runtime settings persisted to SQLite (`gateway_settings`), dark/light/system theme toggle, test email/SMS diagnostics, ITA user sync, and certificate downloads.

## Supported Platforms

| Platform | Architecture | Binary / Package | Service Manager |
|----------|--------------|------------------|-----------------|
| Windows | `amd64` (x86_64) | `samlguard.exe` / `samlguard-v1.1.0-windows-amd64.zip` | Windows Service (`SAMLGuard` via SCM) |
| Linux | `amd64` (x86_64) | `samlguard` / `samlguard-v1.1.0-linux-amd64.tar.gz` | `systemd` (`samlguard.service`) + Webmin |
| Linux | `arm64` (aarch64) | `samlguard` / `samlguard-v1.1.0-linux-arm64.tar.gz` | `systemd` (`samlguard.service`) + Webmin |

> **Development Note:** On macOS/Linux/Windows workstations, SAMLGuard can also run directly from any terminal via `go run ./cmd/samlguard`.

## Architecture Overview

```text
Browser ──► Service Provider (e.g., EcoStruxure IT Advisor)
               │  (1) SAML AuthnRequest (HTTP-Redirect / HTTP-POST)
               ▼
        SAMLGuard Gateway (:8443 TLS / :8080 HTTP)
               ├──► (2) Validation Pipeline (Binding, XML Schema, Signature, Replay, Clock, Policy)
               ├──► (3) Upstream IdP (Microsoft Entra ID / Okta / Keycloak / Mock IdP)
               ├──► (4) Authorization Check (ITA Authorized Users Whitelist in SQLite)
               ├──► (5) MFA Challenge (TOTP Authenticator or Email OTP via SMTP)
               ▼  (6) Re-signed SAML 2.0 Response + Mapped Attributes/Groups
        Service Provider ACS ──► Authenticated Session
```

See [Architecture Guide](docs/architecture.md) for package structure, pipeline stages, and SQLite schema details.

## Quick Start (Development)

### Prerequisites

- Go **1.25+**
- Optional: OpenSSL (or use the built-in cross-platform Go generator `scripts/generate-certs.go`)

### Run Locally from Source

```bash
# 1. Clone the repository
git clone https://github.com/hedyeart02/MFA-Golang.git
cd MFA-Golang

# 2. Generate development TLS, SAML signing, and encryption keys
go run ./scripts/generate-certs.go

# 3. Copy the example configuration if needed (or use configs/development.yaml)
cp configs/config.yaml.example configs/config.yaml

# 4. Run the gateway server
go run ./cmd/samlguard -config ./configs/development.yaml
```

Default Admin Console URL: `http://localhost:8080/admin/settings` (or `https://localhost:8443/admin/settings` with TLS enabled).  
Default initial admin credentials: **`admin` / `admin`** (mandatory password change is enforced on first login).

## Cross-Platform Release Builds

To compile all standalone pure-Go release archives (`windows/amd64`, `linux/amd64`, `linux/arm64`) with SHA-256 checksums and the Webmin `.wbm.gz` bundle:

```powershell
# Build Windows AMD64, Linux AMD64, Linux ARM64 archives + dist/checksums.txt
powershell -ExecutionPolicy Bypass -File .\scripts\build-release.ps1

# Build Webmin module archive (dist/samlguard-webmin.wbm.gz)
go run ./scripts/webmin/build-wbm.go -src scripts/webmin/modules -out dist/samlguard-webmin.wbm.gz
```

## Production Installation & Management

- **Linux (`systemd` + Webmin):** Install via `sudo ./scripts/linux/install.sh` and manage/upgrade with `scripts/linux/upgrade.sh` or the **SAMLGuard** Webmin sidebar modules.
- **Windows Server (SCM Service):** Install via elevated PowerShell `.\scripts\windows\install-service.ps1`.
- Full platform-by-platform steps are in the [Deployment Guide](docs/deployment.md) and [Webmin Module Guide](scripts/webmin/README.md).

## HTTP Endpoints Summary

| Category | Method | Path | Description |
|----------|--------|------|-------------|
| **SAML Federation** | `GET` / `POST` | `/saml/sso`, `/login` | Initiate SSO / display corporate login or redirect to upstream IdP |
| **SAML Federation** | `POST` / `GET` | `/saml/acs`, `/acs` | Consume upstream IdP SAML Response and initiate MFA step |
| **SAML Metadata** | `GET` | `/saml/metadata`, `/metadata` | Proxy SP/IdP SAML 2.0 XML metadata (`/metadata/idp`, `/metadata/sp`) |
| **MFA Flow** | `POST` | `/mfa/verify`, `/mfa/resend`, `/mfa/re-enroll` | Verify TOTP/Email/SMS code, resend Email/SMS OTP, or reset TOTP enrollment |
| **Admin Console** | `GET` / `POST` | `/admin/login`, `/admin/change-password`, `/admin/logout` | Admin authentication and first-login password change |
| **Admin Settings** | `GET` / `POST` | `/admin/settings` | Manage SAML, Multi-OTP, SMTP, SMS Gateway, and ITA configuration (persisted to SQLite) |
| **Admin Operations** | `POST` / `GET` | `/admin/ita/sync`, `/admin/settings/test-email`, `/admin/settings/test-sms`, `/admin/users/*`, `/admin/cert/download` | Synchronize ITA users, test SMTP/SMS, manage allowlist & user phones, download signing cert |
| **Operations** | `GET` | `/health`, `/ready`, `/live`, `/version`, `/metrics` | Probes, build version JSON, and Prometheus metrics |
| **Assets** | `GET` | `/static/*`, `/assets/*`, `/favicon.ico` | Embedded images, JS theme switcher, backgrounds, and favicons |

See [API Documentation](docs/api.md) for parameters, cookies, and responses.

## Testing

```bash
# Run all unit and integration tests
go test -count=1 ./...

# Run static analysis
go vet ./...

# With coverage summary
go test -coverprofile=coverage.out ./...
go tool cover -func=coverage.out
```

## Technology Stack

| Component | Technology |
|-----------|------------|
| Language | Go 1.25 (`CGO_ENABLED=0` pure Go) |
| HTTP Framework | Gin (`github.com/gin-gonic/gin`) |
| Embedded Assets | `embed.FS` (`web/` templates & static icons, `public/` backgrounds) |
| Database | SQLite via pure-Go `modernc.org/sqlite` |
| SAML & XML Signing | `crewjam/saml`, `beevik/etree`, `russellhaering/goxmldsig`, `mattermost/xml-roundtrip-validator` |
| Cryptography | `golang.org/x/crypto` (bcrypt), Go stdlib AES-256-GCM, HMAC-SHA256, RSA/X.509 |
| Configuration | Viper (`configs/*.yaml` + `SAMLGUARD_*` env vars + SQLite `gateway_settings`) |
| Logging & Metrics | Uber Zap (`go.uber.org/zap`) + Prometheus (`client_golang`) |
| OS Integration | `golang.org/x/sys/windows/svc` (Windows SCM), `systemd` + Webmin Perl/CGI (Linux) |

## Documentation

- [Architecture Guide](docs/architecture.md)
- [API Documentation](docs/api.md)
- [Configuration Guide](docs/configuration.md)
- [SMS Gateway & Multi-OTP Manual](docs/sms-gateway-manual.md)
- [Deployment Guide](docs/deployment.md)
- [Security Guide](docs/security.md)
- [Troubleshooting Guide](docs/troubleshooting.md)
- [Webmin Module Guide](scripts/webmin/README.md)

## Author & License

Developed and maintained by **Hidayat Ahmad**.  
Enterprise proprietary. All rights reserved.
