# SAMLGuard Architecture Guide

## Overview

SAMLGuard is built as a **single, self-contained pure-Go binary** (`cmd/samlguard`) compiled with `CGO_ENABLED=0`. All web templates, CSS/JS assets, favicons, background graphics, and the SQLite database driver (`modernc.org/sqlite`) are compiled directly into the executable, enabling zero-dependency deployments across **Windows AMD64**, **Linux AMD64**, and **Linux ARM64**.

---

## Request & Authentication Flow

SAMLGuard acts as a **SAML 2.0 Proxy Identity Provider**:

```text
+---------+        1. AuthnRequest        +------------------+        2. Proxy Auth       +------------------+
| Browser | ----------------------------> |  Service Provider| -------------------------> |   SAMLGuard      |
|  User   |                               |  (e.g. ITA App)  |    (/saml/sso | /login)    |   Gateway        |
+---------+                               +------------------+                            +--------+---------+
     ^                                                                                             |
     |                                                                       3. Forward to Upstream|
     |                                                                          IdP or Dev Mock IdP|
     |                                                                                             v
     |        6. Signed SAML Response                                                     +------------------+
     |        (POST to SP ACS URL)                                                        |  Upstream IdP    |
     | <--------------------------------------------------------------------------------- | (Entra / Okta /  |
     |                                                                                    |  Keycloak / Mock)|
     |                         5. Enforce Whitelist & MFA Challenge                       +--------+---------+
     |                            (TOTP / Email OTP via SMTP)                                      |
     | <-------------------------------------------------------------------------------------------+
     |                                  4. Upstream SAML Response (/saml/acs | /acs)
```

### Step-by-Step Lifecycle

1. **SP-Initiated or Direct SSO (`/saml/sso` or `/login`)**:
   - Decodes inbound `SAMLRequest` (HTTP-Redirect DEFLATE+Base64 or HTTP-POST Base64) and runs it through `DefaultAuthnPipeline`.
   - Depending on configuration, forwards authentication to the configured upstream SAML 2.0 IdP (`saml.idp_sso_url`) or presents SAMLGuard's built-in Corporate Sign-In / Mock IdP form (non-production only).
2. **Upstream Assertion Consumption (`/saml/acs` or `/acs`)**:
   - Parses and validates the upstream SAML 2.0 response XML signature against the trusted upstream IdP X.509 certificate (`saml.idp_cert_file`), checks conditions/timestamps, and extracts `UpstreamClaims` (username, email, groups).
3. **Authorization Whitelist Enforcement**:
   - When `ita.enforce_user_whitelist` is enabled, verifies that the authenticated user exists in SQLite `authorized_users` (populated manually, seeded defaults, or synchronized via EcoStruxure IT Advisor API).
4. **MFA Challenge (`/mfa/verify`, `/mfa/resend`, `/mfa/re-enroll`)**:
   - **TOTP Mode:** Prompts for a 6-digit authenticator code. First-time users receive an inline QR enrollment screen; secrets are encrypted with AES-256-GCM before storage in `mfa_secrets`.
   - **Email OTP Mode:** Generates a one-time code, stores an HMAC-SHA256 digest (`mfa.server_pepper`) in `email_otps`, and dispatches the code over SMTP.
5. **Downstream SAML Assertion Generation**:
   - `ResponseGenerator` builds a fresh SAML 2.0 `<Response>` targeted at `saml.acs_url` and audience (`saml.allowed_audiences` / SP entity ID), applies `saml.group_mapping` / `saml.default_groups`, sets `AuthnContextClassRef`, signs the assertion/response with `saml.cert_file` / `saml.key_file`, and auto-submits it via browser HTTP POST.

---

## Repository & Package Structure

```text
MFA Golang/
├── cmd/
│   ├── samlguard/                 # Main gateway binary entrypoint
│   │   ├── main.go                # Dependency wiring, Gin router, graceful shutdown
│   │   ├── service_windows.go     # Windows Service Control Manager (SCM) runner
│   │   └── service_other.go       # POSIX build stub for non-Windows targets
│   └── samlguard-cli/             # Companion CLI diagnostic stub
├── internal/
│   ├── config/                    # Viper config loader, validator, DB settings overlay helpers
│   ├── federation/
│   │   ├── adapter/               # Provider adapters (Generic, Microsoft Entra ID)
│   │   ├── certificate/           # X.509 certificate helpers
│   │   ├── metadata/              # Metadata loader, parser, cache, validator, diff
│   │   └── model/                 # Shared federation models
│   ├── gateway/
│   │   ├── binding/               # HTTP-Redirect / HTTP-POST detection & DEFLATE decoder
│   │   ├── builder/               # Request normalizer & ExecutionContext builder
│   │   ├── capture/               # Request capture utilities & test harness
│   │   ├── handler/               # HTTP handlers (SAML flow, MFA verification, Admin Console)
│   │   ├── parser/                # XML roundtrip-safe crewjam parser
│   │   ├── pipeline/              # DefaultAuthnPipeline orchestrator
│   │   ├── resolver/              # Metadata & IdP provider resolvers
│   │   ├── validator/             # Syntax, signature, schema, replay, clock, policy checks
│   │   └── saml_response.go       # Downstream signed SAML 2.0 assertion/response generator
│   ├── ita/                       # EcoStruxure IT Advisor REST API client (user sync)
│   └── mfa/                       # MFA service, TOTP/Email OTP logic, SMTP client, SQLite storage
├── pkg/
│   ├── logger/                    # Structured Zap logger wrappers
│   ├── metrics/                   # Prometheus metrics registry
│   ├── middleware/                # Recovery, ContextInject, Logger, SecurityHeaders, Identity
│   ├── ratelimiter/               # Rate limiter primitives
│   ├── replay/                    # SAML ID replay prevention cache
│   ├── response/                  # Standard JSON envelopes
│   └── saml/                      # Shared SAML constants
├── web/                           # //go:embed HTML templates & static assets (CSS/JS/icons/favicon)
├── public/                        # //go:embed UI background images
├── configs/                       # YAML templates & environment overlays
├── scripts/
│   ├── build-release.ps1          # Multi-platform CGO=0 release archive builder + SHA-256 checksums
│   ├── generate-certs.go/.sh      # Dev self-signed X.509 & key generators
│   ├── linux/                     # install.sh, upgrade.sh, uninstall.sh, samlguard.service
│   ├── windows/                   # install-service.ps1, uninstall-service.ps1
│   └── webmin/                    # build-wbm.go, install-webmin-module.sh, 5 Webmin CGI modules
└── docs/                          # Project documentation
```

---

## Validation Pipeline (`DefaultAuthnPipeline`)

All inbound SAML `AuthnRequest` payloads execute sequentially through `internal/gateway/pipeline`:

1. `BindingResolver` — Identifies HTTP-Redirect vs HTTP-POST binding.
2. `DefaultRequestDecoder` — Enforces `maximumRequestSize` (default 256 KB), `maximumInflatedSize` (default 2 MB), and `maximumCompressionRatio` (default `20.0`) to prevent zip-bomb / decompression DoS attacks.
3. `SecureCrewjamParser` — Parses SAML XML safely using `mattermost/xml-roundtrip-validator` and `beevik/etree`.
4. `DefaultNormalizer` — Normalizes IDs, issuer, ACS targets, and protocol attributes.
5. `DefaultSyntaxValidator` — Validates XML payload size and required elements.
6. `DefaultSignatureValidator` — Verifies XML signatures when signed.
7. `DefaultSchemaValidator` — Ensures structural SAML 2.0 schema compliance.
8. `DefaultReplayValidator` — Prevents reuse of SAML request/assertion IDs (5-minute window).
9. `DefaultClockValidator` — Enforces allowed clock skew (3 minutes on inbound requests).
10. `DefaultPolicyValidator` — Checks destination URL policy alignment.
11. `MetadataResolver` & `ProviderResolver` — Resolves metadata sources and selects the matching federation adapter (`generic` or `entra`).
12. `DefaultContextBuilder` — Produces the validated gateway execution context.

---

## Persistence & Configuration Architecture

### SQLite Database (`samlguard.db`)

Managed by `internal/mfa/storage.go` using pure-Go `modernc.org/sqlite`:

| Table | Purpose | Key Security / Behavior |
|-------|---------|-------------------------|
| `mfa_secrets` | User TOTP secrets | Encrypted at rest via **AES-256-GCM**; tracks `last_accepted_timestep`, `failed_attempts`, `locked_until` |
| `email_otps` | Active Email OTP challenges | Stored as **HMAC-SHA256** digest (`server_pepper`); tracks `expires_at`, `resend_after`, `attempts`, `consumed` |
| `authorized_users` | ITA User Whitelist | Stores allowed usernames, emails, full names, and `source` (`ita_sync`, `system_default`, `manual`) |
| `admin_users` | Admin Console operators | Password hashed with `bcrypt`; seeded default `admin`/`admin` with `must_change_password = 1` and lockout tracking |
| `gateway_settings` | Persisted Admin Console config | Single-row (`id = 1`) JSON document storing SAML, MFA, SMTP, and ITA changes made in `/admin/settings` |

### Configuration Startup Overlay Order

1. Built-in defaults (`internal/config.SetDefaults`).
2. YAML file loaded from `-config`, `SAMLGUARD_CONFIG_PATH`, executable directory, working directory, `C:\ProgramData\SAMLGuard\config.yaml` (Windows), or `/etc/samlguard/config.yaml` (Linux).
3. Environment-specific YAML overlay (`development.yaml` or `production.yaml` based on `SAMLGUARD_ENV` / `APP_ENV` / `ENV`).
4. Environment variables (`SAMLGUARD_*` prefix with `_` separating nested keys).
5. **SQLite Runtime Overlay**: On startup in `SetupAppWithCleanup`, `GetAdminSettings` loads any persisted `gateway_settings` record from SQLite and applies it via `config.ApplyAdminSettings`. Saving settings in `/admin/settings` persists directly to SQLite and hot-reloads in-memory SAML/MFA/SMTP settings immediately without requiring filesystem write access to `/etc/samlguard/config.yaml`.

---

## Multi-Platform Runtime Execution

- **Windows (`service_windows.go`)**: Detects `svc.IsWindowsService()`. Under Windows SCM, binds the TCP listener synchronously before reporting `RUNNING`, loads TLS certificates up front, and handles `Stop`/`Shutdown` controls with graceful HTTP server drain. Interactive console mode listens for `os.Interrupt` / `SIGTERM`.
- **Linux & Other POSIX (`service_other.go`)**: `isWindowsService()` returns `false`; runs `runInteractive` under `systemd` (`Type=simple`) or terminal foreground, handling `SIGINT`/`SIGTERM` cleanly with configurable `server.shutdown_timeout`.
- **Linux Webmin Integration**: Five Webmin CGI modules (`samlguard_about`, `samlguard_certs`, `samlguard_logs`, `samlguard_setup`, `samlguard_status`) under Webmin's `SAMLGuard` sidebar category control `systemd`, certificates, config inspection, logs, and zero-SSH binary upgrades.
