# SAMLGuard Configuration Guide

SAMLGuard combines YAML configuration files, environment variable overrides (`SAMLGUARD_*`), CLI flags, and runtime gateway settings stored in SQLite (`gateway_settings`).

---

## 1. CLI Flags

```text
samlguard [-config <path> | -c <path>] [-version]
```

- `-config`, `-c`: Explicit path to a YAML configuration file.
- `-version`: Prints `SAMLGuard version <Version>` and exits.

---

## 2. Configuration Precedence & Search Paths

At startup (`internal/config/config.go`), configuration loads in this exact order (later sources override earlier ones):

1. **Compiled-in defaults** (`config.SetDefaults`).
2. **Primary YAML file**:
   - `-config` / `-c` CLI flag, if provided.
   - Else `SAMLGUARD_CONFIG_PATH` or `CONFIG_PATH` environment variable.
   - Else first existing file found among:
     - Executable directory: `<exe_dir>/configs/config.yaml`, `<exe_dir>/configs/default.yaml`, `<exe_dir>/config.yaml`, `<exe_dir>/default.yaml`
     - Working directory: `configs/config.yaml`, `configs/default.yaml`, `config.yaml`, `default.yaml`
     - Windows Service standard path: `%ProgramData%\SAMLGuard\config.yaml`, `%ProgramData%\SAMLGuard\default.yaml`
     - Linux `systemd` standard path: `/etc/samlguard/config.yaml`, `/etc/samlguard/default.yaml`
3. **Environment overlay YAML** (merged when `SAMLGUARD_ENV`, `APP_ENV`, or `ENV` is set, e.g. `production.yaml` or `development.yaml`).
4. **Environment variables**: Prefixed with `SAMLGUARD_` and nested `.` replaced with `_` (for example, `SAMLGUARD_SERVER_PORT=8443`, `SAMLGUARD_MFA_ENCRYPTION_KEY=...`).
5. **SQLite `gateway_settings` overlay**: Applied right after SQLite opens in `SetupAppWithCleanup`. Any SAML, MFA, SMTP, or ITA settings saved via `/admin/settings` override bootstrap YAML values at startup and are hot-reloaded on save.

---

## 3. Complete YAML Configuration Schema

Reference template: [`configs/config.yaml.example`](../configs/config.yaml.example)

### Root & Profile
```yaml
env: "production"   # "production" activates strict HTTPS/key/SMTP validation; "development" permits local testing
```

### `server` & `tls`
```yaml
server:
  host: "0.0.0.0"
  port: 8443                  # Default: 8080 (use 8443 if co-hosted with EcoStruxure ITA on 443)
  read_timeout: 30s
  write_timeout: 30s
  shutdown_timeout: 15s

tls:
  enabled: true
  cert_file: "./cert/server.crt"
  key_file: "./cert/server.key"
```
*(Legacy keys `server.tls_enabled`, `server.tls_cert_file`, and `server.tls_key_file` are also supported for backward compatibility.)*

### `database`
```yaml
database:
  driver: "sqlite"
  # Linux default path:   /var/lib/samlguard/samlguard.db
  # Windows default path: C:\ProgramData\SAMLGuard\data\samlguard.db
  path: "./data/samlguard.db"
  max_idle_conns: 1
  max_open_conns: 1
  enable_foreign_keys: true
```

### `saml`
```yaml
saml:
  entity_id: "https://samlguard.example.com:8443/saml/metadata"
  acs_url: "https://ita.example.com/api/current/authentication/saml2-callback"
  sso_url: "https://samlguard.example.com:8443/saml/sso"
  slo_url: "https://samlguard.example.com:8443/saml/slo"
  metadata_url: "https://samlguard.example.com:8443/saml/metadata"

  # SAMLGuard downstream response/assertion signing keys
  cert_file: "./cert/saml-signing.crt"
  key_file: "./cert/saml-signing.key"
  sign_requests: true
  sign_assertions: true
  sign_responses: true

  # Upstream Enterprise IdP (Microsoft Entra ID, Okta, Keycloak, ADFS)
  idp_entity_id: "https://login.microsoftonline.com/<tenant-id>/v2.0"
  idp_sso_url: "https://login.microsoftonline.com/<tenant-id>/saml2"
  idp_cert_file: "./cert/upstream-idp.crt"

  allowed_audiences:
    - "https://ita.example.com"
  authn_context_class_ref: ""   # Empty selects TimeSyncToken for TOTP or unspecified for Email OTP
  group_mapping:
    "ITAdvisor-Admins": "Admin"
    "ITAdvisor-Operators": "Operator"
  default_groups: []
```

### `mfa`
```yaml
mfa:
  default_provider: "select"  # "totp", "email", "sms", or "select" (chooser on login)
  enabled_providers: ["totp", "email"] # Any subset of ["totp", "email", "sms"]
  issuer: "SAMLGuard"
  timeout: 5m
  otp_expiry: 5m
  otp_length: 6
  max_retries: 5
  rate_limit_window: 15m
  resend_cooldown: 60s
  totp_skew: 1
  allow_dummy_otp: false      # Must be false in production
  encryption_key: "<64-char-hex-aes-256-key>"
  server_pepper: "<high-entropy-secret-string>"
```

### `sms`
Configure SMS OTP delivery via Cloud SMS APIs (`twilio`, `isms`, `vonage`) or on-premises hardware gateways (`sendquick`, `smseagle`, `multitech`, `teltonika`, `custom`). See the full [SMS Gateway & Multi-OTP Manual](sms-gateway-manual.md) for provider wire formats, hardware presets, and phone number resolution.

```yaml
sms:
  provider: "sendquick"       # twilio | isms | vonage | sendquick | smseagle | multitech | teltonika | custom
  api_url: "https://sendquick.internal.local/sq/sendmsg.php"
  account_id: "samlguard-api"
  auth_token: "${SMS_AUTH_TOKEN}"
  sender_id: "SAMLGuard"
  http_method: "POST"         # "POST" or "GET"
  message_template: "Your SAMLGuard verification code is {code}. Valid for 5 minutes."
  timeout: 10s
  profiles: {}                # Optional per-provider saved standby profiles
```

### `smtp`
```yaml
smtp:
  host: "smtp.example.com"
  port: 587
  username: "postmaster@example.com"
  password: "YOUR_SMTP_PASSWORD"
  from: "no-reply@example.com"
  from_name: "SAMLGuard MFA Security"
  encryption: "starttls"      # "starttls", "tls", or "none"
```

### `ita` (EcoStruxure IT Advisor Integration)
```yaml
ita:
  api_url: "https://ita.example.com/api/current"
  api_username: "apc"
  api_password: "YOUR_ITA_API_PASSWORD"
  enforce_user_whitelist: true
  auto_sync_interval: 30m
  manual_allowed_users:
    - "apc"
    - "itaadmin"
```

### `logging`, `metrics`, `security`, & Decompression Limits
```yaml
logging:
  level: "info"               # "debug" or "info"
  format: "json"
  output_path: "stdout"

metrics:
  enabled: true
  path: "/metrics"

# SAMLRequest DoS Protection Defaults
maximumRequestSize: 262144       # 256 KB
maximumInflatedSize: 2097152     # 2 MB
maximumCompressionRatio: 20.0
```

---

## 4. Production Mode Validation Guardrails

When `env: "production"` (or `SAMLGUARD_ENV=production` / `APP_ENV=production`), startup validation strictly rejects insecure configurations:

| Check | Requirement |
|-------|-------------|
| `mfa.allow_dummy_otp` | Must be `false` |
| `mfa.encryption_key` | Required; must be a valid 64-character hex-encoded 32-byte AES-256 key |
| `mfa.server_pepper` | Required non-empty string |
| `smtp.host` | Required; cannot be empty, `localhost`, or `127.0.0.1` |
| `sms.api_url` | When `"sms"` is enabled, must use `https://` for `sendquick`, `smseagle`, `multitech`, `teltonika`, or `custom`; cannot use `mock://`, `localhost`, or `127.0.0.1` |
| `sms.account_id` / `sms.auth_token` | When `"sms"` is enabled, `auth_token` is required; `account_id` is also required for all providers except token-only `smseagle` and `custom` |
| `saml.idp_entity_id` | Required; cannot use `https://mock-idp.samlguard.local` |
| `saml.idp_sso_url` | Required absolute `https://` URL; cannot reference `mock-idp` |
| `saml.acs_url` & `saml.sso_url` | Required absolute `https://` URLs (`http://` or relative URLs rejected) |

---

## 5. Platform Directory Reference

| Artifact | Windows Service Path | Linux `systemd` Path |
|----------|----------------------|----------------------|
| Binary | `C:\Program Files\SAMLGuard\samlguard.exe` | `/usr/local/bin/samlguard` |
| YAML Config | `C:\ProgramData\SAMLGuard\config.yaml` | `/etc/samlguard/config.yaml` |
| Certificates | `C:\ProgramData\SAMLGuard\cert\` | `/etc/samlguard/cert/` |
| SQLite Database | `C:\ProgramData\SAMLGuard\data\samlguard.db` | `/var/lib/samlguard/samlguard.db` |

