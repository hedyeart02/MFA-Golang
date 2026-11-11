# SAMLGuard Security Guide

## Overview

SAMLGuard enforces defense-in-depth security controls across SAML 2.0 federation processing, Multi-Factor Authentication, administrative access, transport encryption, and OS service isolation.

---

## 1. SAML 2.0 Federation Security

### XML Parsing & Signature Validation
- **Roundtrip-Safe Parsing:** `SecureCrewjamParser` uses `mattermost/xml-roundtrip-validator` and `beevik/etree` to neutralize XML signature wrapping (XSW) and parser differential attacks.
- **Trusted Upstream Verification:** All inbound upstream IdP `<Response>` payloads at `/saml/acs` (`/acs`) are cryptographically validated against the pre-configured X.509 certificate (`saml.idp_cert_file`).
- **Downstream Assertion Signing:** `ResponseGenerator` signs outbound SAML 2.0 responses/assertions using SAMLGuard's dedicated RSA/X.509 signing key (`saml.cert_file` / `saml.key_file`).

### Decompression & Request Size Limits (`DefaultRequestDecoder`)
To protect against XML bombs and HTTP-Redirect deflate compression attacks:
- `maximumRequestSize`: `256 KB` (262,144 bytes)
- `maximumInflatedSize`: `2 MB` (2,097,152 bytes)
- `maximumCompressionRatio`: `20.0` maximum expansion ratio

### Replay, Timestamp, & Audience Validation
- **Replay Prevention:** `DefaultReplayValidator` maintains a 5-minute TTL cache rejecting duplicate SAML request/assertion IDs.
- **Clock Skew Enforcement:** `DefaultClockValidator` enforces timestamps with a strict 3-minute allowed skew window.
- **Issuer & Audience Checks:** Validates upstream issuer (`saml.idp_entity_id`), downstream audience restrictions (`saml.allowed_audiences`), and expected destination URLs (`DefaultPolicyValidator`).

---

## 2. MFA Cryptographic Controls

### Authenticator TOTP (`mfa_secrets`)
- Enrollment secrets are encrypted at rest with **AES-256-GCM** using a 32-byte (64-character hex) symmetric key configured via `mfa.encryption_key` (`SAMLGUARD_MFA_ENCRYPTION_KEY`).
- Tracks `last_accepted_timestep` in SQLite to prevent TOTP code reuse within the same 30-second window.
- Locks out accounts temporarily (`locked_until`) after exceeding `mfa.max_retries` (default `5`) within `mfa.rate_limit_window` (default `15m`).

### Email OTP (`email_otps`)
- Numeric codes (`mfa.otp_length`, default `6`) are never persisted in plaintext; SAMLGuard stores only an **HMAC-SHA256** digest keyed with `mfa.server_pepper` and uses constant-time comparison.
- Enforces configurable expiry (`mfa.otp_expiry`, default `5m`), attempt limits (`mfa.max_retries`), and resend cooldown (`mfa.resend_cooldown`, default `60s`).
- Per-session CSRF tokens protect `/mfa/verify`, `/mfa/resend`, and `/mfa/re-enroll` form submissions.

### User Whitelist Authorization (`authorized_users`)
- When `ita.enforce_user_whitelist` is enabled, users must exist in SQLite `authorized_users` (via EcoStruxure IT Advisor sync or manual enrollment) before an MFA challenge or downstream SAML assertion is issued.

---

## 3. Admin Console Security

- **Credential Storage:** Admin passwords in SQLite `admin_users` are hashed with `bcrypt` (`bcrypt.DefaultCost`).
- **First-Login Password Rotation:** The seeded `admin` / `admin` account has `must_change_password = 1`, blocking access to `/admin/settings` and all protected admin endpoints until rotated at `/admin/change-password`.
- **Brute-Force Lockout:** Tracks `failed_attempts` and `locked_until` per admin account in SQLite.
- **Session Cookies:** Admin authentication uses `samlguard_admin_session`, an HMAC-SHA256 signed cookie (`HttpOnly: true`, `SameSite: Lax`, `Secure: true` whenever TLS is active or detected behind HTTPS proxies).
- **Secret Preservation:** Admin Console updates write non-empty credentials to SQLite without echoing plaintext SMTP or ITA passwords back into form fields, preserving existing secrets if omitted on save.

---

## 4. Production Startup Enforcement (`Config.Validate()`)

When `env: "production"` (or `SAMLGUARD_ENV=production`), SAMLGuard refuses to start if any of the following security violations are detected:
1. `mfa.allow_dummy_otp` is `true` (blocked in production).
2. `mfa.encryption_key` is missing or is not a valid 64-character hex (32-byte) AES key.
3. `mfa.server_pepper` is empty.
4. `smtp.host` is empty, `localhost`, or `127.0.0.1`.
5. `saml.idp_entity_id` or `saml.idp_sso_url` uses the development Mock IdP (`mock-idp`).
6. `saml.acs_url`, `saml.idp_sso_url`, or `saml.sso_url` uses plain `http://` or relative paths instead of `https://`.

---

## 5. Transport & HTTP Security Headers

### Native TLS Termination
- Pure-Go `http.Server.ServeTLS` validates TLS certificates synchronously at startup (`tls.enabled: true`, `tls.cert_file`, `tls.key_file`).

### Security Headers Middleware (`pkg/middleware/chain.go`)
Every HTTP response includes:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`
- `Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; frame-ancestors 'none'; form-action *` (`form-action *` allows SAML POST callbacks to downstream SP ACS URLs while preventing framing via `frame-ancestors 'none'`)
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy: camera=(), microphone=(), geolocation=()`

---

## 6. Logging Privacy & Secret Redaction

- `Config.Redacted()` masks `jwt.secret`, `tls.key_file`, `security.csrf_secret`, `mfa.encryption_key`, `mfa.server_pepper`, `smtp.password`, and database passwords before logging.
- Structured Zap logs record correlation metadata (`request_id`, `client_ip`, status, latency) and **never** emit user passwords, OTP codes, plaintext TOTP secrets, or encryption keys.

---

## 7. Host & Service Hardening

- **Linux (`systemd`):** Runs as unprivileged user `samlguard` with `NoNewPrivileges=true`, `ProtectSystem=strict`, `ProtectHome=true`, `PrivateTmp=true`, `PrivateDevices=true`, `ReadOnlyPaths=/etc/samlguard`, `ReadWritePaths=/var/lib/samlguard`, and capability scoping limited strictly to `CAP_NET_BIND_SERVICE` (`chmod 0700` dirs, `0600` config).
- **Windows Service:** `install-service.ps1` strips inherited permissions on `C:\ProgramData\SAMLGuard` and grants NTFS access strictly to `SYSTEM` and `Administrators`.

---

## Production Hardening Checklist

1. Replace development self-signed TLS and SAML signing certificates with CA-signed or organization-PKI certificates.
2. Generate unique cryptographically random 64-character hex values for `mfa.encryption_key` and high-entropy secrets for `mfa.server_pepper` and `jwt.secret`.
3. Immediately change the default `admin` password after first installation.
4. Keep `env: "production"` enabled so HTTPS and key checks cannot be bypassed accidentally.
5. Restrict Admin Console network access (firewall rules or reverse proxy IP allowlisting) if exposing `/saml/*` to untrusted networks.
6. Monitor Prometheus metrics (`/metrics`) and service logs (`journalctl -u samlguard` or Windows Event Viewer).
