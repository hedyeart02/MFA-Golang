# SAMLGuard HTTP & SAML API Documentation

All endpoints are served from the single SAMLGuard HTTP/HTTPS server (default port `8080` in development, `8443` in production). Every response includes correlation headers (`X-Request-ID`, `X-Correlation-ID`) and security headers (`X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy`, `Strict-Transport-Security`).

---

## 1. SAML 2.0 Federation Endpoints

Both `/saml/*` prefixed paths and root compatibility aliases are registered for compatibility with EcoStruxure IT Advisor and enterprise IdPs.

### `GET /saml/sso` | `POST /saml/sso` (Aliases: `GET /login`, `POST /login`)
Initiates SP-initiated or IdP-initiated authentication.

- **Query / Form Parameters:**
  - `SAMLRequest` — Base64-encoded (and deflated for HTTP-Redirect) SAML 2.0 `<AuthnRequest>`.
  - `RelayState` — Opaque state token echoed back to the downstream SP after MFA verification.
- **Behavior:**
  - Runs the request through `DefaultAuthnPipeline`.
  - When upstream external IdP federation is active, builds an outbound SAML `AuthnRequest` (or redirects the browser) to `saml.idp_sso_url`.
  - When running in development Mock IdP mode (`!IsProduction()`), renders the corporate sign-in page (`corporate_login.html`) forwarding to `/mock-idp/submit`.

### `POST /saml/acs` | `GET /saml/acs` (Aliases: `POST /acs`, `GET /acs`)
Assertion Consumer Service for receiving SAML 2.0 Responses from the upstream IdP.

- **Form / Query Parameters:**
  - `SAMLResponse` — Base64-encoded signed `<samlp:Response>` from the upstream IdP.
  - `RelayState` — Correlation token mapping back to the pending gateway `AuthSessionState`.
- **Behavior:**
  - Validates upstream XML signature against `saml.idp_cert_file`, checks timestamps/audience/issuer, and enforces the ITA `authorized_users` whitelist if enabled.
  - Renders the MFA Challenge page (`mfa_challenge.html`) for TOTP or Email OTP verification (including QR provisioning if the user has not yet enrolled in TOTP).

### `GET /saml/metadata` (Alias: `GET /metadata`)
Returns combined/default SAML 2.0 XML entity metadata (`application/samlmetadata+xml`) with signing X.509 certificate, SSO, and ACS locations.

### `GET /saml/metadata/idp` (Alias: `GET /metadata/idp`)
Returns **IdP-role SAML 2.0 metadata** (`IDPSSODescriptor`) to import into downstream Service Providers (such as Schneider Electric EcoStruxure IT Advisor).

### `GET /saml/metadata/sp` (Alias: `GET /metadata/sp`)
Returns **SP-role SAML 2.0 metadata** (`SPSSODescriptor`) to upload into upstream Enterprise IdPs (Microsoft Entra ID, Okta, Keycloak, ADFS).

---

## 2. Multi-Factor Authentication (MFA) Flow Endpoints

### `POST /mfa/verify`
Validates the user's submitted MFA code and completes downstream SAML SSO.

- **Form Parameters:**
  - `session_id` — Pending authentication session identifier.
  - `csrf_token` — Per-session CSRF protection token.
  - `code` — 6-digit TOTP or Email OTP code.
  - `method` — Optional MFA method selector (`totp` or `email`).
- **Responses:**
  - `200 OK`: Auto-submitting HTML form posting the freshly generated, signed `SAMLResponse` and `RelayState` to `saml.acs_url`.
  - `200 OK` / `400` (HTML): Re-renders `mfa_challenge.html` with remaining attempts or lockout feedback on invalid code.

### `POST /mfa/resend`
Triggers a new Email OTP dispatch when the configured `mfa.resend_cooldown` (default `60s`) has elapsed.

- **Form Parameters:** `session_id`, `csrf_token`, `method=email`.

### `POST /mfa/re-enroll` (Alias: `POST /saml/re-enroll`)
Allows resetting an active TOTP enrollment so the user can scan a fresh QR code during authentication.

- **Form Parameters:** `session_id`, `csrf_token`.

### `POST /mock-idp/submit` *(Development Only)*
Processes simulated corporate sign-in submissions from `corporate_login.html` when `env != production` and Mock IdP is active. Blocked automatically in production builds/configs.

---

## 3. Admin Console & Configuration Endpoints

Admin console authentication uses an HMAC-SHA256 signed `HttpOnly` cookie (`samlguard_admin_session`) backed by `admin_users` in SQLite.

### Authentication Endpoints

| Method | Path | Auth Required | Purpose |
|--------|------|---------------|---------|
| `GET` | `/admin` | Redirect | Redirects (`307`) to `/admin/settings` |
| `GET` | `/admin/login` | No | Renders Admin Console login page (`admin_login.html`) |
| `POST` | `/admin/login` | No | Verifies username/password (`bcrypt`), enforces 5-attempt lockout, sets session cookie |
| `GET` | `/admin/change-password` | Admin Cookie | Renders password change form (`admin_change_password.html`) |
| `POST` | `/admin/change-password` | Admin Cookie | Updates admin password hash in SQLite and clears `must_change_password` flag |
| `GET` | `/admin/logout` | No | Clears `samlguard_admin_session` cookie and redirects to `/admin/login` |

### Protected Admin Settings & Operations (`RequireAdminAuth`)

All routes below require a valid authenticated `samlguard_admin_session` cookie and completed initial password change:

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/admin/settings` | Renders the Admin Console (`admin_settings.html`) with SAML, MFA, SMTP, ITA, and Authorized Users panels |
| `POST` | `/admin/settings` | Validates form inputs, saves settings JSON to SQLite `gateway_settings`, applies live in-memory config updates, and hot-reloads SMTP sender |
| `POST` | `/admin/settings/test-email` | Sends a diagnostic test OTP email using the active SMTP settings |
| `POST` | `/admin/ita/sync` | Fetches users from EcoStruxure IT Advisor API (`ita.api_url`) and syncs them into SQLite `authorized_users` |
| `POST` | `/admin/users/add` | Manually adds an allowed user (`username`, `email`, `full_name`) to `authorized_users` |
| `POST` | `/admin/users/delete` | Removes a user from `authorized_users` |
| `GET` | `/admin/cert/download` | Downloads SAMLGuard's X.509 certificate (`type=saml` or `type=tls`) for SP/IdP setup |

---

## 4. Operational, Health, & Static Asset Endpoints

| Method | Path | Content Type | Response / Behavior |
|--------|------|--------------|---------------------|
| `GET` | `/health` | `application/json` | `200 OK` — `{"status":"ok"}` (also queried by Webmin Status check) |
| `GET` | `/ready` | `application/json` | `200 OK` — `{"status":"ready"}` |
| `GET` | `/live` | `application/json` | `200 OK` — `{"status":"live"}` |
| `GET` | `/version` | `application/json` | `200 OK` — `{"version":"v1.0.2"}` (injected at build time via `-X main.Version`) |
| `GET` | `/metrics` | `text/plain` | Prometheus metrics endpoint (`promhttp.Handler()`) |
| `GET` | `/favicon.ico` | `image/x-icon` | Embedded SAMLGuard shield icon (`Cache-Control: public, max-age=86400`) |
| `GET` | `/static/*` | Various | Embedded static assets (`img/favicon.svg`, `img/ecostruxure-*.png`, `js/theme.js`, etc.) |
| `GET` | `/assets/*` | `image/png` | Embedded background assets (`backgrounds/bg-login-*.png`, `bg-console-*.png`) |

