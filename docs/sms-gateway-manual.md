# SAMLGuard SMS Gateway & Multi-OTP Manual

> Applies to **SAMLGuard `v1.0.4+`**

This manual explains how to configure, test, operate, and troubleshoot **SMS OTP** in SAMLGuard alongside **Authenticator App (TOTP)** and **Email OTP (SMTP)**, using either **Cloud SMS APIs** or **On-Premises Hardware SMS Gateways & Cellular Appliances**.

---

## Table of Contents

1. [Overview & Multi-OTP Sign-In Flow](#1-overview--multi-otp-sign-in-flow)
2. [How Phone Numbers Are Resolved (Without ITA Phone Numbers)](#2-how-phone-numbers-are-resolved-without-ita-phone-numbers)
3. [Supported Cloud SMS Providers](#3-supported-cloud-sms-providers)
4. [Supported Hardware SMS Gateways & Cellular Appliances](#4-supported-hardware-sms-gateways--cellular-appliances)
5. [Admin Console Setup & Live Testing](#5-admin-console-setup--live-testing)
6. [YAML Configuration Reference](#6-yaml-configuration-reference)
7. [Security Architecture & Production Guardrails](#7-security-architecture--production-guardrails)
8. [Local Development & Simulation Mode](#8-local-development--simulation-mode)
9. [Troubleshooting](#9-troubleshooting)

---

## 1. Overview & Multi-OTP Sign-In Flow

SAMLGuard supports activating one or **multiple OTP verification methods simultaneously** (`totp`, `email`, `sms`).

When a user completes primary upstream authentication (via Local Simulator, Microsoft Entra ID, Keycloak, or any Custom SAML 2.0 IdP) and is authorized in SAMLGuard:

- **`mfa.default_provider: "select"` (Recommended when multiple methods are active):**
  Users are presented with the **"Select a method to verify your identity"** chooser listing every enabled verification method (`Authenticator App`, `Email`, `SMS`). Once inside a challenge screen, they can also click **"Or verify another way"** or switch tabs at any time.
- **`mfa.default_provider: "sms"` / `"totp"` / `"email"`:**
  Users land directly on that verification method's challenge form and can switch to any other enabled method via the tabs or **"Or verify another way"** section.

### How SMS OTP Verification Works

1. User selects **SMS** (or lands on SMS as the default method).
2. SAMLGuard resolves the user's phone number from the upstream SAML assertion or SAMLGuard's local allowlist (`authorized_users.phone`).
3. SAMLGuard generates a cryptographically random numeric OTP (`mfa.otp_length`, default `6` digits), stores an HMAC-SHA256 digest in the SQLite `sms_otps` table with expiry (`mfa.otp_expiry`) and resend cooldown (`mfa.resend_cooldown`), and dispatches the message through the active SMS gateway profile.
4. The challenge screen displays the masked destination number (for example, `+60••••5678`).
5. Upon successful verification, SAMLGuard consumes the OTP record, checks retry/lockout limits (`mfa.max_retries`, `mfa.rate_limit_window`), and issues the signed downstream SAML 2.0 Assertion to the Service Provider (e.g., Schneider Electric EcoStruxure™ IT Advisor or future enterprise applications).

> **Note on `AuthnContextClassRef`:** SAMLGuard emits `urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken` for TOTP verifications and `urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified` for SMS OTP and Email OTP verifications.

---

## 2. How Phone Numbers Are Resolved (Without ITA Phone Numbers)

EcoStruxure™ IT Advisor (ITA) user records synchronized from ITA do not store mobile phone numbers. SAMLGuard solves this cleanly with a **two-tier lookup** so SMS OTP works both today and for any future SAML 2.0 application integrated behind SAMLGuard:

### Resolution Priority Order

1. **Priority 1 — Upstream SAML Assertion Claims (Dynamic per login)**
   During SAML Assertion Consumer Service (ACS) processing, SAMLGuard checks the upstream IdP attributes (Microsoft Entra ID, Keycloak, Okta, ADFS, Ping, etc.) in order for any non-empty phone claim:
   - `phone`
   - `phone_number`
   - `phonenumber`
   - `mobile`
   - `telephoneNumber`
   - WS-Federation claims ending in `mobilephone`, `homephone`, or `otherphone`
   If your corporate IdP already holds user mobile numbers, map that claim in your IdP's SAML attribute mapping and SAMLGuard will pick it up automatically without manual entry.

2. **Priority 2 — SAMLGuard Local User Database (`authorized_users.phone`)**
   If the upstream SAML assertion does not include a phone claim, SAMLGuard queries `authorized_users.phone` in SQLite for the authenticated user email.
   - Admins assign or update a user's phone number directly in **Admin Console → User Groups** (**Add User** `phone` field or **Set Phone** button per row, backed by `POST /admin/users/update-phone`).
   - **Safe Across ITA Syncs:** Re-running **Sync with ITA** (`POST /admin/ita/sync`) updates roles and account status from ITA while **preserving existing `authorized_users.phone` values** (ITA only overwrites the phone column if ITA itself provides a non-empty phone value).

### Normalization & Safety Policy

- Phone numbers are normalized toward E.164 (`+` followed by digits; whitespace, dashes, dots, and parentheses are stripped). Numbers should include the country code (for example, `+60123456789` or `+14155552671`).
- If neither Priority 1 nor Priority 2 yields a phone number for the user, SAMLGuard refuses to send an SMS and instructs the user to contact an administrator (or choose another active MFA method such as Authenticator App or Email OTP). **Unauthenticated users are never allowed to type an arbitrary destination phone number during login.**

---

## 3. Supported Cloud SMS Providers

All provider adapters are implemented natively in pure Go (`internal/mfa/sms.go`) with zero external SDK dependencies.

| Provider ID | Service | Endpoint Used | Auth & Required Credentials | Request Format & Notes |
|---|---|---|---|---|
| `twilio` | **Twilio Programmable Messaging** | `https://api.twilio.com/2010-04-01/Accounts/{account_id}/Messages.json` (overrideable via `api_url`) | HTTP Basic Auth (`account_id` = Account SID `AC...`, `auth_token` = Auth Token) | `POST` form-urlencoded (`To`, `Body`, and `MessagingServiceSid` if `sender_id` starts with `MG`, otherwise `From`). |
| `isms` | **iSMS (Malaysia)** | `https://www.isms.com.my/isms_send_all_id.php` (overrideable via `api_url`) | `account_id` = iSMS Username (`un`), `auth_token` = API Password (`pwd`) | `POST` (or `GET` if `http_method: GET`), sends `un`, `pwd`, `dstno` (digits without leading `+`), `msg`, `type=1`, `agreedterm=YES`, optional `sendid`. Fails on responses starting with `-` or containing `FAILED`. |
| `vonage` *(alias `nexmo`)* | **Vonage / Nexmo SMS API** | `https://rest.nexmo.com/sms/json` (overrideable via `api_url`) | `account_id` = API Key (`api_key`), `auth_token` = API Secret (`api_secret`) | `POST` JSON (`api_key`, `api_secret`, `from`, `to` without leading `+`, `text`). Validates response `messages[0].status == "0"`. |

---

## 4. Supported Hardware SMS Gateways & Cellular Appliances

For air-gapped networks, OT/industrial environments, and on-premises data centers where outbound internet access to cloud SMS APIs is restricted or prohibited, SAMLGuard ships built-in profiles for hardware GSM/4G LTE SMS gateways and cellular routers:

| Provider ID *(aliases)* | Appliance / Hardware | Example Endpoint URL | Auth & Credentials | Wire Parameters & Response Handling |
|---|---|---|---|---|
| `sendquick` | **SendQuick Enterprise Appliance** *(SendQuick Aspira / ConeXa / Entera)* | `https://sendquick.example.local/sq/sendmsg.php` | `account_id` = Username, `auth_token` = Password (+ HTTP Basic Auth) | `POST` (or `GET`), sends `username`, `passwd`, `tar_num` (recipient), `tar_msg` (text), `tar_mode=text`, optional `tar_sender`. Rejects responses containing `ERR`, `INVALID USER`, or `FAILED`. |
| `smseagle` *(alias `sms-eagle`)* | **SMSEagle Hardware SMS Gateway** *(NXS / MHD series)* | `https://smseagle.example.local/index.php/http_api/send_sms` | **Mode A (Token):** leave `account_id` blank (or `token`) + set `auth_token` = API Access Token.<br>**Mode B (Login/Pass):** `account_id` = `login`, `auth_token` = `pass`. | `POST` (or `GET`), sends `to`, `message`, plus `access_token` (query/form) and `access-token` HTTP header in Token mode, or `login` + `pass`. Rejects `ERR`, `Invalid login`, or `Invalid access token`. |
| `multitech` *(aliases `smsfinder`, `multitech-isms`)* | **MultiTech MultiModem / SMSFinder iSMS** *(SF100 / SF400 / SF800)* | `https://multitech.example.local/sendmsg` | `account_id` = Username (`user`), `auth_token` = Password (`passwd`) (+ HTTP Basic Auth) | Defaults to `GET` (supports `POST`), sends `user`, `passwd`, `cat=1`, `enc=0`, `to`, `text`. Rejects responses containing `Err:` or `FAILED`. |
| `teltonika` *(aliases `rut`, `rut240`, `rut955`, `trb140`)* | **Teltonika Cellular Routers & Gateways** *(RUT240, RUT955, TRB140, etc.)* | `https://teltonika.example.local/cgi-bin/sms_send` | `account_id` = Router Admin Username (`username`), `auth_token` = Password (`password`) | Defaults to `GET` (supports `POST`), sends `username`, `password`, `number`, `text`. Rejects responses containing `ERR`, `INVALID`, or `FAILED`. |
| `custom` | **Custom HTTP / JSON Gateway** *(Kannel, Ozeki SMS Gateway, Yeastar TG, Gammu / SMSTools relay, internal webhook)* | `https://sms-relay.internal.local/api/send` | **Bearer mode:** leave `account_id` blank (or `bearer`) + `auth_token` = Bearer Token.<br>**Basic Auth mode:** `account_id` = Username + `auth_token` = Password. | `POST` JSON payload `{ "to": "...", "from": "...", "message": "...", "code": "..." }` or `GET` query params (`to`, `from`, `message`, `code`). |

### Message Template Placeholders

Customize `sms.message_template` (or the **Message Template** field in Admin Console) to match your organization's wording or gateway formatting rules:

- Supported placeholders: `{code}` or `{{code}}` (for example: `Your SAMLGuard verification code is {code}. Valid for 5 minutes.`)
- If omitted or blank, SAMLGuard defaults to: `Your <issuer> verification code is <code>. Valid for <expiry>.`

---

## 5. Admin Console Setup & Live Testing

### Step 1 — Enable SMS OTP & Select Your Gateway Profile

1. Sign in to the Admin Console (`/admin/login`) and open **Tab 2: Upstream IdP & OTP** (`#tab-upstream`).
2. Under **OTP & MFA Verification Providers**:
   - Toggle **SMS OTP** to **Active**.
   - Activate any additional OTP methods you want available simultaneously (`Authenticator App (TOTP)`, `Email OTP`).
   - Under **Default OTP Method Shown First on Sign-In**, select **Customer Chooses on Sign-In** (`select`) or **SMS OTP** (`sms`).
3. Inside the **SMS OTP** card, click one of the **8 Provider Preset Cards** (or quick-fill buttons):
   - Cloud: **Twilio**, **iSMS**, **Vonage**
   - Hardware Appliances: **SendQuick HW**, **SMSEagle HW**, **MultiTech HW**, **Teltonika HW**
   - Generic / Dev: **Custom HTTP / Local Dev Mock**
4. Each provider maintains its own saved **SMS Gateway Profile**, so switching presets does not erase credentials saved for other gateways.
5. Fill in the highlighted fields for the selected provider:
   - **API Endpoint URL** *(mandatory for hardware appliances & custom relays)*
   - **Account ID / Username / API Key** *(leave empty for token-only SMSEagle or Bearer-token Custom HTTP)*
   - **Auth Token / Password / Secret** *(leave blank when editing existing config to keep the stored encrypted token)*
   - **Sender ID / From Number** *(required for Twilio/Vonage; optional for hardware SIM gateways)*
   - **HTTP Method** (`POST` or `GET`, matching your hardware firmware expectations)
   - **Message Template** (optional; supports `{code}` or `{{code}}`)
   - **Request Timeout** (e.g., `10s`; increase to `15s`–`20s` if a cellular modem takes extra time queuing AT commands)
6. Click **Save Configuration**.

### Step 2 — Run a Live SMS Gateway Test

Before enforcing SMS OTP for users:

1. Stay inside the **SMS OTP** settings card and locate **Live SMS Gateway Test**.
2. Enter a destination mobile number in international format (e.g., `+60123456789`).
3. Click **Send Test SMS** (`POST /admin/settings/test-sms`).
4. Confirm you receive `SAMLGuard test SMS` (or check stdout/logs if testing against a `mock://` local dev profile).

### Step 3 — Assign Phone Numbers to Users (When ITA Does Not Provide Them)

1. Open **Tab 6: User Groups & Allowlist** (`#tab-user-groups`).
2. To register a new user manually with SMS support, fill the **Phone (SMS)** field when clicking **Add User** (`POST /admin/users/add`).
3. To add or update a phone number on an existing ITA-synced user, click **Set Phone** on that user's row (`POST /admin/users/update-phone`) and enter their E.164 phone number (e.g., `+60123456789`).
4. You can clear a phone number at any time via **Set Phone** with an empty value.

---

## 6. YAML Configuration Reference

SMS settings can be provisioned statically in `config.yaml` (and overridden dynamically at runtime from the encrypted SQLite settings store via Admin Console).

```yaml
mfa:
  default_provider: "select"                # "totp", "email", "sms", or "select"
  enabled_providers: ["totp", "email", "sms"]
  issuer: "SAMLGuard"
  otp_expiry: 5m
  otp_length: 6
  max_retries: 5
  rate_limit_window: 15m
  resend_cooldown: 60s
  allow_dummy_otp: false

sms:
  provider: "sendquick"                     # Active profile: twilio | isms | vonage | sendquick | smseagle | multitech | teltonika | custom
  api_url: "https://sendquick.internal.local/sq/sendmsg.php"
  account_id: "samlguard-api"
  auth_token: "${SMS_AUTH_TOKEN}"           # Prefer environment variables or Admin Console encrypted storage
  sender_id: "SAMLGuard"
  http_method: "POST"                       # "POST" or "GET"
  message_template: "Your SAMLGuard verification code is {code}. Valid for 5 minutes."
  timeout: 10s
  # Optional standby profiles for rapid failover / switching in Admin Console:
  profiles:
    twilio:
      account_id: "${TWILIO_ACCOUNT_SID}"
      auth_token: "${TWILIO_AUTH_TOKEN}"
      sender_id: "+15551234567"
      http_method: "POST"
      timeout: 10s
    smseagle:
      api_url: "https://smseagle.internal.local/index.php/http_api/send_sms"
      account_id: ""                        # Blank = token-only auth
      auth_token: "${SMSEAGLE_API_TOKEN}"
      http_method: "POST"
      timeout: 15s
    multitech:
      api_url: "https://multitech.internal.local/sendmsg"
      account_id: "admin"
      auth_token: "${MULTITECH_PASSWORD}"
      http_method: "GET"
      timeout: 15s
    teltonika:
      api_url: "https://teltonika.internal.local/cgi-bin/sms_send"
      account_id: "admin"
      auth_token: "${TELTONIKA_PASSWORD}"
      http_method: "GET"
      timeout: 15s
```

---

## 7. Security Architecture & Production Guardrails

When `env: "production"` is set, `config.Load()` and Admin Console saves enforce strict validation:

1. **HTTPS Mandatory for On-Premises & Custom Gateways**
   When `"sms"` is enabled in `mfa.enabled_providers`, providers that require a custom/local endpoint (`sendquick`, `smseagle`, `multitech`, `teltonika`, `custom`) **must configure an `https://` `sms.api_url`**.
   - Plain `http://` URLs are rejected in production to prevent credential and OTP interception on the corporate LAN.
   - Terminate TLS in front of older hardware appliances using a trusted internal reverse proxy (Nginx, Caddy, HAProxy, or IIS ARR) if the appliance firmware itself only exposes plain HTTP.
   - `mock://`, `localhost`, and `127.0.0.1` SMS endpoints are blocked in production.

2. **Credentials Encrypted at Rest & Masked in UI/Logs**
   - `sms.auth_token` and every `sms.profiles[*].auth_token` are encrypted with AES-256-GCM (using `mfa.encryption_key`) before persistence to SQLite `admin_settings`.
   - `Config.Redacted()` masks all SMS `AuthToken` values in diagnostics/logs.
   - Rendered Admin Console HTML strips saved profile tokens from inline JavaScript objects; leaving the **Auth Token** input blank preserves the existing secret server-side.

3. **OTP Hashing, Rate Limiting & Lockout**
   - Raw SMS OTP codes are never stored in SQLite; only `HMAC-SHA256(server_pepper, code)` digests are persisted (`sms_otps` table).
   - Brute-force attempts are bounded by `mfa.max_retries` within `mfa.rate_limit_window`, and SMS flooding is prevented by `mfa.resend_cooldown`.

---

## 8. Local Development & Simulation Mode

In non-production mode (`env: "development"` or unset/non-`"production"`), SAMLGuard automatically **simulates SMS delivery** instead of making external network calls whenever any of the following is true:

- `sms.api_url` starts with `mock://` (for example, `mock://dev`)
- `sms.api_url` targets `://localhost` or `://127.0.0.1`
- `sms.api_url`, `sms.account_id`, and `sms.auth_token` are all empty

During local simulation, SAMLGuard prints the exact generated OTP and masked destination to standard output:

```text
[LOCAL-DEV SMS SIMULATION] provider=sendquick to=+60••••5678 message="Your SAMLGuard verification code is 482913. Valid for 5 minutes."
```

You can also use `mfa.allow_dummy_otp: true` in local development (accepts `000000`), though simulation mode lets you test the complete end-to-end OTP generation, cooldown, expiry, and retry lockout lifecycle.

---

## 9. Troubleshooting

| Symptom | Likely Cause | Resolution |
|---|---|---|
| **"No phone number is registered for SMS verification"** | Upstream SAML assertion has no phone claim AND `authorized_users.phone` is blank. | Assign the user's mobile number in **Tab 6: User Groups → Set Phone** (or map `phone` / `mobile` / `telephoneNumber` in Entra ID / Keycloak), then retry sign-in. |
| **Config fails to start in `production` with `sms.api_url must use https://`** | Hardware or custom SMS gateway URL uses `http://`, `localhost`, or `mock://`. | Put the hardware gateway behind an internal HTTPS reverse proxy (or enable HTTPS on the appliance) and configure `https://...` as `sms.api_url`. |
| **Test SMS fails on SMSEagle with `Invalid access token` or `Invalid login`** | Mismatch between Token mode and Login/Password mode. | For API Access Token authentication, clear **Account ID / Username** (leave blank or set `token`) and paste the SMSEagle token in **Auth Token**. For user/pass mode, enter both `login` and `pass`. |
| **Test SMS fails on SendQuick / MultiTech / Teltonika despite `HTTP 200`** | Gateway returned an application-level error string in the HTTP 200 body (`ERR`, `FAILED`, `INVALID USER`). | Read the exact returned snippet shown in the Admin Console error alert; verify API user permissions, SIM card registration/PIN status, and credit/carrier signal on the hardware unit. |
| **SMS delayed or timing out on USB/GSM hardware modem** | Cellular network registration or AT queue latency exceeds default `10s`. | Increase **Request Timeout** (`sms.timeout`) to `15s`–`20s` in Admin Console or `config.yaml`. |
| **Resend button returns cooldown error** | Request clicked before `mfa.resend_cooldown` elapsed. | Wait for the configured cooldown period (default `60s`), or switch temporarily to **Authenticator App** or **Email OTP** if multiple methods are enabled. |
