# SAMLGuard Troubleshooting Guide

This guide covers common runtime, configuration, SAML federation, MFA, and service issues across **Linux (`systemd` / Webmin)** and **Windows (SCM Service)**.

---

## 1. Service Fails to Start

### Error: `security violation: ... in production mode`
**Cause:** `env: "production"` (or `SAMLGUARD_ENV=production`) is active and `Config.Validate()` blocked an insecure setting.  
**Resolution:** Verify all required fields in `/etc/samlguard/config.yaml` (Linux) or `C:\ProgramData\SAMLGuard\config.yaml` (Windows):
- `mfa.allow_dummy_otp` must be `false`
- `mfa.encryption_key` must be an exact **64-character hex** string (32 bytes, generated via `openssl rand -hex 32` or `go run ./scripts/generate-certs.go`)
- `mfa.server_pepper` must be non-empty
- `smtp.host` cannot be empty, `localhost`, or `127.0.0.1`
- `saml.acs_url`, `saml.sso_url`, and `saml.idp_sso_url` must all start with `https://` and must not reference `mock-idp`

### Error: `failed to bind HTTP listener: listen tcp :443: bind: permission denied` (Linux)
**Cause:** Unprivileged `samlguard` user lacks capability to bind ports `< 1024`, or another service already binds that port.  
**Resolution:**
1. Check if `setcap` is applied:
   ```bash
   sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/samlguard
   ```
2. Verify no port conflict exists (especially port `443` when EcoStruxure IT Advisor runs on the same Linux host):
   ```bash
   sudo ss -tulpn | grep -E ':443|:8443|:8080'
   ```
   If co-hosted with IT Advisor, set `server.port: 8443` in `/etc/samlguard/config.yaml` and restart `samlguard`.

### Error: `failed to load TLS certificate or key`
**Cause:** `tls.enabled: true` is set, but `tls.cert_file` or `tls.key_file` path is missing or unreadable by the service account.  
**Resolution:**
- On **Linux**, ensure files are in `/etc/samlguard/cert/` and readable by `samlguard`:
  ```bash
  sudo chown -R samlguard:samlguard /etc/samlguard/cert
  sudo chmod 0640 /etc/samlguard/cert/*.crt
  sudo chmod 0600 /etc/samlguard/cert/*.key
  ```
- On **Windows**, verify paths in `C:\ProgramData\SAMLGuard\config.yaml` point to `C:\ProgramData\SAMLGuard\cert\...` and `SYSTEM` has read permission.

---

## 2. Admin Console Issues (`/admin/settings`)

### Changes Saved in Admin Console vs YAML Config
- Saving in `/admin/settings` stores settings in SQLite (`gateway_settings` table inside `samlguard.db`) rather than modifying `/etc/samlguard/config.yaml` (which is mounted read-only to `samlguard` by `systemd`).
- On restart, SAMLGuard loads bootstrap values from YAML/env vars first, then automatically overlays `gateway_settings` from `samlguard.db`.
- If you move servers, copy both `/etc/samlguard/` and `/var/lib/samlguard/samlguard.db` (or `C:\ProgramData\SAMLGuard\` on Windows).

### Admin Password Locked Out or Forgotten
**Cause:** Exceeding 5 failed logins triggers temporary lockout in SQLite `admin_users`.  
**Resolution:** Wait for `locked_until` to expire, or reset the `admin_users` row in a maintenance window using SQLite (or remove/re-seed only `admin_users` if needed while keeping `mfa_secrets` intact).

---

## 3. SAML Federation & Login Errors

### Error: `signature verification failed` / `untrusted certificate` on `/saml/acs`
**Cause:** The upstream IdP certificate (`saml.idp_cert_file`) does not match the X.509 certificate used by Microsoft Entra ID, Okta, or Keycloak to sign the incoming `<Response>`.  
**Resolution:** Download the current Base64/PEM SAML signing certificate from your upstream IdP, save it to `/etc/samlguard/cert/upstream-idp.crt` (or upload it via Webmin **SAMLGuard -> Certificates**), and restart `samlguard`.

### Error: Clock Skew / Expired SAML Assertion
**Cause:** Server system time differs from upstream IdP time beyond 3 minutes.  
**Resolution:** Enable NTP / `chronyd` (Linux) or `w32tm` (Windows) on the gateway host so UTC clocks stay synchronized.

### Error: User Rejected After Upstream Login (`unauthorized` / Not in Whitelist)
**Cause:** `ita.enforce_user_whitelist` is enabled and the user is not present in SQLite `authorized_users`.  
**Resolution:** Log in to `/admin/settings`, verify ITA API connectivity under **IT Advisor Integration**, click **Sync Users Now**, or add the username/email manually under **Authorized Users**.

---

## 4. Email OTP & TOTP MFA Issues

### Email OTP Not Arriving
1. Open `/admin/settings` -> **System Settings** and click **Send Test Email** to see the exact SMTP error returned by `SMTPSender`.
2. Check `smtp.encryption` matches your relay port (`starttls` for port `587`, `tls` for port `465`, `none` for internal unauthenticated port `25` relay).
3. Verify firewall egress from the SAMLGuard host to your SMTP relay.

### TOTP Codes Rejected (`invalid code`)
1. Confirm system clock synchronization (NTP); TOTP relies on accurate UTC 30-second intervals.
2. Check if the user has exceeded `mfa.max_retries` (default 5 attempts -> temporary lockout).
3. If the user lost their authenticator device, reset/re-enroll their TOTP token using the **Re-enroll MFA** option on the challenge screen.

---

## 5. Collecting Logs & Diagnostics

### Linux (`systemd` & Webmin)
```bash
# Live tail service logs
sudo journalctl -u samlguard -f

# Last 200 log entries
sudo journalctl -u samlguard -n 200 --no-pager

# Local health & version check (use -k for self-signed TLS)
curl -k https://localhost:8443/health
curl -k https://localhost:8443/version
```
In Webmin, open **SAMLGuard -> Debug** to filter or download `journalctl` output and verify SQLite database permissions and listening sockets, or **SAMLGuard -> Status** to inspect daemon health.

### Windows Server
```powershell
# Check Windows Service status
Get-Service -Name SAMLGuard

# Check Application/System logs for SAMLGuard
Get-EventLog -LogName Application -Newest 50 | Where-Object { $_.Message -like "*SAMLGuard*" }

# Run interactively in PowerShell to view real-time JSON stdout logs (stop service first)
Stop-Service -Name SAMLGuard
& "C:\Program Files\SAMLGuard\samlguard.exe" -config "C:\ProgramData\SAMLGuard\config.yaml"
```

