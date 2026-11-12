package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSaveConfig(t *testing.T) {
	// Create a temp config file
	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, "config.yaml")

	initialYAML := `server:
  host: "0.0.0.0"
  port: 18080
saml:
  entity_id: "https://initial:18080"
  acs_url: "https://initial/callback"
  group_mapping:
    "admins": "Admin"
mfa:
  default_provider: "totp"
  otp_expiry: 5m
  allow_dummy_otp: false
smtp:
  host: "initial.smtp"
  port: 587
  username: "user"
  password: "secretpassword"
`
	if err := os.WriteFile(cfgFile, []byte(initialYAML), 0644); err != nil {
		t.Fatalf("failed to write initial config: %v", err)
	}

	cfg, err := Load(cfgFile)
	if err != nil {
		t.Fatalf("failed to load initial config: %v", err)
	}

	// Update payload
	payload := &AdminSettingsPayload{
		IdPEntityID:        "https://sts.windows.net/tenant-123/",
		IdPSSOURL:          "https://login.microsoftonline.com/tenant-123/saml2",
		EntityID:           "https://samlguard.example.com:8443",
		ACSURL:             "https://ita.example.com/api/current/authentication/saml2-callback",
		AllowedAudiences:   []string{"https://ita.example.com", "https://samlguard.example.com:8443"},
		GroupMapping:       map[string]string{"ita-admins": "Admin", "ita-viewers": "Viewer"},
		MFADefaultProvider: "email",
		OTPExpiry:          10 * time.Minute,
		ResendCooldown:     45 * time.Second,
		AllowDummyOTP:      true,
		SMTPHost:           "smtp.office365.com",
		SMTPPort:           587,
		SMTPUsername:       "admin@company.com",
		SMTPPassword:       "", // keep existing!
		SMTPFrom:           "noreply@company.com",
		SMTPFromName:       "Company MFA",
		SMTPEncryption:     "starttls",
	}

	if err := SaveConfig(cfgFile, cfg, payload); err != nil {
		t.Fatalf("SaveConfig failed: %v", err)
	}

	// Verify in-memory cfg was updated
	if cfg.SAML.IdPEntityID != "https://sts.windows.net/tenant-123/" {
		t.Errorf("expected IdPEntityID updated, got %s", cfg.SAML.IdPEntityID)
	}
	if cfg.SAML.ACSURL != "https://ita.example.com/api/current/authentication/saml2-callback" {
		t.Errorf("expected ACSURL updated, got %s", cfg.SAML.ACSURL)
	}
	if cfg.MFA.DefaultProvider != "email" {
		t.Errorf("expected DefaultProvider 'email', got %s", cfg.MFA.DefaultProvider)
	}
	if cfg.MFA.AllowDummyOTP != true {
		t.Errorf("expected AllowDummyOTP true, got %v", cfg.MFA.AllowDummyOTP)
	}
	if cfg.SMTP.Password != "secretpassword" {
		t.Errorf("expected SMTP password preserved as 'secretpassword', got %s", cfg.SMTP.Password)
	}

	// Reload from disk to verify persistence
	reloaded, err := Load(cfgFile)
	if err != nil {
		t.Fatalf("failed to reload config from disk: %v", err)
	}
	if reloaded.SAML.IdPEntityID != "https://sts.windows.net/tenant-123/" {
		t.Errorf("disk config mismatch: %s", reloaded.SAML.IdPEntityID)
	}
	if reloaded.SMTP.Host != "smtp.office365.com" {
		t.Errorf("disk smtp host mismatch: %s", reloaded.SMTP.Host)
	}
	if reloaded.SMTP.Password != "secretpassword" {
		t.Errorf("disk smtp password mismatch: %s", reloaded.SMTP.Password)
	}
}

func TestSaveConfig_IdPProfilesAndEnabledProviders(t *testing.T) {
	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, "config.yaml")

	initialYAML := `server:
  host: "0.0.0.0"
  port: 18080
saml:
  entity_id: "https://initial:18080"
  acs_url: "https://initial/callback"
mfa:
  enabled_providers:
    - "totp"
    - "email"
  default_provider: "totp"
`
	if err := os.WriteFile(cfgFile, []byte(initialYAML), 0644); err != nil {
		t.Fatalf("failed to write initial config: %v", err)
	}

	cfg, err := Load(cfgFile)
	if err != nil {
		t.Fatalf("failed to load initial config: %v", err)
	}

	payload := &AdminSettingsPayload{
		ActiveIdP: "keycloak",
		IdPProfiles: map[string]UpstreamIdPProfile{
			"entra": {
				EntityID: "https://sts.windows.net/t1/",
				SSOURL:   "https://login.microsoftonline.com/t1/saml2",
			},
			"keycloak": {
				EntityID: "https://sso.corp.local/realms/prod",
				SSOURL:   "https://sso.corp.local/realms/prod/protocol/saml",
			},
		},
		IdPEntityID:         "https://sso.corp.local/realms/prod",
		IdPSSOURL:           "https://sso.corp.local/realms/prod/protocol/saml",
		EntityID:            "https://samlguard.example.com:8443",
		ACSURL:              "https://ita.example.com/api/current/authentication/saml2-callback",
		MFAEnabledProviders: []string{"email"},
		MFADefaultProvider:  "totp", // Should auto-align to "email"
	}

	if err := SaveConfig(cfgFile, cfg, payload); err != nil {
		t.Fatalf("SaveConfig failed: %v", err)
	}

	reloaded, err := Load(cfgFile)
	if err != nil {
		t.Fatalf("reload failed: %v", err)
	}
	if reloaded.SAML.ActiveIdP != "keycloak" {
		t.Errorf("expected ActiveIdP 'keycloak', got %q", reloaded.SAML.ActiveIdP)
	}
	if len(reloaded.SAML.IdPProfiles) != 2 || reloaded.SAML.IdPProfiles["entra"].EntityID != "https://sts.windows.net/t1/" {
		t.Errorf("expected persisted IdPProfiles, got %+v", reloaded.SAML.IdPProfiles)
	}
	if len(reloaded.MFA.EnabledProviders) != 1 || reloaded.MFA.EnabledProviders[0] != "email" {
		t.Errorf("expected EnabledProviders ['email'], got %v", reloaded.MFA.EnabledProviders)
	}
	if reloaded.MFA.DefaultProvider != "email" {
		t.Errorf("expected DefaultProvider auto-aligned to 'email', got %q", reloaded.MFA.DefaultProvider)
	}
}

func TestSaveConfig_MultiIdPsAndSelectDefault(t *testing.T) {
	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, "config.yaml")

	initialYAML := `server:
  host: "0.0.0.0"
  port: 18080
saml:
  entity_id: "https://initial:18080"
  acs_url: "https://initial/callback"
`
	if err := os.WriteFile(cfgFile, []byte(initialYAML), 0644); err != nil {
		t.Fatalf("write initial config: %v", err)
	}
	cfg, err := Load(cfgFile)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	payload := &AdminSettingsPayload{
		ActiveIdP:   "simulator",
		EnabledIdPs: []string{"simulator", "entra"},
		IdPProfiles: map[string]UpstreamIdPProfile{
			"simulator": {
				EntityID: "https://initial:18080",
				SSOURL:   "https://initial:18080/mock-idp-login",
			},
			"entra": {
				EntityID: "https://sts.windows.net/t2/",
				SSOURL:   "https://login.microsoftonline.com/t2/saml2",
			},
		},
		EntityID:            "https://initial:18080",
		ACSURL:              "https://initial/callback",
		MFAEnabledProviders: []string{"totp", "email"},
		MFADefaultProvider:  "select",
	}

	if err := SaveConfig(cfgFile, cfg, payload); err != nil {
		t.Fatalf("SaveConfig failed: %v", err)
	}

	reloaded, err := Load(cfgFile)
	if err != nil {
		t.Fatalf("reload failed: %v", err)
	}
	if len(reloaded.SAML.EnabledIdPs) != 2 || reloaded.SAML.EnabledIdPs[0] != "simulator" || reloaded.SAML.EnabledIdPs[1] != "entra" {
		t.Errorf("expected EnabledIdPs [simulator entra], got %v", reloaded.SAML.EnabledIdPs)
	}
	if reloaded.MFA.DefaultProvider != "select" {
		t.Errorf("expected MFADefaultProvider 'select', got %q", reloaded.MFA.DefaultProvider)
	}
}

func TestSaveConfig_SMSProfilesAndMultiOTP(t *testing.T) {
	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, "config.yaml")

	if err := os.WriteFile(cfgFile, []byte("env: \"development\"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgFile)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	payload := &AdminSettingsPayload{
		ActiveIdP:           "simulator",
		EntityID:            "https://samlguard.local",
		ACSURL:              "https://ita.local/callback",
		MFAEnabledProviders: []string{"totp", "email", "sms"},
		MFADefaultProvider:  "select",
		SMSProvider:         "isms",
		SMSAPIURL:           "https://www.isms.com.my/isms_send_all_id.php",
		SMSAccountID:        "isms_user",
		SMSAuthToken:        "isms_secret",
		SMSSenderID:         "SAMLGuard",
		SMSHTTPMethod:       "POST",
		SMSMessageTemplate:  "Your code is {code}",
		SMSProfiles: map[string]SMSGatewayProfile{
			"sendquick": {
				APIURL:     "https://sq.corp.local/sendmsg.php",
				AccountID:  "sq_user",
				AuthToken:  "sq_pass",
				SenderID:   "SAMLGuard",
				HTTPMethod: "POST",
			},
		},
	}

	if err := SaveConfig(cfgFile, cfg, payload); err != nil {
		t.Fatalf("SaveConfig failed: %v", err)
	}

	reloaded, err := Load(cfgFile)
	if err != nil {
		t.Fatalf("Load after save failed: %v", err)
	}
	if !reloaded.MFA.IsProviderEnabled("sms") || len(reloaded.MFA.ActiveProviders()) != 3 {
		t.Errorf("expected 3 active MFA providers including sms, got %v", reloaded.MFA.ActiveProviders())
	}
	if reloaded.SMS.Provider != "isms" || reloaded.SMS.AuthToken != "isms_secret" {
		t.Errorf("expected iSMS active profile saved, got %+v", reloaded.SMS)
	}
	if reloaded.SMS.ProfileForProvider("sendquick").APIURL != "https://sq.corp.local/sendmsg.php" {
		t.Errorf("expected SendQuick standby profile saved, got %+v", reloaded.SMS.Profiles)
	}
}

func TestSaveConfig_CustomerTenantsAndAllowlist(t *testing.T) {
	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, "config.yaml")

	initialYAML := `server:
  host: "0.0.0.0"
  port: 18080
saml:
  entity_id: "https://samlguard.example.com:8443"
  acs_url: "https://ita.example.com/api/current/authentication/saml2-callback"
`
	if err := os.WriteFile(cfgFile, []byte(initialYAML), 0644); err != nil {
		t.Fatalf("failed to write initial config: %v", err)
	}

	cfg, err := Load(cfgFile)
	if err != nil {
		t.Fatalf("failed to load initial config: %v", err)
	}

	payload := &AdminSettingsPayload{
		CustomerTenantsSubmitted: true,
		CustomerTenants: []CustomerTenant{
			{
				Name:       "Acme Corp Enterprise",
				SPEntityID: "https://acme.example.com/saml/metadata",
				ACSURL:     "https://acme.example.com/api/current/authentication/saml2-callback",
				Notes:      "Production tenant",
				Enabled:    true,
			},
			{
				Name:       "Disabled Tenant",
				SPEntityID: "https://disabled.example.com/saml/metadata",
				ACSURL:     "https://disabled.example.com/callback",
				Enabled:    false,
			},
		},
	}

	if err := SaveConfig(cfgFile, cfg, payload); err != nil {
		t.Fatalf("SaveConfig failed: %v", err)
	}

	reloaded, err := Load(cfgFile)
	if err != nil {
		t.Fatalf("Load after save failed: %v", err)
	}

	if len(reloaded.SAML.CustomerTenants) != 2 {
		t.Fatalf("expected 2 customer tenants, got %d", len(reloaded.SAML.CustomerTenants))
	}
	if reloaded.SAML.CustomerTenants[0].ID != "acme-corp-enterprise" {
		t.Errorf("expected generated slug id 'acme-corp-enterprise', got %q", reloaded.SAML.CustomerTenants[0].ID)
	}
	if reloaded.SAML.EnabledCustomerTenantsCount() != 1 {
		t.Errorf("expected 1 enabled customer tenant, got %d", reloaded.SAML.EnabledCustomerTenantsCount())
	}
	if !reloaded.IsAllowedDownstreamACSURL("https://acme.example.com/api/current/authentication/saml2-callback") {
		t.Errorf("expected enabled customer tenant ACSURL to be allowlisted")
	}
	if reloaded.IsAllowedDownstreamACSURL("https://disabled.example.com/callback") {
		t.Errorf("expected disabled customer tenant ACSURL not to be allowlisted")
	}
}

func TestSaveConfig_AutoTLS(t *testing.T) {
	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, "config.yaml")

	initialYAML := `server:
  host: "0.0.0.0"
  port: 443
saml:
  entity_id: "https://sso.example.com"
  acs_url: "https://ita.example.com/api/current/authentication/saml2-callback"
database:
  driver: "sqlite"
  path: "samlguard.db"
`
	if err := os.WriteFile(cfgFile, []byte(initialYAML), 0644); err != nil {
		t.Fatalf("failed to write initial config: %v", err)
	}

	cfg, err := Load(cfgFile)
	if err != nil {
		t.Fatalf("failed to load initial config: %v", err)
	}

	payload := &AdminSettingsPayload{
		TLSSubmitted:             true,
		TLSEnabled:               true,
		AutoTLSEnabled:           true,
		AutoTLSDomains:           []string{"SSO.Example.com", "sso.example.com"},
		AutoTLSEmail:             "admin@example.com",
		AutoTLSCacheDir:          filepath.Join(tmpDir, "autocert"),
		AutoTLSHTTPChallengeAddr: ":80",
	}

	if err := SaveConfig(cfgFile, cfg, payload); err != nil {
		t.Fatalf("SaveConfig failed: %v", err)
	}

	reloaded, err := Load(cfgFile)
	if err != nil {
		t.Fatalf("Load after save failed: %v", err)
	}
	if !reloaded.TLS.Enabled || !reloaded.TLS.AutoTLS.Enabled {
		t.Fatalf("expected TLS and AutoTLS enabled, got %+v", reloaded.TLS)
	}
	if len(reloaded.TLS.AutoTLS.Domains) != 1 || reloaded.TLS.AutoTLS.Domains[0] != "sso.example.com" {
		t.Errorf("expected normalized domain ['sso.example.com'], got %v", reloaded.TLS.AutoTLS.Domains)
	}
	if err := reloaded.Validate(); err != nil {
		t.Errorf("expected AutoTLS config without cert_file/key_file to validate, got: %v", err)
	}
}

