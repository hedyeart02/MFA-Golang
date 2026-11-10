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
		EntityID:           "https://192.168.0.178:18080",
		ACSURL:             "https://192.168.0.119/api/current/authentication/saml2-callback",
		AllowedAudiences:   []string{"https://192.168.0.119", "https://192.168.0.178:18080"},
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
	if cfg.SAML.ACSURL != "https://192.168.0.119/api/current/authentication/saml2-callback" {
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

