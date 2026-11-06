package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestConfigLoad_Valid(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	yamlData := []byte(`
server:
  host: "127.0.0.1"
  port: 8088
saml:
  entity_id: "https://test.samlguard.example/idp"
database:
  driver: "sqlite"
  connection_string: "file:data/test.db"
jwt:
  secret: "my-super-secret-key"
`)
	if err := os.WriteFile(configPath, yamlData, 0644); err != nil {
		t.Fatalf("failed to write test config file: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("unexpected load error: %v", err)
	}

	if cfg.Server.Port != 8088 {
		t.Errorf("expected port 8088, got %d", cfg.Server.Port)
	}
	if cfg.Server.Host != "127.0.0.1" {
		t.Errorf("expected host 127.0.0.1, got %s", cfg.Server.Host)
	}
	if cfg.Server.Address() != "127.0.0.1:8088" {
		t.Errorf("expected address 127.0.0.1:8088, got %s", cfg.Server.Address())
	}
	if cfg.SAML.EntityID != "https://test.samlguard.example/idp" {
		t.Errorf("expected entity ID, got %s", cfg.SAML.EntityID)
	}
}

func TestConfigLoad_InvalidPort(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "invalid_port.yaml")

	yamlData := []byte(`
server:
  port: 70000
saml:
  entity_id: "urn:test"
`)
	if err := os.WriteFile(configPath, yamlData, 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	_, err := Load(configPath)
	if err == nil {
		t.Fatal("expected error for port > 65535, got nil")
	}
}

func TestConfigLoad_MissingEntityID(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "missing_entity_id.yaml")

	yamlData := []byte(`
server:
  port: 8080
saml:
  entity_id: ""
`)
	if err := os.WriteFile(configPath, yamlData, 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	_, err := Load(configPath)
	if err == nil {
		t.Fatal("expected error for empty saml.entity_id, got nil")
	}
}

func TestConfigLoad_TLSMissingCert(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "tls_invalid.yaml")

	yamlData := []byte(`
server:
  port: 8443
tls:
  enabled: true
  cert_file: ""
  key_file: ""
saml:
  entity_id: "urn:test"
`)
	if err := os.WriteFile(configPath, yamlData, 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	_, err := Load(configPath)
	if err == nil {
		t.Fatal("expected error for TLS enabled without cert/key, got nil")
	}
}

func TestConfigRedacted(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		TLS: TLSConfig{
			Enabled:  true,
			CertFile: "/path/to/cert.pem",
			KeyFile:  "/path/to/private.key",
		},
		JWT: JWTConfig{
			Secret: "super-secret-jwt-key-12345",
		},
		MFA: MFAConfig{
			EncryptionKey: "enc-key-abcd",
		},
		Security: SecurityConfig{
			CSRFSecret: "csrf-secret-999",
		},
		Database: DatabaseConfig{
			ConnectionString: "postgres://user:password=secretpass@localhost:5432/db",
		},
	}

	redacted := cfg.Redacted()

	if redacted.JWT.Secret != "[REDACTED]" {
		t.Errorf("expected JWT secret to be redacted, got %s", redacted.JWT.Secret)
	}
	if redacted.TLS.KeyFile != "[REDACTED]" {
		t.Errorf("expected TLS key file to be redacted, got %s", redacted.TLS.KeyFile)
	}
	if redacted.MFA.EncryptionKey != "[REDACTED]" {
		t.Errorf("expected MFA key to be redacted, got %s", redacted.MFA.EncryptionKey)
	}
	if redacted.Security.CSRFSecret != "[REDACTED]" {
		t.Errorf("expected CSRF secret to be redacted, got %s", redacted.Security.CSRFSecret)
	}
	if redacted.Database.ConnectionString != "[REDACTED]" {
		t.Errorf("expected DB password to be redacted, got %s", redacted.Database.ConnectionString)
	}

	// Verify original is untouched
	if cfg.JWT.Secret != "super-secret-jwt-key-12345" {
		t.Errorf("original JWT secret was modified")
	}
}

func TestConfigEnvironmentOverride(t *testing.T) {
	t.Setenv("SAMLGUARD_SERVER_PORT", "9999")
	t.Setenv("SAMLGUARD_SAML_ENTITY_ID", "urn:env:override")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected load error: %v", err)
	}

	if cfg.Server.Port != 9999 {
		t.Errorf("expected port 9999 from environment, got %d", cfg.Server.Port)
	}
	if cfg.SAML.EntityID != "urn:env:override" {
		t.Errorf("expected entity ID from environment, got %s", cfg.SAML.EntityID)
	}
}

func validProdConfig() *Config {
	return &Config{
		Env: "production",
		Server: ServerConfig{
			Port:         8443,
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 15 * time.Second,
		},
		SAML: SAMLConfig{
			EntityID:    "https://samlguard.prod.example/metadata",
			IdPEntityID: "https://login.microsoftonline.com/tenant-123/v2.0",
			IdPSSOURL:   "https://login.microsoftonline.com/tenant-123/saml2",
			ACSURL:      "https://samlguard.prod.example/saml/acs",
		},
		Database: DatabaseConfig{
			Driver: "sqlite",
			Path:   "./data/prod.db",
		},
		MFA: MFAConfig{
			AllowDummyOTP: false,
			EncryptionKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			ServerPepper:  "prod-server-pepper-value",
		},
		SMTP: SMTPConfig{
			Host: "smtp.sendgrid.net",
			Port: 587,
		},
	}
}

func TestConfig_Production_ValidSAMLSettingsPass(t *testing.T) {
	cfg := validProdConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid production config to pass validation, got: %v", err)
	}
}

func TestConfig_Production_MandatoryIdPEntityID(t *testing.T) {
	cfg := validProdConfig()
	cfg.SAML.IdPEntityID = ""
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "saml.idp_entity_id is mandatory in production") {
		t.Fatalf("expected error for empty saml.idp_entity_id in production, got: %v", err)
	}
}

func TestConfig_Production_ProhibitMockIdPEntityID(t *testing.T) {
	cfg := validProdConfig()
	cfg.SAML.IdPEntityID = "https://mock-idp.samlguard.local"
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "mock IdP entity ID") {
		t.Fatalf("expected error for mock IdP entity ID in production, got: %v", err)
	}
}

func TestConfig_Production_ProhibitMockIdPSSOURL(t *testing.T) {
	cfg := validProdConfig()
	cfg.SAML.IdPSSOURL = "https://example.com/mock-idp-login"
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "mock IdP SSO URL cannot be used in production mode") {
		t.Fatalf("expected error for mock IdP SSO URL in production, got: %v", err)
	}
}

func TestConfig_Production_MandatoryACSURL(t *testing.T) {
	cfg := validProdConfig()
	cfg.SAML.ACSURL = ""
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "saml.acs_url is mandatory in production") {
		t.Fatalf("expected error for empty saml.acs_url in production, got: %v", err)
	}
}

func TestConfig_Production_ProhibitRelativeACSURL(t *testing.T) {
	cfg := validProdConfig()
	cfg.SAML.ACSURL = "/saml/acs"
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "must be an absolute URL in production mode") {
		t.Fatalf("expected error for relative /saml/acs in production, got: %v", err)
	}
}

