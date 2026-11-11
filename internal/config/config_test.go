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
			SSOURL:      "https://samlguard.prod.example/saml/sso",
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

func TestConfig_Development_AllowsHTTPLocalhost(t *testing.T) {
	cfg := validProdConfig()
	cfg.Env = "development"
	cfg.SAML.ACSURL = "http://localhost:8080/saml/acs"
	cfg.SAML.SSOURL = "http://localhost:8080/saml/sso"
	cfg.SAML.IdPSSOURL = "http://localhost:8080/mock-idp"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected HTTP localhost URLs to be allowed in development mode, got: %v", err)
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

func TestConfig_Production_ACSURL_RejectsHTTP(t *testing.T) {
	cfg := validProdConfig()
	cfg.SAML.ACSURL = "http://samlguard.prod.example/saml/acs"
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "saml.acs_url must use HTTPS in production mode") {
		t.Fatalf("expected error for HTTP saml.acs_url in production, got: %v", err)
	}
}

func TestConfig_Production_ACSURL_RejectsRelative(t *testing.T) {
	cfg := validProdConfig()
	cfg.SAML.ACSURL = "/saml/acs"
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "must be an absolute HTTPS URL in production mode") {
		t.Fatalf("expected error for relative /saml/acs in production, got: %v", err)
	}
}

func TestConfig_Production_IdPSSOURL_RejectsHTTP(t *testing.T) {
	cfg := validProdConfig()
	cfg.SAML.IdPSSOURL = "http://login.microsoftonline.com/tenant-123/saml2"
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "saml.idp_sso_url must use HTTPS in production mode") {
		t.Fatalf("expected error for HTTP saml.idp_sso_url in production, got: %v", err)
	}
}

func TestConfig_Production_IdPSSOURL_RejectsRelative(t *testing.T) {
	cfg := validProdConfig()
	cfg.SAML.IdPSSOURL = "/idp/sso"
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "must be an absolute HTTPS URL in production mode") {
		t.Fatalf("expected error for relative saml.idp_sso_url in production, got: %v", err)
	}
}

func TestConfig_Production_SSOURL_RejectsHTTP(t *testing.T) {
	cfg := validProdConfig()
	cfg.SAML.SSOURL = "http://samlguard.prod.example/saml/sso"
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "saml.sso_url must use HTTPS in production mode") {
		t.Fatalf("expected error for HTTP saml.sso_url in production, got: %v", err)
	}
}

func TestConfig_Production_SSOURL_RejectsRelative(t *testing.T) {
	cfg := validProdConfig()
	cfg.SAML.SSOURL = "/saml/sso"
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "must be an absolute HTTPS URL in production mode") {
		t.Fatalf("expected error for relative saml.sso_url in production, got: %v", err)
	}
}

func TestConfig_Production_SSOURL_Mandatory(t *testing.T) {
	cfg := validProdConfig()
	cfg.SAML.SSOURL = ""
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "saml.sso_url is mandatory in production") {
		t.Fatalf("expected error for empty saml.sso_url in production, got: %v", err)
	}
}

func TestConfig_ExplicitCLIPath(t *testing.T) {
	dir := t.TempDir()
	customPath := filepath.Join(dir, "custom_cli.yaml")
	yamlData := []byte(`
server:
  port: 8999
saml:
  entity_id: "urn:test:cli"
`)
	if err := os.WriteFile(customPath, yamlData, 0644); err != nil {
		t.Fatalf("failed to write custom config: %v", err)
	}

	cfg, err := Load(customPath)
	if err != nil {
		t.Fatalf("expected Load to succeed with explicit CLI path, got error: %v", err)
	}
	if cfg.Server.Port != 8999 {
		t.Errorf("expected port 8999 from CLI path, got %d", cfg.Server.Port)
	}
	if cfg.SAML.EntityID != "urn:test:cli" {
		t.Errorf("expected entity ID urn:test:cli, got %s", cfg.SAML.EntityID)
	}
}

func TestConfig_EnvironmentVariablePath(t *testing.T) {
	dir := t.TempDir()
	customPath := filepath.Join(dir, "custom_env.yaml")
	yamlData := []byte(`
server:
  port: 8877
saml:
  entity_id: "urn:test:env_path"
`)
	if err := os.WriteFile(customPath, yamlData, 0644); err != nil {
		t.Fatalf("failed to write custom config: %v", err)
	}

	t.Setenv("SAMLGUARD_CONFIG_PATH", customPath)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("expected Load to succeed with SAMLGUARD_CONFIG_PATH, got error: %v", err)
	}
	if cfg.Server.Port != 8877 {
		t.Errorf("expected port 8877 from env path, got %d", cfg.Server.Port)
	}
	if cfg.SAML.EntityID != "urn:test:env_path" {
		t.Errorf("expected entity ID urn:test:env_path, got %s", cfg.SAML.EntityID)
	}
}

func TestConfig_ProgramDataLookup(t *testing.T) {
	fakeProgramData := t.TempDir()
	samlguardDir := filepath.Join(fakeProgramData, "SAMLGuard")
	if err := os.MkdirAll(samlguardDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	configPath := filepath.Join(samlguardDir, "config.yaml")
	yamlData := []byte(`
server:
  port: 8765
saml:
  entity_id: "urn:test:programdata"
`)
	if err := os.WriteFile(configPath, yamlData, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	t.Setenv("ProgramData", fakeProgramData)
	// Temporarily switch working dir to an empty temp dir so local configs aren't found
	origDir, _ := os.Getwd()
	emptyDir := t.TempDir()
	_ = os.Chdir(emptyDir)
	defer os.Chdir(origDir)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("expected Load to discover config in ProgramData, got error: %v", err)
	}
	if cfg.Server.Port != 8765 {
		t.Errorf("expected port 8765 from ProgramData, got %d", cfg.Server.Port)
	}
}

func TestConfig_Production_RejectsPlaceholderServerPepper(t *testing.T) {
	placeholders := []string{
		"CHANGE_ME_GENERATE_HIGH_ENTROPY_SERVER_PEPPER",
		"samlguard-default-server-pepper-secret-key",
	}
	for _, placeholder := range placeholders {
		cfg := validProdConfig()
		cfg.MFA.ServerPepper = placeholder
		if err := cfg.Validate(); err == nil {
			t.Fatalf("expected production config validation to reject placeholder ServerPepper %q", placeholder)
		}
	}
}

func TestConfig_IsAllowedDownstreamACSURL(t *testing.T) {
	cfg := validProdConfig()
	cfg.SAML.ACSURL = "https://ita.example.com/api/current/authentication/saml2-callback"
	cfg.SAML.DownstreamACSURLs = []string{"https://ita-dr.example.com/api/current/authentication/saml2-callback"}

	if !cfg.IsAllowedDownstreamACSURL("https://ita.example.com/api/current/authentication/saml2-callback") {
		t.Error("expected configured SAML.ACSURL to be allowed")
	}
	if !cfg.IsAllowedDownstreamACSURL("https://ita-dr.example.com/api/current/authentication/saml2-callback") {
		t.Error("expected configured DownstreamACSURLs entry to be allowed")
	}
	if !cfg.IsAllowedDownstreamACSURL("https://ita-meta.example.com/callback", "https://ita-meta.example.com/callback") {
		t.Error("expected metadata endpoint to be allowed")
	}
	if cfg.IsAllowedDownstreamACSURL("https://evil.attacker.example/callback") {
		t.Error("expected untrusted ACS URL to be rejected")
	}
	if cfg.IsAllowedDownstreamACSURL("") {
		t.Error("expected empty candidate ACS URL to be rejected")
	}
}

func TestConfig_TrustedProxiesAndCSPFormAction(t *testing.T) {
	cfg := validProdConfig()
	cfg.Security.TrustedProxies = []string{"10.0.0.1", "192.168.10.0/24"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid trusted proxies to pass, got: %v", err)
	}

	cfgBad := validProdConfig()
	cfgBad.Security.TrustedProxies = []string{"not-an-ip-or-cidr"}
	if err := cfgBad.Validate(); err == nil {
		t.Fatal("expected invalid trusted proxy entry to fail validation")
	}

	cfg.SAML.ACSURL = "https://ita.example.com/api/current/authentication/saml2-callback"
	cfg.SAML.IdPSSOURL = "https://login.microsoftonline.com/tenant/saml2"
	csp := cfg.AllowedCSPFormAction()
	if strings.Contains(csp, "*") {
		t.Fatalf("AllowedCSPFormAction must not return wildcard '*': %s", csp)
	}
	if !strings.Contains(csp, "'self'") ||
		!strings.Contains(csp, "https://ita.example.com") ||
		!strings.Contains(csp, "https://login.microsoftonline.com") {
		t.Fatalf("unexpected AllowedCSPFormAction output: %s", csp)
	}
}

func TestConfig_Phase3_ITATLSAndMetricsRedaction(t *testing.T) {
	cfg := validProdConfig()
	cfg.ITA.TLSInsecureSkipVerify = true
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "tls_insecure_skip_verify") {
		t.Fatalf("expected error for ita.tls_insecure_skip_verify in production, got: %v", err)
	}

	cfg = validProdConfig()
	cfg.ITA.TLSCAFile = filepath.Join(t.TempDir(), "missing-ca.pem")
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "ita.tls_ca_file") {
		t.Fatalf("expected error for missing ita.tls_ca_file, got: %v", err)
	}

	caPath := filepath.Join(t.TempDir(), "ita-ca.pem")
	if err := os.WriteFile(caPath, []byte("dummy-ca"), 0o600); err != nil {
		t.Fatalf("write dummy CA file: %v", err)
	}
	cfg.ITA.TLSCAFile = caPath
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid ita.tls_ca_file to pass, got: %v", err)
	}

	cfg.ITA.APIPassword = "ita-secret-password"
	cfg.Metrics.BearerToken = "metrics-secret-token"
	redacted := cfg.Redacted()
	if redacted.ITA.APIPassword == "ita-secret-password" || redacted.Metrics.BearerToken == "metrics-secret-token" {
		t.Fatalf("expected ITA.APIPassword and Metrics.BearerToken to be masked in Redacted()")
	}
	if cfg.ITA.APIPassword != "ita-secret-password" || cfg.Metrics.BearerToken != "metrics-secret-token" {
		t.Fatalf("expected Redacted() not to mutate original Config")
	}
}

