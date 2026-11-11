package config

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config represents the root configuration schema for SAMLGuard runtime.
type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	TLS      TLSConfig      `mapstructure:"tls"`
	SAML     SAMLConfig     `mapstructure:"saml"`
	Database DatabaseConfig `mapstructure:"database"`
	JWT      JWTConfig      `mapstructure:"jwt"`
	MFA      MFAConfig      `mapstructure:"mfa"`
	Audit    AuditConfig    `mapstructure:"audit"`
	Logging  LoggingConfig  `mapstructure:"logging"`
	Metrics  MetricsConfig  `mapstructure:"metrics"`
	Plugins  PluginsConfig  `mapstructure:"plugins"`
	Security SecurityConfig `mapstructure:"security"`
	SMTP     SMTPConfig     `mapstructure:"smtp"`
	ITA      ITAConfig      `mapstructure:"ita"`
	Env      string         `mapstructure:"env"`

	// Gateway Feature Flags
	EnableStaticMetadata    bool    `mapstructure:"enableStaticMetadata"`
	EnableMetadataDownload  bool    `mapstructure:"enableMetadataDownload"`
	EnableMetadataCache     bool    `mapstructure:"enableMetadataCache"`
	EnableReplayCache       bool    `mapstructure:"enableReplayCache"`
	EnableStrictXML         bool    `mapstructure:"enableStrictXML"`
	CaptureRequests         bool    `mapstructure:"captureRequests"`
	MaximumRequestSize      int     `mapstructure:"maximumRequestSize"`
	MaximumInflatedSize     int     `mapstructure:"maximumInflatedSize"`
	MaximumCompressionRatio float64 `mapstructure:"maximumCompressionRatio"`
}

type ServerConfig struct {
	Host            string        `mapstructure:"host"`
	Port            int           `mapstructure:"port"`
	ReadTimeout     time.Duration `mapstructure:"read_timeout"`
	WriteTimeout    time.Duration `mapstructure:"write_timeout"`
	ShutdownTimeout time.Duration `mapstructure:"shutdown_timeout"`
}

func (s ServerConfig) Address() string {
	if s.Host == "" {
		return fmt.Sprintf(":%d", s.Port)
	}
	return fmt.Sprintf("%s:%d", s.Host, s.Port)
}

type TLSConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	CertFile string `mapstructure:"cert_file"`
	KeyFile  string `mapstructure:"key_file"`
}

type SAMLConfig struct {
	EntityID              string            `mapstructure:"entity_id"`
	Issuer                string            `mapstructure:"issuer"`
	SSOURL                string            `mapstructure:"sso_url"`
	SLOURL                string            `mapstructure:"slo_url"`
	ACSURL                string            `mapstructure:"acs_url"`
	MetadataURL           string            `mapstructure:"metadata_url"`
	CertFile              string            `mapstructure:"cert_file"`
	KeyFile               string            `mapstructure:"key_file"`
	SignRequests          bool              `mapstructure:"sign_requests"`
	SignAssertions        bool              `mapstructure:"sign_assertions"`
	SignResponses         bool              `mapstructure:"sign_responses"`
	IdPMetadataURL        string            `mapstructure:"idp_metadata_url"`
	IdPEntityID           string            `mapstructure:"idp_entity_id"`
	IdPSSOURL             string            `mapstructure:"idp_sso_url"`
	IdPCertFile           string            `mapstructure:"idp_cert_file"`
	AllowedAudiences      []string          `mapstructure:"allowed_audiences"`
	GroupMapping          map[string]string `mapstructure:"group_mapping"`
	DefaultGroups         []string          `mapstructure:"default_groups"`
	AuthnContextClassRef  string            `mapstructure:"authn_context_class_ref"`
	SPEntityID            string            `mapstructure:"sp_entity_id"`
}

type DatabaseConfig struct {
	Driver            string `mapstructure:"driver"`
	ConnectionString  string `mapstructure:"connection_string"`
	Path              string `mapstructure:"path"`
	MaxIdleConns      int    `mapstructure:"max_idle_conns"`
	MaxOpenConns      int    `mapstructure:"max_open_conns"`
	EnableForeignKeys bool   `mapstructure:"enable_foreign_keys"`
}

type JWTConfig struct {
	Secret             string        `mapstructure:"secret"`
	Expiration         time.Duration `mapstructure:"expiration"`
	PrivateKeyFile     string        `mapstructure:"private_key_file"`
	PublicKeyFile      string        `mapstructure:"public_key_file"`
	AccessTokenExpiry  time.Duration `mapstructure:"access_token_expiry"`
	RefreshTokenExpiry time.Duration `mapstructure:"refresh_token_expiry"`
	Issuer             string        `mapstructure:"issuer"`
}

type MFAConfig struct {
	DefaultProvider  string        `mapstructure:"default_provider"`
	Timeout          time.Duration `mapstructure:"timeout"`
	Issuer           string        `mapstructure:"issuer"`
	MaxRetries       int           `mapstructure:"max_retries"`
	OTPExpiry        time.Duration `mapstructure:"otp_expiry"`
	OTPLength        int           `mapstructure:"otp_length"`
	BackupCodeCount  int           `mapstructure:"backup_code_count"`
	BackupCodeLength int           `mapstructure:"backup_code_length"`
	RateLimitWindow  time.Duration `mapstructure:"rate_limit_window"`
	TrustDeviceDays  int           `mapstructure:"trust_device_days"`
	EncryptionKey    string        `mapstructure:"encryption_key"`
	TOTPSkew         uint          `mapstructure:"totp_skew"`
	AllowDummyOTP    bool          `mapstructure:"allow_dummy_otp"`
	ResendCooldown   time.Duration `mapstructure:"resend_cooldown"`
	ServerPepper     string        `mapstructure:"server_pepper"`
}

type SMTPConfig struct {
	Host       string `mapstructure:"host"`
	Port       int    `mapstructure:"port"`
	Username   string `mapstructure:"username"`
	Password   string `mapstructure:"password"`
	From       string `mapstructure:"from"`
	FromName   string `mapstructure:"from_name"`
	Encryption string `mapstructure:"encryption"` // "starttls", "tls", "none"
}

type ITAConfig struct {
	APIURL               string        `mapstructure:"api_url"`
	APIUsername          string        `mapstructure:"api_username"`
	APIPassword          string        `mapstructure:"api_password"`
	EnforceUserWhitelist bool          `mapstructure:"enforce_user_whitelist"`
	AutoSyncInterval     time.Duration `mapstructure:"auto_sync_interval"`
	ManualAllowedUsers   []string      `mapstructure:"manual_allowed_users"`
}

func (c *Config) IsProduction() bool {
	if c == nil {
		return false
	}
	env := strings.ToLower(strings.TrimSpace(c.Env))
	if env == "production" || env == "prod" {
		return true
	}
	for _, envVar := range []string{"SAMLGUARD_ENV", "APP_ENV", "ENV"} {
		v := strings.ToLower(strings.TrimSpace(os.Getenv(envVar)))
		if v == "production" || v == "prod" {
			return true
		}
	}
	return false
}

type AuditConfig struct {
	Enabled bool `mapstructure:"enabled"`
	Async   bool `mapstructure:"async"`
}

type LoggingConfig struct {
	Level      string `mapstructure:"level"`
	Format     string `mapstructure:"format"`
	OutputPath string `mapstructure:"output_path"`
}

type MetricsConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Path    string `mapstructure:"path"`
}

type PluginsConfig struct {
	Directory string `mapstructure:"directory"`
}

type SecurityConfig struct {
	CSRFSecret         string   `mapstructure:"csrf_secret"`
	CORSAllowedOrigins []string `mapstructure:"cors_allowed_origins"`
	RateLimit          int      `mapstructure:"rate_limit"`
}

// SetDefaults configures sensible runtime defaults
func SetDefaults(v *viper.Viper) {
	v.SetDefault("server.host", "0.0.0.0")
	v.SetDefault("server.port", 8080)
	v.SetDefault("server.read_timeout", 15*time.Second)
	v.SetDefault("server.write_timeout", 15*time.Second)
	v.SetDefault("server.shutdown_timeout", 15*time.Second)
	v.SetDefault("server.tls_enabled", false)

	v.SetDefault("saml.entity_id", "urn:samlguard:idp")
	v.SetDefault("saml.issuer", "samlguard")
	v.SetDefault("saml.sso_url", "http://localhost:8080/saml/sso")
	v.SetDefault("saml.sign_requests", true)
	v.SetDefault("saml.sign_assertions", true)
	v.SetDefault("saml.sign_responses", true)
	v.SetDefault("saml.authn_context_class_ref", "urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken")

	v.SetDefault("database.driver", "sqlite")
	v.SetDefault("database.connection_string", "file:data/samlguard.db?cache=shared&mode=rwc")
	v.SetDefault("database.path", "./data/samlguard.db")
	v.SetDefault("database.max_idle_conns", 5)
	v.SetDefault("database.max_open_conns", 10)
	v.SetDefault("database.enable_foreign_keys", true)

	v.SetDefault("jwt.secret", "change-me-in-production")
	v.SetDefault("jwt.expiration", 24*time.Hour)
	v.SetDefault("jwt.access_token_expiry", 15*time.Minute)
	v.SetDefault("jwt.refresh_token_expiry", 24*time.Hour)
	v.SetDefault("jwt.issuer", "samlguard")

	v.SetDefault("mfa.default_provider", "totp")
	v.SetDefault("mfa.timeout", 5*time.Minute)
	v.SetDefault("mfa.issuer", "SAMLGuard")
	v.SetDefault("mfa.max_retries", 5)
	v.SetDefault("mfa.otp_expiry", 5*time.Minute)
	v.SetDefault("mfa.otp_length", 6)
	v.SetDefault("mfa.backup_code_count", 10)
	v.SetDefault("mfa.backup_code_length", 8)
	v.SetDefault("mfa.rate_limit_window", 15*time.Minute)
	v.SetDefault("mfa.trust_device_days", 30)
	v.SetDefault("mfa.totp_skew", 1)
	v.SetDefault("mfa.allow_dummy_otp", false)
	v.SetDefault("mfa.resend_cooldown", 60*time.Second)

	v.SetDefault("smtp.port", 587)
	v.SetDefault("smtp.encryption", "starttls")

	v.SetDefault("ita.api_url", "https://ita.example.com/api/current")
	v.SetDefault("ita.api_username", "apc")
	v.SetDefault("ita.enforce_user_whitelist", true)
	v.SetDefault("ita.auto_sync_interval", 30*time.Minute)
	v.SetDefault("ita.manual_allowed_users", []string{"apc", "itaadmin"})

	v.SetDefault("audit.enabled", true)
	v.SetDefault("audit.async", true)

	v.SetDefault("logging.level", "info")
	v.SetDefault("logging.format", "json")
	v.SetDefault("logging.output_path", "stdout")

	v.SetDefault("metrics.enabled", true)
	v.SetDefault("metrics.path", "/metrics")

	v.SetDefault("plugins.directory", "./plugins")

	v.SetDefault("security.cors_allowed_origins", []string{"*"})
	v.SetDefault("security.rate_limit", 100)

	// Gateway limits and defaults
	v.SetDefault("maximumRequestSize", 256*1024)     // 256KB
	v.SetDefault("maximumInflatedSize", 2*1024*1024) // 2MB
	v.SetDefault("maximumCompressionRatio", 20.0)
}

// Load loads configuration from file, environment-specific overrides, and environment variables.
func Load(paths ...string) (*Config, error) {
	v := viper.New()
	SetDefaults(v)

	v.SetConfigType("yaml")
	v.SetEnvPrefix("SAMLGUARD")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// 1. Determine configuration file path
	var explicitPath string
	if len(paths) > 0 && paths[0] != "" {
		explicitPath = paths[0]
	} else if envPath := os.Getenv("SAMLGUARD_CONFIG_PATH"); envPath != "" {
		explicitPath = envPath
	} else if envPath := os.Getenv("CONFIG_PATH"); envPath != "" {
		explicitPath = envPath
	}

	if explicitPath != "" {
		v.SetConfigFile(explicitPath)
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("reading specified config file %q: %w", explicitPath, err)
		}
	} else {
		// Look for default config files in standard search locations
		var candidateFiles []string

		// 1. Executable-relative paths (critical when running as a system service with arbitrary working dir)
		if exePath, err := os.Executable(); err == nil {
			exeDir := filepath.Dir(exePath)
			candidateFiles = append(candidateFiles,
				filepath.Join(exeDir, "configs", "config.yaml"),
				filepath.Join(exeDir, "configs", "default.yaml"),
				filepath.Join(exeDir, "config.yaml"),
				filepath.Join(exeDir, "default.yaml"),
			)
		}

		// 2. Working directory relative paths
		candidateFiles = append(candidateFiles,
			"configs/config.yaml",
			"./configs/config.yaml",
			"configs/default.yaml",
			"./configs/default.yaml",
			"config.yaml",
			"default.yaml",
		)

		// 3. Windows standard directory (%ProgramData%\SAMLGuard)
		if programData := os.Getenv("ProgramData"); programData != "" {
			candidateFiles = append(candidateFiles,
				filepath.Join(programData, "SAMLGuard", "config.yaml"),
				filepath.Join(programData, "SAMLGuard", "default.yaml"),
			)
		}

		// 4. Linux standard directory (/etc/samlguard)
		candidateFiles = append(candidateFiles,
			"/etc/samlguard/config.yaml",
			"/etc/samlguard/default.yaml",
		)

		loaded := false
		for _, candidate := range candidateFiles {
			if fileExists(candidate) {
				v.SetConfigFile(candidate)
				if err := v.ReadInConfig(); err == nil {
					loaded = true
					break
				}
			}
		}
		// If no default file was found, continue with defaults + environment
		_ = loaded
	}

	// 2. Load environment-specific overlay if applicable (e.g. development, production)
	envName := strings.ToLower(os.Getenv("SAMLGUARD_ENV"))
	if envName == "" {
		envName = strings.ToLower(os.Getenv("APP_ENV"))
	}
	if envName == "" {
		envName = strings.ToLower(os.Getenv("ENV"))
	}

	if envName != "" {
		var envCandidates []string
		if exePath, err := os.Executable(); err == nil {
			exeDir := filepath.Dir(exePath)
			envCandidates = append(envCandidates,
				filepath.Join(exeDir, "configs", envName+".yaml"),
				filepath.Join(exeDir, envName+".yaml"),
			)
		}
		envCandidates = append(envCandidates,
			filepath.Join("configs", envName+".yaml"),
			filepath.Join(".", "configs", envName+".yaml"),
			envName+".yaml",
		)
		if programData := os.Getenv("ProgramData"); programData != "" {
			envCandidates = append(envCandidates,
				filepath.Join(programData, "SAMLGuard", envName+".yaml"),
			)
		}
		envCandidates = append(envCandidates,
			filepath.Join("/etc/samlguard", envName+".yaml"),
		)

		for _, envFile := range envCandidates {
			if fileExists(envFile) {
				v.SetConfigFile(envFile)
				_ = v.MergeInConfig()
				break
			}
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshaling config: %w", err)
	}

	// Backwards compatibility for legacy configs with server.tls_enabled / server.tls_cert_file / server.tls_key_file
	if v.GetBool("server.tls_enabled") && !cfg.TLS.Enabled {
		cfg.TLS.Enabled = true
		if cfg.TLS.CertFile == "" {
			cfg.TLS.CertFile = v.GetString("server.tls_cert_file")
		}
		if cfg.TLS.KeyFile == "" {
			cfg.TLS.KeyFile = v.GetString("server.tls_key_file")
		}
	}

	// Apply limit fallbacks if set to <= 0
	if cfg.MaximumRequestSize <= 0 {
		cfg.MaximumRequestSize = 256 * 1024
	}
	if cfg.MaximumInflatedSize <= 0 {
		cfg.MaximumInflatedSize = 2 * 1024 * 1024
	}
	if cfg.MaximumCompressionRatio <= 0 {
		cfg.MaximumCompressionRatio = 20.0
	}

	// 3. Validate mandatory configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &cfg, nil
}

// Validate ensures all mandatory runtime configuration parameters are valid
func (c *Config) Validate() error {
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return fmt.Errorf("server.port must be between 1 and 65535, got %d", c.Server.Port)
	}

	if c.Server.ReadTimeout < 0 {
		return errors.New("server.read_timeout cannot be negative")
	}

	if c.Server.WriteTimeout < 0 {
		return errors.New("server.write_timeout cannot be negative")
	}

	if strings.TrimSpace(c.SAML.EntityID) == "" {
		return errors.New("saml.entity_id is mandatory and cannot be empty")
	}

	if c.TLS.Enabled {
		if strings.TrimSpace(c.TLS.CertFile) == "" {
			return errors.New("tls.cert_file is required when TLS is enabled")
		}
		if strings.TrimSpace(c.TLS.KeyFile) == "" {
			return errors.New("tls.key_file is required when TLS is enabled")
		}
	}

	if c.Database.Driver == "" && c.Database.ConnectionString == "" && c.Database.Path == "" {
		return errors.New("database configuration is mandatory")
	}

	if c.IsProduction() {
		if c.MFA.AllowDummyOTP {
			return errors.New("security violation: mfa.allow_dummy_otp must be false in production mode")
		}
		trimmedKey := strings.TrimSpace(c.MFA.EncryptionKey)
		if trimmedKey == "" {
			return errors.New("security violation: mfa.encryption_key is mandatory in production mode")
		}
		keyBytes, err := hex.DecodeString(trimmedKey)
		if err != nil || len(keyBytes) != 32 {
			return errors.New("security violation: mfa.encryption_key must be a valid 64-character (32-byte) hex-encoded key in production mode")
		}
		if strings.TrimSpace(c.MFA.ServerPepper) == "" {
			return errors.New("security violation: mfa.server_pepper is mandatory in production mode")
		}
		host := strings.TrimSpace(strings.ToLower(c.SMTP.Host))
		if host == "" || host == "localhost" || host == "127.0.0.1" {
			return errors.New("security violation: smtp.host must be configured with a real external SMTP server in production mode")
		}

		// SAML Production Mandatory Settings & Mock Fallback Prohibitions
		if strings.TrimSpace(c.SAML.IdPEntityID) == "" {
			return errors.New("security violation: saml.idp_entity_id is mandatory in production mode")
		}
		if strings.EqualFold(strings.TrimSpace(c.SAML.IdPEntityID), "https://mock-idp.samlguard.local") {
			return errors.New("security violation: mock IdP entity ID (https://mock-idp.samlguard.local) cannot be used in production mode")
		}
		if strings.Contains(strings.ToLower(c.SAML.IdPSSOURL), "mock-idp") {
			return errors.New("security violation: mock IdP SSO URL cannot be used in production mode")
		}

		// HTTPS Enforcement for external SAML endpoints in production
		if err := requireHTTPS("saml.acs_url", c.SAML.ACSURL); err != nil {
			return err
		}
		if err := requireHTTPS("saml.idp_sso_url", c.SAML.IdPSSOURL); err != nil {
			return err
		}
		if err := requireHTTPS("saml.sso_url", c.SAML.SSOURL); err != nil {
			return err
		}
	}

	return nil
}

func requireHTTPS(paramName, rawURL string) error {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return fmt.Errorf("security violation: %s is mandatory in production mode", paramName)
	}
	lower := strings.ToLower(trimmed)
	if !strings.HasPrefix(lower, "https://") {
		if strings.HasPrefix(lower, "http://") {
			return fmt.Errorf("security violation: %s must use HTTPS in production mode (HTTP is rejected)", paramName)
		}
		return fmt.Errorf("security violation: %s must be an absolute HTTPS URL in production mode (relative URLs rejected)", paramName)
	}
	return nil
}

// Redacted returns a sanitized copy of Config with secrets safely masked for logging
func (c *Config) Redacted() *Config {
	if c == nil {
		return nil
	}
	copy := *c

	if copy.JWT.Secret != "" {
		copy.JWT.Secret = "[REDACTED]"
	}
	if copy.TLS.KeyFile != "" {
		copy.TLS.KeyFile = "[REDACTED]"
	}
	if copy.Security.CSRFSecret != "" {
		copy.Security.CSRFSecret = "[REDACTED]"
	}
	if copy.MFA.EncryptionKey != "" {
		copy.MFA.EncryptionKey = "[REDACTED]"
	}
	if copy.MFA.ServerPepper != "" {
		copy.MFA.ServerPepper = "[REDACTED]"
	}
	if copy.SMTP.Password != "" {
		copy.SMTP.Password = "[REDACTED]"
	}
	if strings.Contains(copy.Database.ConnectionString, "password=") {
		copy.Database.ConnectionString = "[REDACTED]"
	}

	return &copy
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

// ResolveDownstreamSPEntityID determines the canonical downstream Service Provider
// EntityID/origin from configured SAML or ITA URLs without relying on hardcoded host IPs.
func (c *Config) ResolveDownstreamSPEntityID() string {
	if c == nil {
		return "https://ita.example.com"
	}
	if sp := strings.TrimSpace(c.SAML.SPEntityID); sp != "" {
		return sp
	}
	if len(c.SAML.AllowedAudiences) > 0 {
		if aud := strings.TrimSpace(c.SAML.AllowedAudiences[0]); aud != "" {
			return aud
		}
	}
	for _, rawURL := range []string{c.SAML.ACSURL, c.ITA.APIURL} {
		if origin := extractURLOrigin(rawURL); origin != "" {
			return origin
		}
	}
	return "https://ita.example.com"
}

// DownstreamSPOrigins returns all known downstream SP entity IDs and origins
// derived from configuration for metadata and provider resolution.
func (c *Config) DownstreamSPOrigins() []string {
	if c == nil {
		return nil
	}
	seen := make(map[string]struct{})
	var out []string
	add := func(val string) {
		val = strings.TrimSpace(val)
		if val == "" {
			return
		}
		if _, ok := seen[val]; !ok {
			seen[val] = struct{}{}
			out = append(out, val)
		}
	}
	add(c.SAML.EntityID)
	add(c.SAML.SPEntityID)
	for _, aud := range c.SAML.AllowedAudiences {
		add(aud)
	}
	add(extractURLOrigin(c.SAML.ACSURL))
	add(extractURLOrigin(c.ITA.APIURL))
	return out
}

func extractURLOrigin(rawURL string) string {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return ""
	}
	if u, err := url.Parse(trimmed); err == nil && u.Scheme != "" && u.Host != "" {
		return u.Scheme + "://" + u.Host
	}
	return ""
}
