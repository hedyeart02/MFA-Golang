// Package config provides centralized configuration management using Viper.
// It supports config.yaml files, environment variables, and Docker secrets
// with a clear precedence order: env > file > defaults.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config holds all application configuration.
type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	Database DatabaseConfig `mapstructure:"database"`
	SAML     SAMLConfig     `mapstructure:"saml"`
	JWT      JWTConfig      `mapstructure:"jwt"`
	MFA      MFAConfig      `mapstructure:"mfa"`
	Session  SessionConfig  `mapstructure:"session"`
	Services ServicesConfig `mapstructure:"services"`
	Logging  LoggingConfig  `mapstructure:"logging"`
	Security SecurityConfig `mapstructure:"security"`
}

// ServerConfig holds HTTP server settings.
type ServerConfig struct {
	Host            string        `mapstructure:"host"`
	Port            int           `mapstructure:"port"`
	ReadTimeout     time.Duration `mapstructure:"read_timeout"`
	WriteTimeout    time.Duration `mapstructure:"write_timeout"`
	ShutdownTimeout time.Duration `mapstructure:"shutdown_timeout"`
	TLSCertFile     string        `mapstructure:"tls_cert_file"`
	TLSKeyFile      string        `mapstructure:"tls_key_file"`
	TLSEnabled      bool          `mapstructure:"tls_enabled"`
}

// DatabaseConfig holds database connection settings.
type DatabaseConfig struct {
	Path            string `mapstructure:"path"`
	MaxIdleConns    int    `mapstructure:"max_idle_conns"`
	MaxOpenConns    int    `mapstructure:"max_open_conns"`
	EnableForeignKs bool   `mapstructure:"enable_foreign_keys"`
}

// SAMLConfig holds SAML 2.0 configuration.
type SAMLConfig struct {
	EntityID       string `mapstructure:"entity_id"`
	ACSURL         string `mapstructure:"acs_url"`
	SSOURL         string `mapstructure:"sso_url"`
	SLOURL         string `mapstructure:"slo_url"`
	MetadataURL    string `mapstructure:"metadata_url"`
	CertFile       string `mapstructure:"cert_file"`
	KeyFile        string `mapstructure:"key_file"`
	SignRequests   bool   `mapstructure:"sign_requests"`
	SignAssertions bool   `mapstructure:"sign_assertions"`
	SignResponses  bool   `mapstructure:"sign_responses"`
	IdPMetadataURL string `mapstructure:"idp_metadata_url"`
	IdPEntityID    string `mapstructure:"idp_entity_id"`
	IdPSSOURL      string `mapstructure:"idp_sso_url"`
	IdPCertFile    string `mapstructure:"idp_cert_file"`
	AllowedAudiences []string `mapstructure:"allowed_audiences"`
}

// JWTConfig holds JWT token settings.
type JWTConfig struct {
	PrivateKeyFile       string        `mapstructure:"private_key_file"`
	PublicKeyFile        string        `mapstructure:"public_key_file"`
	AccessTokenExpiry    time.Duration `mapstructure:"access_token_expiry"`
	RefreshTokenExpiry   time.Duration `mapstructure:"refresh_token_expiry"`
	Issuer               string        `mapstructure:"issuer"`
}

// MFAConfig holds MFA settings.
type MFAConfig struct {
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
}

// SessionConfig holds session management settings.
type SessionConfig struct {
	IdleTimeout     time.Duration `mapstructure:"idle_timeout"`
	AbsoluteTimeout time.Duration `mapstructure:"absolute_timeout"`
	CookieName      string        `mapstructure:"cookie_name"`
	CookieDomain    string        `mapstructure:"cookie_domain"`
	CookiePath      string        `mapstructure:"cookie_path"`
	CookieSecure    bool          `mapstructure:"cookie_secure"`
	CookieHTTPOnly  bool          `mapstructure:"cookie_httponly"`
	CookieSameSite  string        `mapstructure:"cookie_samesite"`
}

// ServicesConfig holds internal service endpoints.
type ServicesConfig struct {
	AuthURL    string `mapstructure:"auth_url"`
	MFAURL     string `mapstructure:"mfa_url"`
	SessionURL string `mapstructure:"session_url"`
	AuditURL   string `mapstructure:"audit_url"`
	APIKey     string `mapstructure:"api_key"`
	Timeout    time.Duration `mapstructure:"timeout"`
}

// LoggingConfig holds logging settings.
type LoggingConfig struct {
	Level      string `mapstructure:"level"`
	Format     string `mapstructure:"format"`
	OutputPath string `mapstructure:"output_path"`
}

// SecurityConfig holds security-related settings.
type SecurityConfig struct {
	CSRFSecret    string `mapstructure:"csrf_secret"`
	AllowedOrigins []string `mapstructure:"allowed_origins"`
	RateLimit     int    `mapstructure:"rate_limit"`
}

// Load reads configuration from the given path, environment variables,
// and Docker secrets. It returns a fully populated Config struct.
func Load(configPath string) (*Config, error) {
	v := viper.New()

	setDefaults(v)

	v.SetConfigType("yaml")

	if configPath != "" {
		v.SetConfigFile(configPath)
	} else {
		v.SetConfigName("config")
		v.AddConfigPath("./configs")
		v.AddConfigPath("/etc/samlguard")
		v.AddConfigPath(".")
	}

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("reading config file: %w", err)
		}
	}

	v.SetEnvPrefix("SAMLGUARD")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	if err := loadDockerSecrets(v, "/run/secrets"); err != nil {
		return nil, fmt.Errorf("loading docker secrets: %w", err)
	}

	cfg := &Config{}
	if err := v.Unmarshal(cfg); err != nil {
		return nil, fmt.Errorf("unmarshaling config: %w", err)
	}

	if err := validate(cfg); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	return cfg, nil
}

// setDefaults configures sensible defaults for all configuration values.
func setDefaults(v *viper.Viper) {
	// Server defaults
	v.SetDefault("server.host", "0.0.0.0")
	v.SetDefault("server.port", 8080)
	v.SetDefault("server.read_timeout", 30*time.Second)
	v.SetDefault("server.write_timeout", 30*time.Second)
	v.SetDefault("server.shutdown_timeout", 15*time.Second)
	v.SetDefault("server.tls_enabled", false)

	// Database defaults
	v.SetDefault("database.path", "./data/samlguard.db")
	v.SetDefault("database.max_idle_conns", 5)
	v.SetDefault("database.max_open_conns", 10)
	v.SetDefault("database.enable_foreign_keys", true)

	// JWT defaults
	v.SetDefault("jwt.access_token_expiry", 15*time.Minute)
	v.SetDefault("jwt.refresh_token_expiry", 24*time.Hour)
	v.SetDefault("jwt.issuer", "samlguard")

	// MFA defaults
	v.SetDefault("mfa.issuer", "SAMLGuard")
	v.SetDefault("mfa.max_retries", 5)
	v.SetDefault("mfa.otp_expiry", 5*time.Minute)
	v.SetDefault("mfa.otp_length", 6)
	v.SetDefault("mfa.backup_code_count", 10)
	v.SetDefault("mfa.backup_code_length", 8)
	v.SetDefault("mfa.rate_limit_window", 15*time.Minute)
	v.SetDefault("mfa.trust_device_days", 30)
	v.SetDefault("mfa.totp_skew", 1)

	// Session defaults
	v.SetDefault("session.idle_timeout", 30*time.Minute)
	v.SetDefault("session.absolute_timeout", 12*time.Hour)
	v.SetDefault("session.cookie_name", "samlguard_session")
	v.SetDefault("session.cookie_path", "/")
	v.SetDefault("session.cookie_secure", true)
	v.SetDefault("session.cookie_httponly", true)
	v.SetDefault("session.cookie_samesite", "Strict")

	// Services defaults
	v.SetDefault("services.auth_url", "http://localhost:8081")
	v.SetDefault("services.mfa_url", "http://localhost:8082")
	v.SetDefault("services.session_url", "http://localhost:8083")
	v.SetDefault("services.audit_url", "http://localhost:8084")
	v.SetDefault("services.timeout", 10*time.Second)

	// Logging defaults
	v.SetDefault("logging.level", "info")
	v.SetDefault("logging.format", "json")
	v.SetDefault("logging.output_path", "stdout")

	// SAML defaults
	v.SetDefault("saml.sign_requests", true)
	v.SetDefault("saml.sign_assertions", true)
	v.SetDefault("saml.sign_responses", true)

	// Security defaults
	v.SetDefault("security.rate_limit", 100)
}

// loadDockerSecrets reads files from the Docker secrets directory and
// sets their contents as configuration values.
func loadDockerSecrets(v *viper.Viper, secretsDir string) error {
	entries, err := os.ReadDir(secretsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("reading secrets directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		secretPath := filepath.Join(secretsDir, entry.Name())
		content, err := os.ReadFile(secretPath)
		if err != nil {
			return fmt.Errorf("reading secret %s: %w", entry.Name(), err)
		}

		key := strings.TrimSpace(entry.Name())
		value := strings.TrimSpace(string(content))
		v.Set(key, value)
	}

	return nil
}

// validate checks that required configuration values are present and valid.
func validate(cfg *Config) error {
	if cfg.Server.Port < 1 || cfg.Server.Port > 65535 {
		return fmt.Errorf("server.port must be between 1 and 65535, got %d", cfg.Server.Port)
	}

	if cfg.Server.ReadTimeout <= 0 {
		return fmt.Errorf("server.read_timeout must be positive")
	}

	if cfg.Server.WriteTimeout <= 0 {
		return fmt.Errorf("server.write_timeout must be positive")
	}

	if cfg.Database.Path == "" {
		return fmt.Errorf("database.path is required")
	}

	if cfg.MFA.MaxRetries < 1 {
		return fmt.Errorf("mfa.max_retries must be at least 1")
	}

	if cfg.MFA.OTPLength < 6 || cfg.MFA.OTPLength > 10 {
		return fmt.Errorf("mfa.otp_length must be between 6 and 10")
	}

	return nil
}

// Address returns the server listen address as "host:port".
func (s ServerConfig) Address() string {
	return fmt.Sprintf("%s:%d", s.Host, s.Port)
}
