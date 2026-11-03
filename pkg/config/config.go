package config

import (
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config represents the root configuration schema
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

	// Gateway Feature Flags
	EnableStaticMetadata   bool `mapstructure:"enableStaticMetadata"`
	EnableMetadataDownload bool `mapstructure:"enableMetadataDownload"`
	EnableMetadataCache    bool `mapstructure:"enableMetadataCache"`
	EnableReplayCache      bool `mapstructure:"enableReplayCache"`
	EnableStrictXML        bool `mapstructure:"enableStrictXML"`
	CaptureRequests        bool `mapstructure:"captureRequests"`
	MaximumRequestSize     int  `mapstructure:"maximumRequestSize"`
	MaximumInflatedSize    int  `mapstructure:"maximumInflatedSize"`
	MaximumCompressionRatio float64 `mapstructure:"maximumCompressionRatio"`
}

type ServerConfig struct {
	Port         int           `mapstructure:"port"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
}

type TLSConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	CertFile string `mapstructure:"cert_file"`
	KeyFile  string `mapstructure:"key_file"`
}

type SAMLConfig struct {
	EntityID string `mapstructure:"entity_id"`
	Issuer   string `mapstructure:"issuer"`
	SSOURL   string `mapstructure:"sso_url"`
}

type DatabaseConfig struct {
	Driver           string `mapstructure:"driver"`
	ConnectionString string `mapstructure:"connection_string"`
}

type JWTConfig struct {
	Secret     string        `mapstructure:"secret"`
	Expiration time.Duration `mapstructure:"expiration"`
}

type MFAConfig struct {
	DefaultProvider string        `mapstructure:"default_provider"`
	Timeout         time.Duration `mapstructure:"timeout"`
}

type AuditConfig struct {
	Enabled bool `mapstructure:"enabled"`
	Async   bool `mapstructure:"async"`
}

type LoggingConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
}

type MetricsConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Path    string `mapstructure:"path"`
}

type PluginsConfig struct {
	Directory string `mapstructure:"directory"`
}

type SecurityConfig struct {
	CORSAllowedOrigins []string `mapstructure:"cors_allowed_origins"`
	RateLimit          int      `mapstructure:"rate_limit"`
}

// Load reads the configuration from file and environment variables
func Load(configPath string) (*Config, error) {
	v := viper.New()

	v.SetConfigFile(configPath)
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	if err := v.ReadInConfig(); err != nil {
		return nil, err
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}
