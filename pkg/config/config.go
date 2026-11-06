package config

import (
	"github.com/hidayat-SE/samlguard/internal/config"
)

// Re-export types from internal/config for backwards compatibility
type Config = config.Config
type ServerConfig = config.ServerConfig
type TLSConfig = config.TLSConfig
type SAMLConfig = config.SAMLConfig
type DatabaseConfig = config.DatabaseConfig
type JWTConfig = config.JWTConfig
type MFAConfig = config.MFAConfig
type AuditConfig = config.AuditConfig
type LoggingConfig = config.LoggingConfig
type MetricsConfig = config.MetricsConfig
type PluginsConfig = config.PluginsConfig
type SecurityConfig = config.SecurityConfig

// Load delegates to internal/config.Load
func Load(paths ...string) (*Config, error) {
	return config.Load(paths...)
}

// SetDefaults delegates to internal/config.SetDefaults
var SetDefaults = config.SetDefaults
