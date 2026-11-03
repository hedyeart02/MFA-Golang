package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	// Create a temporary config file
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	yamlData := []byte(`
server:
  port: 9090
database:
  driver: "postgres"
logging:
  level: "debug"
`)
	if err := os.WriteFile(configPath, yamlData, 0644); err != nil {
		t.Fatalf("failed to write test config file: %v", err)
	}

	// Test loading the config
	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Server.Port != 9090 {
		t.Errorf("expected port 9090, got %d", cfg.Server.Port)
	}
	if cfg.Database.Driver != "postgres" {
		t.Errorf("expected postgres driver, got %s", cfg.Database.Driver)
	}
	if cfg.Logging.Level != "debug" {
		t.Errorf("expected debug log level, got %s", cfg.Logging.Level)
	}
}
