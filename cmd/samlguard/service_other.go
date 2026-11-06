//go:build !windows

package main

import (
	"fmt"
	"net/http"

	"github.com/hidayat-SE/samlguard/internal/config"
	"github.com/hidayat-SE/samlguard/pkg/logger"
)

// isWindowsService returns false on non-Windows platforms.
func isWindowsService() bool {
	return false
}

// runAsWindowsService is a stub on non-Windows platforms.
func runAsWindowsService(name string, srv *http.Server, cfg *config.Config, appLogger *logger.Logger) error {
	return fmt.Errorf("windows service execution is not supported on this platform")
}

