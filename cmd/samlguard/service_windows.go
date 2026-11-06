//go:build windows

package main

import (
	"context"
	"net/http"
	"time"

	"github.com/hidayat-SE/samlguard/internal/config"
	"github.com/hidayat-SE/samlguard/pkg/logger"
	"go.uber.org/zap"
	"golang.org/x/sys/windows/svc"
)

// isWindowsService returns true if the current process was invoked by the Windows Service Control Manager.
func isWindowsService() bool {
	isSvc, err := svc.IsWindowsService()
	if err != nil {
		return false
	}
	return isSvc
}

// samlguardService implements svc.Handler for the Windows Service Control Manager.
type samlguardService struct {
	srv       *http.Server
	cfg       *config.Config
	appLogger *logger.Logger
}

// Execute handles Windows SCM state transitions and control commands.
func (s *samlguardService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	serverErrors := make(chan error, 1)

	go func() {
		s.appLogger.System().Info("Windows service HTTP listener starting",
			zap.String("address", s.srv.Addr),
			zap.Bool("tls_enabled", s.cfg.TLS.Enabled),
		)
		if s.cfg.TLS.Enabled {
			if err := s.srv.ListenAndServeTLS(s.cfg.TLS.CertFile, s.cfg.TLS.KeyFile); err != nil && err != http.ErrServerClosed {
				serverErrors <- err
			}
		} else {
			if err := s.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				serverErrors <- err
			}
		}
	}()

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
	s.appLogger.System().Info("Windows service state reported as RUNNING to SCM")

	for {
		select {
		case err := <-serverErrors:
			s.appLogger.System().Error("HTTP server failed unexpectedly in Windows service", zap.Error(err))
			changes <- svc.Status{State: svc.StopPending}
			return false, 1

		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				s.appLogger.System().Info("Windows service received stop/shutdown request from SCM",
					zap.Uint32("command", uint32(c.Cmd)),
				)
				changes <- svc.Status{State: svc.StopPending}

				shutdownTimeout := s.cfg.Server.ShutdownTimeout
				if shutdownTimeout <= 0 {
					shutdownTimeout = 15 * time.Second
				}
				shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
				defer cancel()

				if err := s.srv.Shutdown(shutdownCtx); err != nil {
					s.appLogger.System().Error("Windows service server forced to stop after timeout", zap.Error(err))
				} else {
					s.appLogger.System().Info("Windows service server shutdown completed cleanly")
				}

				changes <- svc.Status{State: svc.Stopped}
				return false, 0

			default:
				s.appLogger.System().Warn("Windows service received unhandled control request",
					zap.Uint32("command", uint32(c.Cmd)),
				)
			}
		}
	}
}

// runAsWindowsService registers and runs the application under the Windows Service Control Manager.
func runAsWindowsService(name string, srv *http.Server, cfg *config.Config, appLogger *logger.Logger) error {
	service := &samlguardService{
		srv:       srv,
		cfg:       cfg,
		appLogger: appLogger,
	}
	return svc.Run(name, service)
}

