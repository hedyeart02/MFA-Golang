//go:build windows

package main

import (
	"context"
	"crypto/tls"
	"net"
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
	cleanup   func()
}

// Execute handles Windows SCM state transitions and control commands.
func (s *samlguardService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	// 1. Validate TLS certificate and key up-front if TLS is enabled
	if s.cfg != nil && s.cfg.TLS.Enabled {
		if _, err := tls.LoadX509KeyPair(s.cfg.TLS.CertFile, s.cfg.TLS.KeyFile); err != nil {
			s.appLogger.System().Error("failed to load TLS certificate or key in Windows service", zap.Error(err))
			if s.cleanup != nil {
				s.cleanup()
			}
			changes <- svc.Status{State: svc.Stopped}
			return false, 1
		}
	}

	// 2. Synchronously create and bind the TCP listener before reporting Running to SCM
	ln, err := net.Listen("tcp", s.srv.Addr)
	if err != nil {
		s.appLogger.System().Error("failed to bind HTTP listener in Windows service",
			zap.Error(err),
			zap.String("address", s.srv.Addr),
		)
		if s.cleanup != nil {
			s.cleanup()
		}
		changes <- svc.Status{State: svc.Stopped}
		return false, 1
	}

	serverErrors := make(chan error, 1)

	go func() {
		s.appLogger.System().Info("Windows service HTTP listener starting",
			zap.String("address", ln.Addr().String()),
			zap.Bool("tls_enabled", s.cfg != nil && s.cfg.TLS.Enabled),
		)
		if s.cfg != nil && s.cfg.TLS.Enabled {
			if err := s.srv.ServeTLS(ln, s.cfg.TLS.CertFile, s.cfg.TLS.KeyFile); err != nil && err != http.ErrServerClosed {
				serverErrors <- err
			}
		} else {
			if err := s.srv.Serve(ln); err != nil && err != http.ErrServerClosed {
				serverErrors <- err
			}
		}
	}()

	// 3. Listener is successfully bound and serving: report RUNNING to SCM
	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
	s.appLogger.System().Info("Windows service state reported as RUNNING to SCM")

	for {
		select {
		case err := <-serverErrors:
			s.appLogger.System().Error("HTTP server failed unexpectedly in Windows service", zap.Error(err))
			if s.cleanup != nil {
				s.cleanup()
			}
			changes <- svc.Status{State: svc.Stopped}
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

				shutdownTimeout := 15 * time.Second
				if s.cfg != nil && s.cfg.Server.ShutdownTimeout > 0 {
					shutdownTimeout = s.cfg.Server.ShutdownTimeout
				}
				shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
				defer cancel()

				if err := s.srv.Shutdown(shutdownCtx); err != nil {
					s.appLogger.System().Error("Windows service server forced to stop after timeout", zap.Error(err))
				} else {
					s.appLogger.System().Info("Windows service server shutdown completed cleanly")
				}

				if s.cleanup != nil {
					s.cleanup()
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
func runAsWindowsService(name string, srv *http.Server, cfg *config.Config, appLogger *logger.Logger, cleanup func()) error {
	service := &samlguardService{
		srv:       srv,
		cfg:       cfg,
		appLogger: appLogger,
		cleanup:   cleanup,
	}
	return svc.Run(name, service)
}

