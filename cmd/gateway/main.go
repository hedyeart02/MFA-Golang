package main

import (
	"context"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"go.uber.org/zap"

	"github.com/hidayat-SE/samlguard/internal/gateway"
	"github.com/hidayat-SE/samlguard/pkg/config"
	"github.com/hidayat-SE/samlguard/pkg/logger"
	"github.com/hidayat-SE/samlguard/pkg/saml"
)

func main() {
	if err := run(); err != nil {
		fmt.Printf("gateway service failed: %v\n", err)
	}
}

func run() error {
	cfg, err := config.Load("")
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	log, err := logger.New(cfg.Logging.Level, cfg.Logging.Format, cfg.Logging.OutputPath)
	if err != nil {
		return fmt.Errorf("initializing logger: %w", err)
	}
	defer func() {
		_ = log.Sync()
	}()

	log.Info("starting gateway service", zap.Int("port", cfg.Server.Port))

	authClient := gateway.NewAuthClient(cfg.Services.AuthURL, cfg.Services.APIKey, cfg.Services.Timeout, log)
	mfaClient := gateway.NewMFAClient(cfg.Services.MFAURL, cfg.Services.APIKey, cfg.Services.Timeout, log)
	sessionClient := gateway.NewSessionClient(cfg.Services.SessionURL, cfg.Services.APIKey, cfg.Services.Timeout, log)
	auditClient := gateway.NewAuditClient(cfg.Services.AuditURL, cfg.Services.APIKey, cfg.Services.Timeout, log)

	var spService *saml.SPService
	if cfg.SAML.EntityID != "" {
		spService, err = saml.NewSPService(cfg.SAML, log)
		if err != nil {
			log.Warn("SAML SP service not initialized", zap.Error(err))
		}
	}

	svc := gateway.NewService(authClient, mfaClient, sessionClient, auditClient, spService, cfg.SAML, cfg.Services, log)

	metadataGen := saml.NewMetadataGenerator(cfg.SAML.EntityID, cfg.SAML.SSOURL, cfg.SAML.SLOURL, "")

	var tmpl *template.Template
	templateDir := filepath.Join("web", "templates")
	if _, statErr := os.Stat(templateDir); statErr == nil {
		tmpl, err = template.ParseGlob(filepath.Join(templateDir, "*.html"))
		if err != nil {
			log.Warn("failed to parse templates, using inline templates", zap.Error(err))
		}
	}

	handler := gateway.NewHandler(svc, metadataGen, tmpl, log)
	router := gateway.SetupRouter(handler, log)

	srv := &http.Server{
		Addr:         cfg.Server.Address(),
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		log.Info("gateway service listening", zap.String("address", srv.Addr), zap.Bool("tls", cfg.Server.TLSEnabled))
		var err error
		if cfg.Server.TLSEnabled {
			err = srv.ListenAndServeTLS(cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile)
		} else {
			err = srv.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			log.Fatal("server failed", zap.Error(err))
		}
	}()

	<-ctx.Done()
	log.Info("shutting down gateway service")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("server shutdown: %w", err)
	}

	log.Info("gateway service stopped gracefully")
	return nil
}
