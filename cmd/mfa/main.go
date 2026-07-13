package main

import (
	"context"
	"fmt"
	"net/http"
	"os/signal"
	"syscall"

	"go.uber.org/zap"

	"github.com/hidayat-SE/samlguard/internal/mfa"
	"github.com/hidayat-SE/samlguard/pkg/config"
	"github.com/hidayat-SE/samlguard/pkg/database"
	"github.com/hidayat-SE/samlguard/pkg/logger"
	"github.com/hidayat-SE/samlguard/pkg/otp"
)

func main() {
	if err := run(); err != nil {
		fmt.Printf("mfa service failed: %v\n", err)
	}
}

func run() error {
	cfg, err := config.Load("")
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	cfg.Server.Port = 18082

	log, err := logger.New(cfg.Logging.Level, cfg.Logging.Format, cfg.Logging.OutputPath)
	if err != nil {
		return fmt.Errorf("initializing logger: %w", err)
	}
	defer func() {
		_ = log.Sync()
	}()

	log.Info("starting MFA service", zap.Int("port", cfg.Server.Port))

	db, err := database.New(cfg.Database, log)
	if err != nil {
		return fmt.Errorf("initializing database: %w", err)
	}
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			log.Error("closing database", zap.Error(closeErr))
		}
	}()

	if err := database.Migrate(db.Conn, log); err != nil {
		return fmt.Errorf("running migrations: %w", err)
	}

	totpSvc := otp.NewTOTPService(cfg.MFA.Issuer, cfg.MFA.TOTPSkew)

	emailSender := mfa.NewLogSender("email", log)
	emailOTPSvc := otp.NewEmailOTPService(emailSender, cfg.MFA.OTPLength, cfg.MFA.OTPExpiry)

	smsSender := mfa.NewLogSender("sms", log)
	smsOTPSvc := otp.NewSMSOTPService(smsSender, cfg.MFA.OTPLength, cfg.MFA.OTPExpiry)

	backupSvc := otp.NewBackupCodeService(cfg.MFA.BackupCodeCount, cfg.MFA.BackupCodeLength)

	repo := mfa.NewRepository(db.Conn)
	svc := mfa.NewService(repo, totpSvc, emailOTPSvc, smsOTPSvc, backupSvc, cfg.MFA, log)
	handler := mfa.NewHandler(svc)
	router := mfa.SetupRouter(handler, log, cfg.Services.APIKey)

	srv := &http.Server{
		Addr:         cfg.Server.Address(),
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		log.Info("MFA service listening", zap.String("address", srv.Addr))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("server failed", zap.Error(err))
		}
	}()

	<-ctx.Done()
	log.Info("shutting down MFA service")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("server shutdown: %w", err)
	}

	log.Info("MFA service stopped gracefully")
	return nil
}
