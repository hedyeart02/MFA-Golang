package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/hidayat-SE/samlguard/internal/config"
	"github.com/hidayat-SE/samlguard/internal/federation/adapter"
	"github.com/hidayat-SE/samlguard/internal/federation/adapter/entra"
	fedmetadata "github.com/hidayat-SE/samlguard/internal/federation/metadata"
	"github.com/hidayat-SE/samlguard/internal/gateway"
	"github.com/hidayat-SE/samlguard/internal/gateway/binding"
	"github.com/hidayat-SE/samlguard/internal/gateway/builder"
	"github.com/hidayat-SE/samlguard/internal/gateway/handler"
	"github.com/hidayat-SE/samlguard/internal/gateway/parser"
	"github.com/hidayat-SE/samlguard/internal/gateway/pipeline"
	"github.com/hidayat-SE/samlguard/internal/gateway/resolver"
	"github.com/hidayat-SE/samlguard/internal/gateway/validator"
	"github.com/hidayat-SE/samlguard/internal/mfa"
	"github.com/hidayat-SE/samlguard/pkg/logger"
	"github.com/hidayat-SE/samlguard/pkg/middleware"
	"github.com/hidayat-SE/samlguard/pkg/response"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Version string populated at build time
var Version = "1.0.0-dev"

// SetupApp constructs and wires all runtime dependencies into the Gin engine
func SetupApp(cfg *config.Config, appLogger *logger.Logger) (*gin.Engine, error) {
	if cfg == nil {
		return nil, fmt.Errorf("configuration cannot be nil")
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid runtime configuration: %w", err)
	}

	r := gin.Default()

	// Set up router with middleware chain: Recovery -> RequestID/Context -> Logger -> SecurityHeaders -> Identity
	r.Use(middleware.Recovery())
	r.Use(middleware.ContextInject(appLogger))
	r.Use(middleware.Logger())
	r.Use(middleware.SecurityHeaders())
	r.Use(middleware.IdentityMiddleware())

	// 1. Federation Adapters & Registry
	entraAdapter := &entra.EntraAdapter{}
	genericAdapter := &adapter.GenericAdapter{}
	adapterRegistry := adapter.NewRegistry(entraAdapter, genericAdapter)

	// 2. Gateway Resolvers
	bindingResolver := binding.NewDefaultBindingResolver()
	requestDecoder := &binding.DefaultRequestDecoder{
		MaxRequestSize:   cfg.MaximumRequestSize,
		MaxInflatedSize:  cfg.MaximumInflatedSize,
		MaxCompressRatio: cfg.MaximumCompressionRatio,
	}

	metadataSources := make(map[string]string)
	if cfg.SAML.MetadataURL != "" {
		metadataSources[cfg.SAML.EntityID] = cfg.SAML.MetadataURL
		metadataSources["https://192.168.0.119"] = cfg.SAML.MetadataURL
		for _, aud := range cfg.SAML.AllowedAudiences {
			metadataSources[aud] = cfg.SAML.MetadataURL
		}
	}
	metadataResolver := resolver.NewDefaultMetadataResolver(
		metadataSources,
		cfg.SAML.MetadataURL,
		&fedmetadata.StaticFileLoader{},
		&fedmetadata.Parser{},
	)

	configuredProviders := make(map[string]string)
	if cfg.SAML.EntityID != "" {
		configuredProviders[cfg.SAML.EntityID] = "generic"
	}
	configuredProviders["https://192.168.0.119"] = "generic"
	for _, aud := range cfg.SAML.AllowedAudiences {
		configuredProviders[aud] = "generic"
	}
	providerResolver := resolver.NewDefaultProviderResolver(adapterRegistry, configuredProviders)

	// 3. Gateway Parsers, Normalizers, Builders & Validators
	samlParser := &parser.SecureCrewjamParser{}
	samlNormalizer := &builder.DefaultNormalizer{}
	syntaxValidator := &validator.DefaultSyntaxValidator{
		MaxXMLSize: cfg.MaximumInflatedSize,
	}
	// Allow unsigned inbound AuthnRequests from SP per SAML 2.0 HTTP-Redirect standard
	signatureValidator := &validator.DefaultSignatureValidator{AllowUnsigned: true}
	schemaValidator := &validator.DefaultSchemaValidator{}
	replayValidator := validator.NewDefaultReplayValidator(5 * time.Minute)
	clockValidator := &validator.DefaultClockValidator{AllowedSkew: 3 * time.Minute}
	policyValidator := &validator.DefaultPolicyValidator{ExpectedDestination: cfg.SAML.SSOURL}
	contextBuilder := builder.NewDefaultContextBuilder()

	// 4. Construct production DefaultAuthnPipeline
	authnPipeline := &pipeline.DefaultAuthnPipeline{
		BindingResolver:    bindingResolver,
		Decoder:            requestDecoder,
		Parser:             samlParser,
		Normalizer:         samlNormalizer,
		SyntaxValidator:    syntaxValidator,
		SignatureValidator: signatureValidator,
		SchemaValidator:    schemaValidator,
		ReplayValidator:    replayValidator,
		ClockValidator:     clockValidator,
		PolicyValidator:    policyValidator,
		MetadataResolver:   metadataResolver,
		ProviderResolver:   providerResolver,
		ContextBuilder:     contextBuilder,
	}

	// 5. Validate dependencies during startup
	if err := authnPipeline.Validate(); err != nil {
		return nil, fmt.Errorf("pipeline dependency validation failed: %w", err)
	}

	// 6. Initialize MFA dependencies & Response Generator
	mfaStorage, err := mfa.NewSQLiteStorage(cfg.Database.Path)
	if err != nil {
		return nil, fmt.Errorf("mfa storage initialization failed: %w", err)
	}

	smtpSender := mfa.NewSMTPSender(
		cfg.SMTP.Host,
		cfg.SMTP.Port,
		cfg.SMTP.Username,
		cfg.SMTP.Password,
		cfg.SMTP.From,
		cfg.SMTP.FromName,
		cfg.SMTP.Encryption,
		appLogger.System(),
	)

	mfaService := mfa.NewService(mfaStorage, smtpSender, cfg, appLogger.System())

	responseGen, err := gateway.NewResponseGenerator(cfg)
	if err != nil {
		return nil, fmt.Errorf("saml response generator initialization failed: %w", err)
	}

	// 7. Construct SAMLHandler with real pipeline, mfaService, and responseGen
	samlHandler, err := handler.NewSAMLHandler(authnPipeline, mfaService, responseGen, cfg, appLogger.System())
	if err != nil {
		return nil, fmt.Errorf("handler initialization failed: %w", err)
	}

	// Register SAML and MFA routes
	samlGroup := r.Group("/saml")
	{
		samlGroup.GET("/sso", samlHandler.HandleSSO)
		samlGroup.POST("/acs", samlHandler.HandleACS)
		samlGroup.GET("/metadata", samlHandler.HandleMetadata)
		samlGroup.POST("/re-enroll", samlHandler.HandleMFAReEnroll)
	}

	// Additional direct routes for compatibility with ITA and web browser forms
	r.GET("/login", samlHandler.HandleSSO)
	r.POST("/login", samlHandler.HandleSSO)
	r.POST("/acs", samlHandler.HandleACS)
	r.POST("/mfa/verify", samlHandler.HandleMFAVerify)
	r.POST("/mfa/resend", samlHandler.HandleMFAResend)
	r.POST("/mfa/re-enroll", samlHandler.HandleMFAReEnroll)

	// Health endpoint
	r.GET("/health", func(c *gin.Context) {
		response.Success(c, gin.H{"status": "ok"})
	})

	// Ready endpoint
	r.GET("/ready", func(c *gin.Context) {
		response.Success(c, gin.H{"status": "ready"})
	})

	// Live endpoint
	r.GET("/live", func(c *gin.Context) {
		response.Success(c, gin.H{"status": "live"})
	})

	// Version endpoint
	r.GET("/version", func(c *gin.Context) {
		response.Success(c, gin.H{"version": Version})
	})

	// Metrics endpoint
	r.GET("/metrics", gin.WrapH(promhttp.Handler()))

	return r, nil
}

func main() {
	// Parse CLI flags (-config, --config, -c, -version)
	var configFilePath string
	flag.StringVar(&configFilePath, "config", "", "Path to YAML configuration file")
	flag.StringVar(&configFilePath, "c", "", "Path to YAML configuration file (shorthand)")
	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("SAMLGuard version %s\n", Version)
		return
	}

	// 1. Initialize structured logger
	zapConfig := zap.NewProductionConfig()
	zapLogger, err := zapConfig.Build()
	if err != nil {
		panic(fmt.Sprintf("failed to initialize logger: %v", err))
	}
	defer zapLogger.Sync()
	appLogger := logger.New(zapLogger)

	// 2. Load and validate runtime configuration (startup must fail clearly on error)
	var cfg *config.Config
	if configFilePath != "" {
		cfg, err = config.Load(configFilePath)
	} else {
		cfg, err = config.Load()
	}
	if err != nil {
		appLogger.System().Fatal("fatal configuration error during application startup", zap.Error(err))
	}

	// Adjust logging level according to configuration
	if cfg.Logging.Level == "debug" {
		zapConfig.Level.SetLevel(zapcore.DebugLevel)
	}

	// Safe startup logging: non-sensitive metadata only (secrets are never logged)
	appLogger.System().Info("starting SAMLGuard gateway runtime",
		zap.String("version", Version),
		zap.Int("port", cfg.Server.Port),
		zap.String("saml_entity_id", cfg.SAML.EntityID),
		zap.Bool("tls_enabled", cfg.TLS.Enabled),
		zap.Int("max_request_size", cfg.MaximumRequestSize),
		zap.Int("max_inflated_size", cfg.MaximumInflatedSize),
	)

	// 3. Assemble and wire application runtime
	engine, err := SetupApp(cfg, appLogger)
	if err != nil {
		appLogger.System().Fatal("application startup failed during dependency wiring", zap.Error(err))
	}

	// 4. Construct HTTP server with configured timeouts and host/port
	serverAddr := cfg.Server.Address()
	srv := &http.Server{
		Addr:         serverAddr,
		Handler:      engine,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	// 5. Windows Service Control Manager or interactive console execution
	if isWindowsService() {
		appLogger.System().Info("running under Windows Service Control Manager", zap.String("service_name", "SAMLGuard"))
		if err := runAsWindowsService("SAMLGuard", srv, cfg, appLogger); err != nil {
			appLogger.System().Fatal("Windows service terminated unexpectedly", zap.Error(err))
		}
		return
	}

	runInteractive(srv, cfg, appLogger)
}

// runInteractive runs the HTTP server for console execution and listens for OS interrupt signals.
func runInteractive(srv *http.Server, cfg *config.Config, appLogger *logger.Logger) {
	appLogger.System().Info("listening and serving HTTP requests", zap.String("address", srv.Addr))

	serverErrors := make(chan error, 1)

	go func() {
		if cfg.TLS.Enabled {
			if err := srv.ListenAndServeTLS(cfg.TLS.CertFile, cfg.TLS.KeyFile); err != nil && err != http.ErrServerClosed {
				serverErrors <- err
			}
		} else {
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				serverErrors <- err
			}
		}
	}()

	// Graceful shutdown listening for OS signals (SIGINT/SIGTERM on Linux, Ctrl+C / console close on Windows)
	shutdownSignal := make(chan os.Signal, 1)
	signal.Notify(shutdownSignal, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serverErrors:
		appLogger.System().Fatal("server terminated unexpectedly", zap.Error(err))
	case sig := <-shutdownSignal:
		appLogger.System().Info("received shutdown signal, initiating graceful stop", zap.String("signal", sig.String()))

		shutdownTimeout := cfg.Server.ShutdownTimeout
		if shutdownTimeout <= 0 {
			shutdownTimeout = 15 * time.Second
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()

		if err := srv.Shutdown(shutdownCtx); err != nil {
			appLogger.System().Error("server forced to stop after shutdown timeout", zap.Error(err))
		} else {
			appLogger.System().Info("server shutdown completed cleanly")
		}
	}
}
