package main

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
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
	"github.com/hidayat-SE/samlguard/pkg/ratelimiter"
	"github.com/hidayat-SE/samlguard/pkg/response"
	"github.com/hidayat-SE/samlguard/public"
	"github.com/hidayat-SE/samlguard/web"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/crypto/acme/autocert"
)

// Version string populated at build time
var Version = "v1.1.1"

// SetupAppWithCleanup constructs and wires all runtime dependencies into the Gin engine
// and returns a resource cleanup function to be invoked on server shutdown.
func SetupAppWithCleanup(cfg *config.Config, appLogger *logger.Logger) (*gin.Engine, func(), error) {
	if cfg == nil {
		return nil, nil, fmt.Errorf("configuration cannot be nil")
	}
	if err := cfg.Validate(); err != nil {
		return nil, nil, fmt.Errorf("invalid runtime configuration: %w", err)
	}

	r := gin.New()

	if len(cfg.Security.TrustedProxies) > 0 {
		if proxyErr := r.SetTrustedProxies(cfg.Security.TrustedProxies); proxyErr != nil {
			return nil, nil, fmt.Errorf("invalid trusted proxies configuration: %w", proxyErr)
		}
	} else {
		_ = r.SetTrustedProxies(nil)
	}

	maxBodyBytes := int64(cfg.MaximumRequestSize) * 2
	if maxBodyBytes < 1<<20 {
		maxBodyBytes = 1 << 20
	}

	globalRateLimit := cfg.Security.RateLimit
	if globalRateLimit <= 0 {
		globalRateLimit = 100
	}
	authRateLimit := cfg.Security.AuthRateLimit
	if authRateLimit <= 0 {
		authRateLimit = 20
	}
	globalLimiter := ratelimiter.NewMemoryRateLimiter(globalRateLimit, time.Minute)
	authLimiter := ratelimiter.NewMemoryRateLimiter(authRateLimit, time.Minute)
	globalRateMW := middleware.RateLimitMiddleware(globalLimiter, "global", appLogger.System())
	authRateMW := middleware.RateLimitMiddleware(authLimiter, "auth", appLogger.System())

	// Set up router with middleware chain: Recovery -> MaxBodyBytes -> RequestID/Context -> Logger -> SecurityHeaders -> Identity
	r.Use(middleware.Recovery())
	r.Use(middleware.MaxBodyBytesWithOverrides(maxBodyBytes, map[string]int64{
		"/admin/branding/upload": 5 << 20, // Allow up to 5MB for custom theme icons, logos & backgrounds
	}))
	r.Use(middleware.ContextInject(appLogger))
	r.Use(middleware.Logger())
	r.Use(middleware.SecurityHeadersWithConfig(middleware.SecurityHeadersOptions{
		TLSEnabled:      cfg.TLS.Enabled,
		TrustProxyProto: len(cfg.Security.TrustedProxies) > 0,
		FormActionFunc:  cfg.AllowedCSPFormAction,
	}))
	r.Use(middleware.IdentityMiddleware())

	// 0. Initialize persistent SQLite storage early and overlay any Admin Console settings
	mfaStorage, err := mfa.NewSQLiteStorage(cfg.Database.Path)
	if err != nil {
		return nil, nil, fmt.Errorf("mfa storage initialization failed: %w", err)
	}

	cleanup := func() {
		if mfaStorage != nil {
			if closeErr := mfaStorage.Close(); closeErr != nil {
				appLogger.System().Warn("error closing database storage", zap.Error(closeErr))
			} else {
				appLogger.System().Info("database storage closed successfully")
			}
		}
	}

	if cfg.MFA.EncryptionKey != "" {
		if keyErr := mfaStorage.SetEncryptionKeyFromHex(cfg.MFA.EncryptionKey); keyErr != nil {
			cleanup()
			return nil, nil, fmt.Errorf("failed to configure storage encryption key: %w", keyErr)
		}
	}

	if savedSettings, loadErr := mfaStorage.GetAdminSettings(context.Background()); loadErr == nil && savedSettings != nil {
		config.ApplyAdminSettings(cfg, savedSettings)
		appLogger.System().Info("loaded persisted gateway settings from database", zap.String("db_path", cfg.Database.Path))
	} else if loadErr != nil && !errors.Is(loadErr, mfa.ErrNotFound) {
		appLogger.System().Warn("failed loading persisted gateway settings from database", zap.Error(loadErr))
	}

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

	spOrigins := cfg.DownstreamSPOrigins()
	metadataSources := make(map[string]string)
	if cfg.SAML.MetadataURL != "" {
		for _, id := range spOrigins {
			metadataSources[id] = cfg.SAML.MetadataURL
		}
	}
	metadataResolver := resolver.NewDefaultMetadataResolver(
		metadataSources,
		cfg.SAML.MetadataURL,
		&fedmetadata.SmartLoader{
			HTTPClient: newMetadataHTTPClient(cfg, appLogger.System()),
		},
		&fedmetadata.Parser{},
	)

	configuredProviders := make(map[string]string)
	for _, id := range spOrigins {
		configuredProviders[id] = "generic"
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
		cleanup()
		return nil, nil, fmt.Errorf("pipeline dependency validation failed: %w", err)
	}

	// 6. Initialize MFA Service & Response Generator

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
		cleanup()
		return nil, nil, fmt.Errorf("saml response generator initialization failed: %w", err)
	}

	// 7. Construct SAMLHandler with real pipeline, mfaService, and responseGen
	samlHandler, err := handler.NewSAMLHandler(authnPipeline, mfaService, responseGen, cfg, appLogger.System())
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("handler initialization failed: %w", err)
	}
	samlHandler.SetAuditLogger(appLogger.Audit())

	// Static assets (embedded logos, icons & public background assets)
	if staticFS, err := web.StaticFS(); err == nil {
		staticGroup := r.Group("/static", func(c *gin.Context) {
			c.Header("Cache-Control", "public, max-age=86400")
			c.Next()
		})
		staticGroup.StaticFS("/", http.FS(staticFS))

		if icoBytes, readErr := fs.ReadFile(staticFS, "img/favicon.ico"); readErr == nil {
			r.GET("/favicon.ico", func(c *gin.Context) {
				c.Header("Cache-Control", "public, max-age=86400")
				c.Data(http.StatusOK, "image/x-icon", icoBytes)
			})
		}
	}
	if assetsFS, err := public.AssetsFS(); err == nil {
		assetsGroup := r.Group("/assets", func(c *gin.Context) {
			c.Header("Cache-Control", "public, max-age=86400")
			c.Next()
		})
		assetsGroup.StaticFS("/", http.FS(assetsFS))
	}
	r.GET("/branding/assets/:id", globalRateMW, samlHandler.HandleBrandingAssetGet)

	// Register SAML and MFA routes
	samlGroup := r.Group("/saml", globalRateMW)
	{
		samlGroup.GET("/sso", samlHandler.HandleSSO)
		samlGroup.POST("/acs", authRateMW, samlHandler.HandleACS)
		samlGroup.GET("/acs", samlHandler.HandleACSGet)
		samlGroup.GET("/metadata", samlHandler.HandleMetadata)
		samlGroup.GET("/metadata/idp", samlHandler.HandleIdPMetadata)
		samlGroup.GET("/metadata/sp", samlHandler.HandleSPMetadata)
		samlGroup.POST("/re-enroll", authRateMW, samlHandler.HandleMFAReEnroll)
	}

	// Additional direct routes for compatibility with ITA and web browser forms
	r.GET("/login", globalRateMW, samlHandler.HandleSSO)
	r.POST("/login", globalRateMW, samlHandler.HandleSSO)
	r.POST("/acs", globalRateMW, authRateMW, samlHandler.HandleACS)
	r.GET("/acs", globalRateMW, samlHandler.HandleACSGet)
	r.GET("/metadata", globalRateMW, samlHandler.HandleMetadata)
	r.GET("/metadata/idp", globalRateMW, samlHandler.HandleIdPMetadata)
	r.GET("/metadata/sp", globalRateMW, samlHandler.HandleSPMetadata)
	r.POST("/mfa/verify", globalRateMW, authRateMW, samlHandler.HandleMFAVerify)
	r.POST("/mfa/resend", globalRateMW, authRateMW, samlHandler.HandleMFAResend)
	r.POST("/mfa/re-enroll", globalRateMW, authRateMW, samlHandler.HandleMFAReEnroll)
	r.POST("/mock-idp/submit", globalRateMW, authRateMW, samlHandler.HandleMockIDPSubmit)

	// Admin Console Authentication & Password Management routes
	r.GET("/admin/login", globalRateMW, samlHandler.HandleAdminLoginGet)
	r.POST("/admin/login", globalRateMW, authRateMW, samlHandler.HandleAdminLoginPost)
	r.GET("/admin/change-password", globalRateMW, samlHandler.HandleAdminChangePasswordGet)
	r.POST("/admin/change-password", globalRateMW, samlHandler.HandleAdminChangePasswordPost)
	r.POST("/admin/logout", globalRateMW, samlHandler.HandleAdminLogout)

	// Protected Admin Settings & Management routes (requires authenticated admin session + CSRF token)
	adminProtected := r.Group("/admin", globalRateMW, samlHandler.RequireAdminAuth(), samlHandler.RequireAdminCSRF())
	{
		adminProtected.GET("/settings", samlHandler.HandleAdminSettingsGet)
		adminProtected.GET("/guide", samlHandler.HandleAdminGuideGet)
		adminProtected.POST("/settings", samlHandler.HandleAdminSettingsPost)
		adminProtected.POST("/settings/test-email", samlHandler.HandleAdminTestEmailPost)
		adminProtected.POST("/settings/test-sms", samlHandler.HandleAdminTestSMSPost)
		adminProtected.POST("/ita/sync", samlHandler.HandleAdminITASyncPost)
		adminProtected.POST("/users/add", samlHandler.HandleAdminUserAddPost)
		adminProtected.POST("/users/update-phone", samlHandler.HandleAdminUserUpdatePhonePost)
		adminProtected.POST("/users/delete", samlHandler.HandleAdminUserDeletePost)
		adminProtected.POST("/users/reset-mfa", samlHandler.HandleAdminUserResetMFAPost)
		adminProtected.GET("/cert/download", samlHandler.HandleAdminCertDownload)
		adminProtected.POST("/branding/upload", samlHandler.HandleAdminBrandingUploadPost)
	}

	r.GET("/admin", func(c *gin.Context) {
		c.Redirect(http.StatusTemporaryRedirect, "/admin/settings")
	})

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

	// Metrics endpoint (honors metrics.enabled, custom path, and auth requirements in production)
	if cfg.Metrics.Enabled {
		metricsPath := strings.TrimSpace(cfg.Metrics.Path)
		if metricsPath == "" {
			metricsPath = "/metrics"
		}
		if !strings.HasPrefix(metricsPath, "/") {
			metricsPath = "/" + metricsPath
		}
		promHandler := gin.WrapH(promhttp.Handler())
		r.GET(metricsPath, func(c *gin.Context) {
			if cfg.Metrics.RequireAuth || cfg.IsProduction() {
				if samlHandler.HasValidAdminSession(c) {
					promHandler(c)
					return
				}
				expectedToken := strings.TrimSpace(cfg.Metrics.BearerToken)
				authHeader := strings.TrimSpace(c.GetHeader("Authorization"))
				const bearerPrefix = "Bearer "
				if expectedToken != "" && len(authHeader) > len(bearerPrefix) && strings.EqualFold(authHeader[:len(bearerPrefix)], bearerPrefix) {
					providedToken := strings.TrimSpace(authHeader[len(bearerPrefix):])
					if subtle.ConstantTimeCompare([]byte(providedToken), []byte(expectedToken)) == 1 {
						promHandler(c)
						return
					}
				}
				c.Header("WWW-Authenticate", `Bearer realm="samlguard-metrics"`)
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "metrics endpoint requires authentication"})
				return
			}
			promHandler(c)
		})
	}

	return r, cleanup, nil
}

// SetupApp constructs and wires all runtime dependencies into the Gin engine
func SetupApp(cfg *config.Config, appLogger *logger.Logger) (*gin.Engine, error) {
	engine, _, err := SetupAppWithCleanup(cfg, appLogger)
	return engine, err
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
	engine, cleanup, err := SetupAppWithCleanup(cfg, appLogger)
	if err != nil {
		appLogger.System().Fatal("application startup failed during dependency wiring", zap.Error(err))
	}

	// 4. Construct HTTP server with configured timeouts, Slowloris guard, and hardened TLS profile
	serverAddr := cfg.Server.Address()
	srv := &http.Server{
		Addr:              serverAddr,
		Handler:           engine,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       cfg.Server.ReadTimeout,
		WriteTimeout:      cfg.Server.WriteTimeout,
		IdleTimeout:       60 * time.Second,
	}
	if cfg.TLS.Enabled {
		srv.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			},
		}
	}

	// 5. Windows Service Control Manager or interactive console execution
	if isWindowsService() {
		appLogger.System().Info("running under Windows Service Control Manager", zap.String("service_name", "SAMLGuard"))
		if err := runAsWindowsService("SAMLGuard", srv, cfg, appLogger, cleanup); err != nil {
			appLogger.System().Fatal("Windows service terminated unexpectedly", zap.Error(err))
		}
		return
	}

	runInteractive(srv, cfg, appLogger, cleanup)
}

// prepareTLSAndChallengeServer validates static TLS keypairs or configures Let's Encrypt autocert
// (and starts its HTTP-01 challenge listener when enabled).
func prepareTLSAndChallengeServer(cfg *config.Config, srv *http.Server, appLogger *logger.Logger) (*http.Server, error) {
	if cfg == nil || !cfg.TLS.Enabled {
		return nil, nil
	}

	if cfg.TLS.AutoTLS.Enabled {
		domains := config.NormalizeAutoTLSDomains(cfg.TLS.AutoTLS.Domains)
		if len(domains) == 0 {
			return nil, errors.New("tls.auto_tls.domains is required when automatic Let's Encrypt TLS is enabled")
		}
		cacheDir := cfg.TLS.AutoTLS.EffectiveCacheDir()
		if err := os.MkdirAll(cacheDir, 0700); err != nil {
			return nil, fmt.Errorf("creating autocert cache directory %q: %w", cacheDir, err)
		}

		mgr := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(domains...),
			Cache:      autocert.DirCache(cacheDir),
			Email:      strings.TrimSpace(cfg.TLS.AutoTLS.Email),
		}
		if srv.TLSConfig == nil {
			srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		}
		srv.TLSConfig.GetCertificate = mgr.GetCertificate
		srv.TLSConfig.NextProtos = []string{"h2", "http/1.1", "acme-tls/1"}

		appLogger.System().Info("automatic Let's Encrypt TLS (autocert) configured",
			zap.Strings("domains", domains),
			zap.String("cache_dir", cacheDir),
		)

		challengeAddr := cfg.TLS.AutoTLS.EffectiveHTTPChallengeAddr()
		challengeLn, err := net.Listen("tcp", challengeAddr)
		if err != nil {
			appLogger.System().Warn("could not bind HTTP-01 ACME challenge listener; TLS-ALPN-01 on port 443 will still be used if reachable",
				zap.String("address", challengeAddr),
				zap.Error(err),
			)
			return nil, nil
		}

		challengeSrv := &http.Server{
			Addr:              challengeAddr,
			Handler:           mgr.HTTPHandler(nil),
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      15 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
		go func() {
			appLogger.System().Info("listening for ACME HTTP-01 challenges and HTTPS redirects", zap.String("address", challengeAddr))
			if err := challengeSrv.Serve(challengeLn); err != nil && err != http.ErrServerClosed {
				appLogger.System().Warn("ACME HTTP-01 challenge server stopped", zap.Error(err))
			}
		}()
		return challengeSrv, nil
	}

	if _, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile); err != nil {
		return nil, fmt.Errorf("loading TLS certificate or key: %w", err)
	}
	return nil, nil
}

func serveGatewayListener(srv *http.Server, ln net.Listener, cfg *config.Config) error {
	if cfg != nil && cfg.TLS.Enabled {
		if cfg.TLS.AutoTLS.Enabled {
			return srv.ServeTLS(ln, "", "")
		}
		return srv.ServeTLS(ln, cfg.TLS.CertFile, cfg.TLS.KeyFile)
	}
	return srv.Serve(ln)
}

// runInteractive runs the HTTP server for console execution and listens for OS interrupt signals.
func runInteractive(srv *http.Server, cfg *config.Config, appLogger *logger.Logger, cleanup func()) {
	challengeSrv, err := prepareTLSAndChallengeServer(cfg, srv, appLogger)
	if err != nil {
		if cleanup != nil {
			cleanup()
		}
		appLogger.System().Fatal("failed to initialize TLS configuration", zap.Error(err))
	}

	// Synchronously bind the TCP listener to detect port collisions or socket errors immediately
	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		if challengeSrv != nil {
			_ = challengeSrv.Close()
		}
		if cleanup != nil {
			cleanup()
		}
		appLogger.System().Fatal("failed to bind HTTP listener", zap.Error(err), zap.String("address", srv.Addr))
	}

	appLogger.System().Info("listening and serving HTTP requests", zap.String("address", ln.Addr().String()))

	serverErrors := make(chan error, 1)

	go func() {
		if err := serveGatewayListener(srv, ln, cfg); err != nil && err != http.ErrServerClosed {
			serverErrors <- err
		}
	}()

	// Graceful shutdown listening for OS signals (SIGINT/SIGTERM on Linux, Ctrl+C / console close on Windows)
	shutdownSignal := make(chan os.Signal, 1)
	signal.Notify(shutdownSignal, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serverErrors:
		if challengeSrv != nil {
			_ = challengeSrv.Close()
		}
		if cleanup != nil {
			cleanup()
		}
		appLogger.System().Fatal("server terminated unexpectedly", zap.Error(err))
	case sig := <-shutdownSignal:
		appLogger.System().Info("received shutdown signal, initiating graceful stop", zap.String("signal", sig.String()))

		shutdownTimeout := cfg.Server.ShutdownTimeout
		if shutdownTimeout <= 0 {
			shutdownTimeout = 15 * time.Second
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()

		if challengeSrv != nil {
			_ = challengeSrv.Shutdown(shutdownCtx)
		}
		if err := srv.Shutdown(shutdownCtx); err != nil {
			appLogger.System().Error("server forced to stop after shutdown timeout", zap.Error(err))
		} else {
			appLogger.System().Info("server shutdown completed cleanly")
		}

		if cleanup != nil {
			cleanup()
		}
	}
}

// newMetadataHTTPClient builds an HTTP client for SAML metadata fetching that appends
// the gateway's configured TLS/IdP certificates into the trusted root pool and, in
// non-production mode, pins self-hosted metadata loopbacks to cfg.TLS.CertFile so
// local dev self-signed certificates (including LAN IPs) verify without disabling TLS.
func newMetadataHTTPClient(cfg *config.Config, log *zap.Logger) *http.Client {
	return newMetadataHTTPClientWithDialer(cfg, log, nil)
}

func newMetadataHTTPClientWithDialer(cfg *config.Config, log *zap.Logger, baseDial func(ctx context.Context, network, addr string) (net.Conn, error)) *http.Client {
	if baseDial == nil {
		baseDial = (&net.Dialer{Timeout: 10 * time.Second}).DialContext
	}
	rootCAs, err := x509.SystemCertPool()
	if err != nil || rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	var pinnedCerts [][]byte
	appendCertFile := func(path string, pin bool) {
		path = strings.TrimSpace(path)
		if path == "" {
			return
		}
		pemBytes, readErr := os.ReadFile(path)
		if readErr != nil {
			if log != nil {
				log.Debug("skipping metadata trust load for unreadable cert file", zap.String("path", path), zap.Error(readErr))
			}
			return
		}
		rootCAs.AppendCertsFromPEM(pemBytes)
		if !pin {
			return
		}
		rest := pemBytes
		for len(rest) > 0 {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type == "CERTIFICATE" && len(block.Bytes) > 0 {
				pinnedCerts = append(pinnedCerts, block.Bytes)
			}
		}
	}

	if cfg != nil {
		appendCertFile(cfg.TLS.CertFile, true)
		if cfg.SAML.IdPCertFile != cfg.TLS.CertFile {
			appendCertFile(cfg.SAML.IdPCertFile, false)
		}
	}

	var selfMetaHost string
	if cfg != nil && cfg.SAML.MetadataURL != "" {
		if u, parseErr := url.Parse(strings.TrimSpace(cfg.SAML.MetadataURL)); parseErr == nil {
			selfMetaHost = u.Hostname()
		}
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    rootCAs,
		},
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			rawConn, dialErr := baseDial(ctx, network, addr)
			if dialErr != nil {
				return nil, dialErr
			}

			host, _, splitErr := net.SplitHostPort(addr)
			if splitErr != nil {
				host = addr
			}

			var tlsCfg *tls.Config
			if cfg != nil && !cfg.IsProduction() && selfMetaHost != "" && len(pinnedCerts) > 0 && strings.EqualFold(host, selfMetaHost) {
				tlsCfg = &tls.Config{
					MinVersion:         tls.VersionTLS12,
					InsecureSkipVerify: true, // Strictly verified against pinned local cfg.TLS.CertFile in VerifyConnection
					VerifyConnection: func(cs tls.ConnectionState) error {
						if len(cs.PeerCertificates) == 0 {
							return errors.New("server presented no TLS certificate")
						}
						peer := cs.PeerCertificates[0]
						now := time.Now().UTC()
						if now.Before(peer.NotBefore) || now.After(peer.NotAfter) {
							return errors.New("pinned local TLS certificate is expired or not yet valid")
						}
						for _, raw := range pinnedCerts {
							if subtle.ConstantTimeCompare(peer.Raw, raw) == 1 {
								return nil
							}
						}
						return errors.New("tls: metadata server certificate does not match configured tls.cert_file")
					},
				}
			} else {
				tlsCfg = &tls.Config{
					MinVersion: tls.VersionTLS12,
					RootCAs:    rootCAs,
					ServerName: host,
				}
			}

			tlsConn := tls.Client(rawConn, tlsCfg)
			if hsErr := tlsConn.HandshakeContext(ctx); hsErr != nil {
				_ = rawConn.Close()
				return nil, hsErr
			}
			return tlsConn, nil
		},
	}

	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
	}
}
