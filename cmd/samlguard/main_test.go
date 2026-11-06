package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/hidayat-SE/samlguard/internal/config"
	"github.com/hidayat-SE/samlguard/pkg/logger"
	"go.uber.org/zap"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func testConfig(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		Env: "development",
		Server: config.ServerConfig{
			Port:         8080,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
		},
		SAML: config.SAMLConfig{
			EntityID:             "https://test.samlguard.example",
			SSOURL:               "http://localhost:8080/saml/sso",
			IdPSSOURL:            "https://mock-idp.example.com/sso",
			IdPEntityID:          "https://mock-idp.samlguard.local",
			ACSURL:               "http://localhost:8080/saml/acs",
			MetadataURL:          "../../testdata/ita/metadata.xml",
			CertFile:             "../../cert/saml-signing.crt",
			KeyFile:              "../../cert/saml-signing.key",
			AuthnContextClassRef: "",
			GroupMapping: map[string]string{
				"ita-admins": "Admin",
			},
		},
		MFA: config.MFAConfig{
			Issuer:        "SAMLGuard",
			AllowDummyOTP: true,
			OTPExpiry:     5 * time.Minute,
			ServerPepper:  "test-server-pepper-secret-32-bytes",
			EncryptionKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			TOTPSkew:      1,
			MaxRetries:    5,
		},
		Database: config.DatabaseConfig{
			Driver: "sqlite",
			Path:   ":memory:",
		},
		MaximumRequestSize:      256 * 1024,
		MaximumInflatedSize:     2 * 1024 * 1024,
		MaximumCompressionRatio: 20.0,
	}
}

func testLogger() *logger.Logger {
	l, _ := zap.NewDevelopment()
	return logger.New(l)
}

func TestHealthEndpoint(t *testing.T) {
	app, err := SetupApp(testConfig(t), testLogger())
	if err != nil {
		t.Fatalf("unexpected setup error: %v", err)
	}

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/health", nil)
	app.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	expectedBody := `{"success":true,"data":{"status":"ok"}}`
	if w.Body.String() != expectedBody {
		t.Errorf("Expected body %s, got %s", expectedBody, w.Body.String())
	}
}

func TestEndpoints_ReadyLiveVersion(t *testing.T) {
	app, err := SetupApp(testConfig(t), testLogger())
	if err != nil {
		t.Fatalf("unexpected setup error: %v", err)
	}

	// Ready
	wReady := httptest.NewRecorder()
	reqReady, _ := http.NewRequest(http.MethodGet, "/ready", nil)
	app.ServeHTTP(wReady, reqReady)
	if wReady.Code != http.StatusOK {
		t.Errorf("expected 200 for /ready, got %d", wReady.Code)
	}

	// Live
	wLive := httptest.NewRecorder()
	reqLive, _ := http.NewRequest(http.MethodGet, "/live", nil)
	app.ServeHTTP(wLive, reqLive)
	if wLive.Code != http.StatusOK {
		t.Errorf("expected 200 for /live, got %d", wLive.Code)
	}

	// Version
	wVersion := httptest.NewRecorder()
	reqVersion, _ := http.NewRequest(http.MethodGet, "/version", nil)
	app.ServeHTTP(wVersion, reqVersion)
	if wVersion.Code != http.StatusOK {
		t.Errorf("expected 200 for /version, got %d", wVersion.Code)
	}
}

func TestSetupApp_InvalidConfigFailsStartup(t *testing.T) {
	// Invalid config with port 0 and empty entity ID
	invalidCfg := &config.Config{
		Server: config.ServerConfig{Port: 0},
		SAML:   config.SAMLConfig{EntityID: ""},
	}

	_, err := SetupApp(invalidCfg, testLogger())
	if err == nil {
		t.Fatal("expected SetupApp to fail with invalid config, got nil")
	}
}

func TestSetupApp_SAMLRouteWired(t *testing.T) {
	app, err := SetupApp(testConfig(t), testLogger())
	if err != nil {
		t.Fatalf("unexpected setup error: %v", err)
	}

	// Send request without SAMLRequest to /saml/sso -> should return 400 Bad Request, not 404 or 500 panic
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/saml/sso", nil)
	app.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400 Bad Request for missing SAMLRequest, got %d", w.Code)
	}
}

func testProductionConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := testConfig(t)
	cfg.Env = "production"
	cfg.MFA.AllowDummyOTP = false
	cfg.SMTP = config.SMTPConfig{
		Host: "smtp.production.example.com",
		Port: 587,
	}
	cfg.SAML.IdPEntityID = "https://login.microsoftonline.com/tenant-prod/v2.0"
	cfg.SAML.IdPSSOURL = "https://login.microsoftonline.com/tenant-prod/saml2"
	cfg.SAML.ACSURL = "https://samlguard.prod.example.com/saml/acs"
	cfg.SAML.SSOURL = "https://samlguard.prod.example.com/saml/sso"
	return cfg
}

func TestSetupApp_ProductionStartup_MissingIdPEntityIDFails(t *testing.T) {
	cfg := testProductionConfig(t)
	cfg.SAML.IdPEntityID = ""

	_, err := SetupApp(cfg, testLogger())
	if err == nil || !strings.Contains(err.Error(), "saml.idp_entity_id is mandatory in production") {
		t.Fatalf("expected SetupApp to fail startup for missing IdPEntityID in production, got: %v", err)
	}
}

func TestSetupApp_ProductionStartup_MockIdPEntityIDFails(t *testing.T) {
	cfg := testProductionConfig(t)
	cfg.SAML.IdPEntityID = "https://mock-idp.samlguard.local"

	_, err := SetupApp(cfg, testLogger())
	if err == nil || !strings.Contains(err.Error(), "mock IdP entity ID") {
		t.Fatalf("expected SetupApp to fail startup for mock IdPEntityID in production, got: %v", err)
	}
}

func TestSetupApp_ProductionStartup_MockIdPSSOURLFails(t *testing.T) {
	cfg := testProductionConfig(t)
	cfg.SAML.IdPSSOURL = "https://example.com/mock-idp-login"

	_, err := SetupApp(cfg, testLogger())
	if err == nil || !strings.Contains(err.Error(), "mock IdP SSO URL cannot be used in production mode") {
		t.Fatalf("expected SetupApp to fail startup for mock IdPSSOURL in production, got: %v", err)
	}
}

func TestSetupApp_ProductionStartup_MissingACSURLFails(t *testing.T) {
	cfg := testProductionConfig(t)
	cfg.SAML.ACSURL = ""

	_, err := SetupApp(cfg, testLogger())
	if err == nil || !strings.Contains(err.Error(), "saml.acs_url is mandatory in production") {
		t.Fatalf("expected SetupApp to fail startup for missing ACSURL in production, got: %v", err)
	}
}

func TestSetupApp_ProductionStartup_RelativeACSURLFails(t *testing.T) {
	cfg := testProductionConfig(t)
	cfg.SAML.ACSURL = "/saml/acs"

	_, err := SetupApp(cfg, testLogger())
	if err == nil || !strings.Contains(err.Error(), "must be an absolute HTTPS URL in production mode") {
		t.Fatalf("expected SetupApp to fail startup for relative /saml/acs in production, got: %v", err)
	}
}

func TestSetupApp_ProductionStartup_HTTPACSURLFails(t *testing.T) {
	cfg := testProductionConfig(t)
	cfg.SAML.ACSURL = "http://samlguard.prod.example.com/saml/acs"

	_, err := SetupApp(cfg, testLogger())
	if err == nil || !strings.Contains(err.Error(), "saml.acs_url must use HTTPS in production mode") {
		t.Fatalf("expected SetupApp to fail startup for HTTP ACSURL in production, got: %v", err)
	}
}

func TestSetupApp_ProductionStartup_HTTPIdPSSOURLFails(t *testing.T) {
	cfg := testProductionConfig(t)
	cfg.SAML.IdPSSOURL = "http://login.microsoftonline.com/tenant-prod/saml2"

	_, err := SetupApp(cfg, testLogger())
	if err == nil || !strings.Contains(err.Error(), "saml.idp_sso_url must use HTTPS in production mode") {
		t.Fatalf("expected SetupApp to fail startup for HTTP IdPSSOURL in production, got: %v", err)
	}
}

func TestSetupApp_ProductionStartup_HTTPSSOURLFails(t *testing.T) {
	cfg := testProductionConfig(t)
	cfg.SAML.SSOURL = "http://samlguard.prod.example.com/saml/sso"

	_, err := SetupApp(cfg, testLogger())
	if err == nil || !strings.Contains(err.Error(), "saml.sso_url must use HTTPS in production mode") {
		t.Fatalf("expected SetupApp to fail startup for HTTP SSOURL in production, got: %v", err)
	}
}

func TestSetupApp_ProductionStartup_ValidSAMLPasses(t *testing.T) {
	cfg := testProductionConfig(t)

	app, err := SetupApp(cfg, testLogger())
	if err != nil {
		t.Fatalf("expected valid production config to start up successfully, got error: %v", err)
	}
	if app == nil {
		t.Fatal("expected non-nil gin engine")
	}
}

func TestServer_GracefulShutdown(t *testing.T) {
	app, err := SetupApp(testConfig(t), testLogger())
	if err != nil {
		t.Fatalf("setup app: %v", err)
	}

	srv := &http.Server{
		Addr:    "127.0.0.1:0", // allocate free ephemeral port
		Handler: app,
	}

	started := make(chan struct{})
	serverDone := make(chan error, 1)
	go func() {
		close(started)
		serverDone <- srv.ListenAndServe()
	}()

	<-started
	// Allow small window for server to start listening
	time.Sleep(50 * time.Millisecond)

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("expected graceful shutdown to succeed, got: %v", err)
	}

	err = <-serverDone
	if err != nil && err != http.ErrServerClosed {
		t.Errorf("unexpected server exit error: %v", err)
	}
}
