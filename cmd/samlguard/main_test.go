package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/hidayat-SE/samlguard/internal/config"
	fedmetadata "github.com/hidayat-SE/samlguard/internal/federation/metadata"
	"github.com/hidayat-SE/samlguard/internal/mfa"
	"github.com/hidayat-SE/samlguard/pkg/logger"
	"github.com/hidayat-SE/samlguard/web"
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
			AllowedAudiences:     []string{"https://ita.example.com"},
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

func TestSetupAppWithCleanup_ResourceCleanup(t *testing.T) {
	app, cleanup, err := SetupAppWithCleanup(testConfig(t), testLogger())
	if err != nil {
		t.Fatalf("unexpected setup error: %v", err)
	}
	if app == nil {
		t.Fatal("expected non-nil engine")
	}
	if cleanup == nil {
		t.Fatal("expected non-nil cleanup function")
	}

	// Verify cleanup executes without panic or error
	cleanup()
}

func TestSetupApp_MetadataRoutes(t *testing.T) {
	app, cleanup, err := SetupAppWithCleanup(testConfig(t), testLogger())
	if err != nil {
		t.Fatalf("unexpected setup error: %v", err)
	}
	defer cleanup()

	routes := []struct {
		path            string
		expectedCode    int
		expectedContent string
	}{
		{"/saml/metadata", http.StatusOK, "IDPSSODescriptor"},
		{"/saml/metadata", http.StatusOK, "SPSSODescriptor"},
		{"/saml/metadata/idp", http.StatusOK, "IDPSSODescriptor"},
		{"/saml/metadata/sp", http.StatusOK, "SPSSODescriptor"},
		{"/metadata", http.StatusOK, "IDPSSODescriptor"},
		{"/metadata/idp", http.StatusOK, "IDPSSODescriptor"},
		{"/metadata/sp", http.StatusOK, "SPSSODescriptor"},
	}

	for _, tc := range routes {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, tc.path, nil)
		app.ServeHTTP(w, req)

		if w.Code != tc.expectedCode {
			t.Errorf("expected %s to return %d, got %d", tc.path, tc.expectedCode, w.Code)
		}
		if !strings.Contains(w.Body.String(), tc.expectedContent) {
			t.Errorf("expected %s to contain %s", tc.path, tc.expectedContent)
		}
	}
}

func TestSetupApp_StaticLogosAndLoginAssets(t *testing.T) {
	app, cleanup, err := SetupAppWithCleanup(testConfig(t), testLogger())
	if err != nil {
		t.Fatalf("unexpected setup error: %v", err)
	}
	defer cleanup()

	assets := []string{
		"/static/img/ecostruxure-dark.png",
		"/static/img/ecostruxure-light.png",
		"/static/img/schneider-electric.png",
		"/assets/backgrounds/bg-login-dark.png",
		"/assets/backgrounds/bg-login-light.png",
		"/assets/backgrounds/bg-console-dark.png",
		"/assets/backgrounds/bg-console-light.png",
	}

	for _, asset := range assets {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, asset, nil)
		app.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected %s to return 200, got %d", asset, w.Code)
		}
		if !strings.HasPrefix(w.Body.String(), "\x89PNG") {
			t.Errorf("expected %s to return PNG image payload", asset)
		}
		if cc := w.Header().Get("Cache-Control"); !strings.Contains(cc, "max-age=") {
			t.Errorf("expected %s to set Cache-Control max-age header, got %q", asset, cc)
		}
	}

	wTheme := httptest.NewRecorder()
	reqTheme, _ := http.NewRequest(http.MethodGet, "/static/js/theme.js", nil)
	app.ServeHTTP(wTheme, reqTheme)
	if wTheme.Code != http.StatusOK {
		t.Fatalf("expected /static/js/theme.js to return 200, got %d", wTheme.Code)
	}
	if !strings.Contains(wTheme.Body.String(), "samlguard.theme") || !strings.Contains(wTheme.Body.String(), "system") {
		t.Errorf("expected /static/js/theme.js to use samlguard.theme key and system default")
	}

	wFavSVG := httptest.NewRecorder()
	reqFavSVG, _ := http.NewRequest(http.MethodGet, "/static/img/favicon.svg", nil)
	app.ServeHTTP(wFavSVG, reqFavSVG)
	if wFavSVG.Code != http.StatusOK {
		t.Fatalf("expected /static/img/favicon.svg to return 200, got %d", wFavSVG.Code)
	}
	if !strings.Contains(wFavSVG.Body.String(), "<svg") {
		t.Errorf("expected /static/img/favicon.svg to return valid SVG markup")
	}

	wFavICO := httptest.NewRecorder()
	reqFavICO, _ := http.NewRequest(http.MethodGet, "/favicon.ico", nil)
	app.ServeHTTP(wFavICO, reqFavICO)
	if wFavICO.Code != http.StatusOK {
		t.Fatalf("expected /favicon.ico to return 200, got %d", wFavICO.Code)
	}
	if wFavICO.Body.Len() < 22 || !strings.HasPrefix(wFavICO.Body.String(), "\x00\x00\x01\x00") {
		t.Errorf("expected /favicon.ico to return valid ICO binary payload")
	}

	wLogin := httptest.NewRecorder()
	reqLogin, _ := http.NewRequest(http.MethodGet, "/admin/login", nil)
	app.ServeHTTP(wLogin, reqLogin)
	if wLogin.Code != http.StatusOK {
		t.Fatalf("expected /admin/login to return 200, got %d", wLogin.Code)
	}
	body := wLogin.Body.String()
	for _, ref := range []string{
		"/static/img/ecostruxure-dark.png",
		"/static/img/ecostruxure-light.png",
		"/static/img/schneider-electric.png",
		"/static/js/theme.js",
		"/assets/backgrounds/bg-login-dark.png",
		"/assets/backgrounds/bg-login-light.png",
	} {
		if !strings.Contains(body, ref) {
			t.Errorf("expected /admin/login HTML to reference %s", ref)
		}
	}

	rawCorpReqXML := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_corp_ui_test_1" Version="2.0" IssueInstant="2026-11-04T12:00:00Z" Destination="http://localhost:8080/saml/sso" AssertionConsumerServiceURL="https://ita.example.com/api/current/authentication/saml2-callback"><saml:Issuer>https://ita.example.com</saml:Issuer></samlp:AuthnRequest>`
	encodedCorpReq, err := encodeSAMLRequest(rawCorpReqXML)
	if err != nil {
		t.Fatalf("failed to encode SAMLRequest for /login: %v", err)
	}
	wCorpLogin := httptest.NewRecorder()
	reqCorpLogin, _ := http.NewRequest(http.MethodGet, "/saml/sso?SAMLRequest="+url.QueryEscape(encodedCorpReq)+"&RelayState=corp-ui-test", nil)
	app.ServeHTTP(wCorpLogin, reqCorpLogin)
	if wCorpLogin.Code != http.StatusOK {
		t.Fatalf("expected /saml/sso to return 200, got %d (body: %s)", wCorpLogin.Code, wCorpLogin.Body.String())
	}
	corpBody := wCorpLogin.Body.String()
	for _, ref := range []string{
		"Corporate Sign In",
		"Secure access to Schneider Electric IT Advisor",
		"Continue to Verification",
		"/static/img/ecostruxure-dark.png",
		"/static/img/ecostruxure-light.png",
		"/static/img/schneider-electric.png",
		"/static/js/theme.js",
		"/assets/backgrounds/bg-login-dark.png",
		"/assets/backgrounds/bg-login-light.png",
		"#00B050",
		"app-footer",
		"Hidayat Ahmad",
	} {
		if !strings.Contains(corpBody, ref) {
			t.Errorf("expected /login HTML to reference %q", ref)
		}
	}

	for _, ref := range []string{
		"/static/js/theme.js",
		"/assets/backgrounds/bg-console-dark.png",
		"/assets/backgrounds/bg-console-light.png",
	} {
		if !strings.Contains(web.DefaultAdminSettingsHTML, ref) {
			t.Errorf("expected admin_settings.html to reference %s", ref)
		}
	}

	embeddedTemplates := map[string]string{
		"mfa_challenge.html":         web.DefaultMFAChallengeHTML,
		"error.html":                 web.DefaultErrorHTML,
		"admin_settings.html":        web.DefaultAdminSettingsHTML,
		"admin_login.html":           web.DefaultAdminLoginHTML,
		"admin_change_password.html": web.DefaultAdminChangePasswordHTML,
		"corporate_login.html":       web.DefaultCorporateLoginHTML,
	}
	for name, html := range embeddedTemplates {
		if !strings.Contains(html, `class="app-footer"`) {
			t.Errorf("expected %s to include class=\"app-footer\"", name)
		}
		if !strings.Contains(html, "Hidayat Ahmad") {
			t.Errorf("expected %s footer to include Hidayat Ahmad", name)
		}
		if !strings.Contains(html, "/static/img/favicon.svg") {
			t.Errorf("expected %s to reference /static/img/favicon.svg", name)
		}
		if !strings.Contains(html, "/favicon.ico") {
			t.Errorf("expected %s to reference /favicon.ico", name)
		}
	}
}

func TestSetupApp_LoadsPersistedAdminSettingsFromDB(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "samlguard.db")
	storage, err := mfa.NewSQLiteStorage(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteStorage failed: %v", err)
	}
	err = storage.SaveAdminSettings(context.Background(), &config.AdminSettingsPayload{
		EntityID:           "https://persisted.samlguard.local:8443",
		ACSURL:             "https://persisted.ita.local/callback",
		SSOURL:             "https://persisted.samlguard.local:8443/saml/sso",
		IdPEntityID:        "https://persisted.idp.local/realm",
		IdPSSOURL:          "https://persisted.idp.local/sso",
		MFADefaultProvider: "email",
	})
	_ = storage.Close()
	if err != nil {
		t.Fatalf("SaveAdminSettings failed: %v", err)
	}

	cfg := testConfig(t)
	cfg.Database.Path = dbPath

	_, cleanup, err := SetupAppWithCleanup(cfg, testLogger())
	if err != nil {
		t.Fatalf("SetupAppWithCleanup failed: %v", err)
	}
	defer cleanup()

	if cfg.SAML.EntityID != "https://persisted.samlguard.local:8443" {
		t.Errorf("expected persisted EntityID loaded at startup, got %q", cfg.SAML.EntityID)
	}
	if cfg.SAML.IdPSSOURL != "https://persisted.idp.local/sso" {
		t.Errorf("expected persisted IdPSSOURL loaded at startup, got %q", cfg.SAML.IdPSSOURL)
	}
	if cfg.MFA.DefaultProvider != "email" {
		t.Errorf("expected persisted MFA provider 'email', got %q", cfg.MFA.DefaultProvider)
	}
}

func TestSetupApp_Phase2SecurityHardening(t *testing.T) {
	cfg := testConfig(t)
	cfg.Security.AuthRateLimit = 2
	cfg.Security.RateLimit = 50
	cfg.SAML.ACSURL = "https://ita.example.com/api/current/authentication/saml2-callback"

	app, cleanup, err := SetupAppWithCleanup(cfg, testLogger())
	if err != nil {
		t.Fatalf("SetupAppWithCleanup failed: %v", err)
	}
	defer cleanup()

	// 1. Verify strict CSP (no wildcard form-action *), Cache-Control: no-store, and X-Frame-Options
	wGet := httptest.NewRecorder()
	reqGet := httptest.NewRequest(http.MethodGet, "/admin/login", nil)
	app.ServeHTTP(wGet, reqGet)
	if wGet.Code != http.StatusOK {
		t.Fatalf("expected 200 on /admin/login, got %d", wGet.Code)
	}
	csp := wGet.Header().Get("Content-Security-Policy")
	if strings.Contains(csp, "form-action *") {
		t.Fatalf("expected CSP without wildcard form-action *, got: %s", csp)
	}
	if !strings.Contains(csp, "https://ita.example.com") {
		t.Fatalf("expected downstream SP origin in CSP form-action, got: %s", csp)
	}
	if !strings.Contains(wGet.Header().Get("Cache-Control"), "no-store") {
		t.Fatalf("expected no-store Cache-Control header, got: %s", wGet.Header().Get("Cache-Control"))
	}

	// 2. Spoofing X-Forwarded-For with default empty TrustedProxies must NOT bypass IP rate limiting
	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/admin/login", strings.NewReader("username=admin&password=wrong"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Forwarded-For", "198.51.100."+string(rune('1'+i)))
		req.RemoteAddr = "203.0.113.5:12345"
		app.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected attempt %d within limit to reach login handler (200), got %d", i+1, w.Code)
		}
	}

	wLimited := httptest.NewRecorder()
	reqLimited := httptest.NewRequest(http.MethodPost, "/admin/login", strings.NewReader("username=admin&password=wrong"))
	reqLimited.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqLimited.Header.Set("X-Forwarded-For", "198.51.100.99") // spoofed IP should be ignored!
	reqLimited.RemoteAddr = "203.0.113.5:12346"
	app.ServeHTTP(wLimited, reqLimited)
	if wLimited.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 Too Many Requests when X-Forwarded-For is untrusted and auth limit exceeded, got %d", wLimited.Code)
	}
}

func TestSetupApp_Phase3_MetricsAuth(t *testing.T) {
	cfg := testConfig(t)
	cfg.Metrics.Enabled = true
	cfg.Metrics.Path = "/metrics"
	cfg.Metrics.RequireAuth = true
	cfg.Metrics.BearerToken = "super-secret-scrape-token"

	app, cleanup, err := SetupAppWithCleanup(cfg, testLogger())
	if err != nil {
		t.Fatalf("SetupAppWithCleanup failed: %v", err)
	}
	defer cleanup()

	// Unauthenticated request to /metrics must be denied
	wUnauth := httptest.NewRecorder()
	reqUnauth := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	app.ServeHTTP(wUnauth, reqUnauth)
	if wUnauth.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized on /metrics without credentials, got %d", wUnauth.Code)
	}

	// Wrong Bearer token must be denied
	wWrong := httptest.NewRecorder()
	reqWrong := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	reqWrong.Header.Set("Authorization", "Bearer wrong-token")
	app.ServeHTTP(wWrong, reqWrong)
	if wWrong.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized on /metrics with invalid bearer token, got %d", wWrong.Code)
	}

	// Valid Bearer token succeeds and serves Prometheus metrics
	wOK := httptest.NewRecorder()
	reqOK := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	reqOK.Header.Set("Authorization", "Bearer super-secret-scrape-token")
	app.ServeHTTP(wOK, reqOK)
	if wOK.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on /metrics with valid bearer token, got %d", wOK.Code)
	}
	if !strings.Contains(wOK.Body.String(), "audit_events_total") && !strings.Contains(wOK.Body.String(), "# HELP") {
		t.Fatalf("expected Prometheus metrics payload, got: %s", wOK.Body.String())
	}
}

type pipeListener struct {
	conns  chan net.Conn
	closed chan struct{}
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error {
	select {
	case <-l.closed:
	default:
		close(l.closed)
	}
	return nil
}

func (l *pipeListener) Addr() net.Addr { return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 18080} }

func startInMemoryTLSServer(t *testing.T, body string, dnsSAN string) (func(context.Context, string, string) (net.Conn, error), []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: dnsSAN},
		DNSNames:     []string{dnsSAN},
		NotBefore:    now.Add(-1 * time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	ln := &pipeListener{conns: make(chan net.Conn, 4), closed: make(chan struct{})}
	tlsLn := tls.NewListener(ln, &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{der},
			PrivateKey:  key,
		}},
	})
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(body))
		}),
	}
	go func() { _ = srv.Serve(tlsLn) }()
	t.Cleanup(func() {
		_ = srv.Close()
		_ = ln.Close()
	})

	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		cConn, sConn := net.Pipe()
		select {
		case ln.conns <- sConn:
			return cConn, nil
		case <-ln.closed:
			_ = cConn.Close()
			_ = sConn.Close()
			return nil, net.ErrClosed
		case <-ctx.Done():
			_ = cConn.Close()
			_ = sConn.Close()
			return nil, ctx.Err()
		}
	}
	return dial, der
}

func TestMetadataHTTPClient_LocalSelfSignedAndPinEnforcement(t *testing.T) {
	metaXML := `<EntityDescriptor entityID="https://192.168.0.178:18080"/>`
	// Self-hosted server serves cert with SAN "samlguard.example.com" while accessed via LAN IP 192.168.0.178
	selfDial, der := startInMemoryTLSServer(t, metaXML, "samlguard.example.com")

	certPath := filepath.Join(t.TempDir(), "server.crt")
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("write temp cert: %v", err)
	}

	localMetaURL := "https://192.168.0.178:18080/metadata"
	cfg := &config.Config{
		Env: "development",
		SAML: config.SAMLConfig{
			MetadataURL: localMetaURL,
		},
		TLS: config.TLSConfig{
			Enabled:  true,
			CertFile: certPath,
		},
	}

	loader := &fedmetadata.SmartLoader{
		HTTPClient: newMetadataHTTPClientWithDialer(cfg, zap.NewNop(), selfDial),
	}
	got, err := loader.Load(context.Background(), localMetaURL)
	if err != nil {
		t.Fatalf("expected local dev metadata fetch with pinned tls.cert_file to succeed, got: %v", err)
	}
	if string(got) != metaXML {
		t.Fatalf("unexpected metadata payload: %s", string(got))
	}

	// Rogue server with a different cert on the same host must be rejected by pin check
	rogueDial, _ := startInMemoryTLSServer(t, metaXML, "192.168.0.178")
	rogueLoader := &fedmetadata.SmartLoader{
		HTTPClient: newMetadataHTTPClientWithDialer(cfg, zap.NewNop(), rogueDial),
	}
	if _, err := rogueLoader.Load(context.Background(), localMetaURL); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("expected rogue certificate not matching tls.cert_file to be rejected, got: %v", err)
	}

	// External host must use standard CA+SAN verification and reject unknown certs
	extDial, _ := startInMemoryTLSServer(t, metaXML, "external-idp.example.com")
	extLoader := &fedmetadata.SmartLoader{
		HTTPClient: newMetadataHTTPClientWithDialer(cfg, zap.NewNop(), extDial),
	}
	if _, err := extLoader.Load(context.Background(), "https://external-idp.example.com/metadata"); err == nil {
		t.Fatal("expected external host with untrusted certificate to be rejected")
	}

	// Production mode must enforce strict CA+SAN verification and reject mismatched SAN even for selfMetaHost
	prodCfg := &config.Config{
		Env: "production",
		SAML: config.SAMLConfig{
			MetadataURL: localMetaURL,
		},
		TLS: config.TLSConfig{
			Enabled:  true,
			CertFile: certPath,
		},
	}
	prodLoader := &fedmetadata.SmartLoader{
		HTTPClient: newMetadataHTTPClientWithDialer(prodCfg, zap.NewNop(), selfDial),
	}
	if _, err := prodLoader.Load(context.Background(), localMetaURL); err == nil {
		t.Fatal("expected production mode to enforce strict SAN verification and reject mismatch")
	}
}

func TestSetupApp_AdminGuideRouteProtectionAndHelpLink(t *testing.T) {
	if !strings.Contains(web.DefaultAdminSettingsHTML, `href="/admin/guide"`) {
		t.Errorf("expected embedded admin_settings.html help button to link to /admin/guide")
	}
	if !strings.Contains(web.DefaultUserGuideHTML, "User Guide") {
		t.Errorf("expected embedded user_guide.html to contain User Guide title")
	}

	app, cleanup, err := SetupAppWithCleanup(testConfig(t), testLogger())
	if err != nil {
		t.Fatalf("unexpected setup error: %v", err)
	}
	defer cleanup()

	wUnauth := httptest.NewRecorder()
	reqUnauth, _ := http.NewRequest(http.MethodGet, "/admin/guide", nil)
	app.ServeHTTP(wUnauth, reqUnauth)
	if wUnauth.Code != http.StatusSeeOther || !strings.Contains(wUnauth.Header().Get("Location"), "/admin/login") {
		t.Fatalf("expected unauthenticated GET /admin/guide to redirect to /admin/login, got %d (%q)", wUnauth.Code, wUnauth.Header().Get("Location"))
	}
}
