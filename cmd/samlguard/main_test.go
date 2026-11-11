package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/hidayat-SE/samlguard/internal/config"
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

	rawCorpReqXML := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_corp_ui_test_1" Version="2.0" IssueInstant="2026-11-04T12:00:00Z" Destination="http://localhost:8080/saml/sso" AssertionConsumerServiceURL="https://192.168.0.119/api/current/authentication/saml2-callback"><saml:Issuer>https://192.168.0.119</saml:Issuer></samlp:AuthnRequest>`
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
