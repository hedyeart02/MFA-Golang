package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/hidayat-SE/samlguard/internal/config"
	"github.com/hidayat-SE/samlguard/internal/mfa"
	"go.uber.org/zap"
)

func setupTestAdminHandler(t *testing.T) (*gin.Engine, *SAMLHandler, string) {
	gin.SetMode(gin.TestMode)

	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, "config.yaml")

	// Create dummy cert
	certDir := filepath.Join(tmpDir, "cert")
	_ = os.MkdirAll(certDir, 0755)
	dummyCert := filepath.Join(certDir, "saml-signing.crt")
	_ = os.WriteFile(dummyCert, []byte("-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJA...\n-----END CERTIFICATE-----\n"), 0644)

	initialYAML := `server:
  host: "0.0.0.0"
  port: 18080
saml:
  entity_id: "https://192.168.0.178:18080"
  acs_url: "https://192.168.0.119/callback"
  sso_url: "https://192.168.0.178:18080/login"
  slo_url: "https://192.168.0.178:18080/logout"
  cert_file: "` + strings.ReplaceAll(dummyCert, "\\", "/") + `"
  idp_entity_id: "https://192.168.0.178:18080"
  idp_sso_url: "https://192.168.0.178:18080/mock-idp-login"
  allowed_audiences:
    - "https://192.168.0.119"
mfa:
  default_provider: "totp"
  issuer: "SAMLGuard"
  otp_expiry: 5m
  resend_cooldown: 60s
  allow_dummy_otp: false
smtp:
  host: "localhost"
  port: 1025
  username: "testuser"
  password: "oldpassword"
  from: "test@samlguard.local"
  from_name: "SAMLGuard Test"
  encryption: "none"
`
	if err := os.WriteFile(cfgFile, []byte(initialYAML), 0644); err != nil {
		t.Fatalf("failed writing test config: %v", err)
	}

	cfg, err := config.Load(cfgFile)
	if err != nil {
		t.Fatalf("failed loading test config: %v", err)
	}

	dbPath := filepath.Join(tmpDir, "test.db")
	storage, err := mfa.NewSQLiteStorage(dbPath)
	if err != nil {
		t.Fatalf("failed creating sqlite storage: %v", err)
	}
	t.Cleanup(func() { _ = storage.Close() })

	smtpSender := mfa.NewSMTPSender(cfg.SMTP.Host, cfg.SMTP.Port, cfg.SMTP.Username, cfg.SMTP.Password, cfg.SMTP.From, cfg.SMTP.FromName, cfg.SMTP.Encryption, zap.NewNop())
	mfaSvc := mfa.NewService(storage, smtpSender, cfg, zap.NewNop())

	h := &SAMLHandler{
		mfaService: mfaSvc,
		cfg:        cfg,
		logger:     zap.NewNop(),
	}

	r := gin.New()
	r.GET("/admin/settings", h.HandleAdminSettingsGet)
	r.POST("/admin/settings", h.HandleAdminSettingsPost)
	r.POST("/admin/settings/test-email", h.HandleAdminTestEmailPost)
	r.POST("/admin/ita/sync", h.HandleAdminITASyncPost)
	r.POST("/admin/users/add", h.HandleAdminUserAddPost)
	r.POST("/admin/users/delete", h.HandleAdminUserDeletePost)
	r.GET("/admin/cert/download", h.HandleAdminCertDownload)

	return r, h, cfgFile
}

func TestAdminSettings_Get(t *testing.T) {
	r, _, _ := setupTestAdminHandler(t)

	req := httptest.NewRequest("GET", "/admin/settings", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "SAMLGuard Gateway Settings") {
		t.Errorf("expected page title in body")
	}
	if !strings.Contains(body, "Microsoft Entra ID (Azure AD)") {
		t.Errorf("expected Entra guide in body")
	}
	if !strings.Contains(body, "Downstream ITA ACS Callback URL") {
		t.Errorf("expected downstream form in body")
	}
}

func TestAdminSettings_Post(t *testing.T) {
	r, h, cfgFile := setupTestAdminHandler(t)

	// Override config path for test by mocking SaveConfig target in test
	form := url.Values{
		"idp_entity_id":          {"https://sts.windows.net/tenant-xyz/"},
		"idp_sso_url":            {"https://login.microsoftonline.com/tenant-xyz/saml2"},
		"idp_metadata_url":       {"https://login.microsoftonline.com/tenant-xyz/federationmetadata.xml"},
		"entity_id":              {"https://192.168.0.178:18080"},
		"acs_url":                {"https://192.168.0.119/api/current/authentication/saml2-callback"},
		"sso_url":                {"https://192.168.0.178:18080/login"},
		"slo_url":                {"https://192.168.0.178:18080/logout"},
		"allowed_audiences_str":  {"https://192.168.0.119, https://192.168.0.178:18080"},
		"group_map_key[]":        {"ita-admins"},
		"group_map_val[]":        {"Admin"},
		"mfa_default_provider":   {"email"},
		"mfa_issuer":             {"EcoStruxure ITA"},
		"otp_expiry":             {"10m"},
		"resend_cooldown":        {"45s"},
		"allow_dummy_otp":        {"true"},
		"smtp_host":              {"smtp.office365.com"},
		"smtp_port":              {"587"},
		"smtp_username":          {"notifications@company.com"},
		"smtp_password":          {""}, // Keep old password
		"smtp_from":              {"notifications@company.com"},
		"smtp_from_name":         {"ITA Security Gateway"},
		"smtp_encryption":        {"starttls"},
	}

	// We test SaveConfig with test cfgFile directly first
	payload := &config.AdminSettingsPayload{
		IdPEntityID:        form.Get("idp_entity_id"),
		IdPSSOURL:          form.Get("idp_sso_url"),
		ACSURL:             form.Get("acs_url"),
		EntityID:           form.Get("entity_id"),
		MFADefaultProvider: form.Get("mfa_default_provider"),
		SMTPHost:           form.Get("smtp_host"),
		AllowDummyOTP:      true,
	}
	if err := config.SaveConfig(cfgFile, h.cfg, payload); err != nil {
		t.Fatalf("SaveConfig failed: %v", err)
	}

	if h.cfg.SAML.IdPEntityID != "https://sts.windows.net/tenant-xyz/" {
		t.Errorf("expected updated IdPEntityID, got %s", h.cfg.SAML.IdPEntityID)
	}
	if h.cfg.MFA.DefaultProvider != "email" {
		t.Errorf("expected updated DefaultProvider, got %s", h.cfg.MFA.DefaultProvider)
	}
	if h.cfg.MFA.AllowDummyOTP != true {
		t.Errorf("expected AllowDummyOTP true")
	}

	// Test form post request handler
	req := httptest.NewRequest("POST", "/admin/settings", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from post handler, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAdminSettings_TestEmail(t *testing.T) {
	r, _, _ := setupTestAdminHandler(t)

	// 1. Missing recipient
	payload := map[string]interface{}{
		"recipient": "",
		"smtp_host": "smtp.example.com",
	}
	jsonBytes, _ := json.Marshal(payload)
	req := httptest.NewRequest("POST", "/admin/settings/test-email", bytes.NewReader(jsonBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w.Code)
	}
	var res map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if res["success"] == true {
		t.Errorf("expected success false on empty recipient")
	}
}

func TestAdminSettings_AddAndDeleteUser(t *testing.T) {
	r, h, _ := setupTestAdminHandler(t)

	// 1. Add user
	addPayload := map[string]string{
		"username":  "testoperator",
		"email":     "testoperator@company.com",
		"full_name": "Test Operator",
	}
	body, _ := json.Marshal(addPayload)
	req := httptest.NewRequest("POST", "/admin/users/add", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w.Code)
	}

	// Verify user is authorized
	auth, err := h.mfaService.IsUserAuthorized(req.Context(), "testoperator")
	if err != nil || !auth {
		t.Fatalf("expected testoperator to be authorized, auth=%v, err=%v", auth, err)
	}

	// 2. Delete user
	delPayload := map[string]string{"username": "testoperator"}
	delBody, _ := json.Marshal(delPayload)
	reqDel := httptest.NewRequest("POST", "/admin/users/delete", bytes.NewReader(delBody))
	reqDel.Header.Set("Content-Type", "application/json")
	wDel := httptest.NewRecorder()
	r.ServeHTTP(wDel, reqDel)

	if wDel.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", wDel.Code)
	}

	// Verify user is no longer authorized
	authAfter, _ := h.mfaService.IsUserAuthorized(req.Context(), "testoperator")
	if authAfter {
		t.Fatalf("expected testoperator to NOT be authorized after deletion")
	}
}

func TestAdminSettings_WhitelistEnforcement(t *testing.T) {
	_, h, _ := setupTestAdminHandler(t)
	ctx := context.Background()

	// Default apc and itaadmin should be authorized
	apcAuth, err := h.mfaService.IsUserAuthorized(ctx, "apc")
	if err != nil || !apcAuth {
		t.Fatalf("expected apc to be authorized by default, auth=%v, err=%v", apcAuth, err)
	}

	itaadminAuth, err := h.mfaService.IsUserAuthorized(ctx, "itaadmin@samlguard.local")
	if err != nil || !itaadminAuth {
		t.Fatalf("expected itaadmin to be authorized by default, auth=%v, err=%v", itaadminAuth, err)
	}

	// Unknown random email should be strictly BLOCKED!
	randomAuth, err := h.mfaService.IsUserAuthorized(ctx, "realchromatic@gmail.com")
	if err != nil || randomAuth {
		t.Fatalf("expected random email to be BLOCKED, got auth=%v", randomAuth)
	}
}
