package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
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
  entity_id: "https://samlguard.example.com:8443"
  acs_url: "https://ita.example.com/callback"
  sso_url: "https://samlguard.example.com:8443/login"
  slo_url: "https://samlguard.example.com:8443/logout"
  cert_file: "` + strings.ReplaceAll(dummyCert, "\\", "/") + `"
  idp_entity_id: "https://samlguard.example.com:8443"
  idp_sso_url: "https://samlguard.example.com:8443/mock-idp-login"
  allowed_audiences:
    - "https://ita.example.com"
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
	r, h, _ := setupTestAdminHandler(t)

	form := url.Values{
		"idp_entity_id":         {"https://sts.windows.net/tenant-xyz/"},
		"idp_sso_url":           {"https://login.microsoftonline.com/tenant-xyz/saml2"},
		"idp_metadata_url":      {"https://login.microsoftonline.com/tenant-xyz/federationmetadata.xml"},
		"entity_id":             {"https://samlguard.example.com:8443"},
		"acs_url":               {"https://ita.example.com/api/current/authentication/saml2-callback"},
		"sso_url":               {"https://samlguard.example.com:8443/login"},
		"slo_url":               {"https://samlguard.example.com:8443/logout"},
		"allowed_audiences_str": {"https://ita.example.com, https://samlguard.example.com:8443"},
		"group_map_key[]":       {"ita-admins"},
		"group_map_val[]":       {"Admin"},
		"mfa_default_provider":  {"email"},
		"mfa_issuer":            {"EcoStruxure ITA"},
		"otp_expiry":            {"10m"},
		"resend_cooldown":       {"45s"},
		"allow_dummy_otp":       {"true"},
		"smtp_host":             {"smtp.office365.com"},
		"smtp_port":             {"587"},
		"smtp_username":         {"notifications@company.com"},
		"smtp_password":         {""}, // Keep old password
		"smtp_from":             {"notifications@company.com"},
		"smtp_from_name":        {"ITA Security Gateway"},
		"smtp_encryption":       {"starttls"},
	}

	// Test form post request handler (note: CWD has no configs/config.yaml in package dir; must save to DB)
	req := httptest.NewRequest("POST", "/admin/settings", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from post handler, got %d: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "Configuration updated successfully and saved to database.") {
		t.Errorf("expected DB save confirmation message in response body")
	}

	// Verify in-memory cfg updated and existing SMTP password preserved
	if h.cfg.SAML.IdPEntityID != "https://sts.windows.net/tenant-xyz/" {
		t.Errorf("expected updated IdPEntityID, got %s", h.cfg.SAML.IdPEntityID)
	}
	if h.cfg.MFA.DefaultProvider != "email" {
		t.Errorf("expected updated DefaultProvider, got %s", h.cfg.MFA.DefaultProvider)
	}
	if !h.cfg.MFA.AllowDummyOTP {
		t.Errorf("expected AllowDummyOTP true")
	}
	if h.cfg.SMTP.Password != "oldpassword" {
		t.Errorf("expected existing SMTP password preserved, got %q", h.cfg.SMTP.Password)
	}

	// Verify persisted in SQLite database
	saved, err := h.mfaService.Storage().GetAdminSettings(context.Background())
	if err != nil {
		t.Fatalf("expected settings saved in DB, got error: %v", err)
	}
	if saved.IdPEntityID != "https://sts.windows.net/tenant-xyz/" {
		t.Errorf("expected persisted IdPEntityID, got %s", saved.IdPEntityID)
	}
	if saved.SMTPPassword != "oldpassword" {
		t.Errorf("expected persisted SMTPPassword 'oldpassword', got %q", saved.SMTPPassword)
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
	randomAuth, err := h.mfaService.IsUserAuthorized(ctx, "unauthorized@example.com")
	if err != nil || randomAuth {
		t.Fatalf("expected random email to be BLOCKED, got auth=%v", randomAuth)
	}
}

func setupAdminAuthEngine(h *SAMLHandler) *gin.Engine {
	r := gin.New()
	r.GET("/admin/login", h.HandleAdminLoginGet)
	r.POST("/admin/login", h.HandleAdminLoginPost)
	r.GET("/admin/change-password", h.HandleAdminChangePasswordGet)
	r.POST("/admin/change-password", h.HandleAdminChangePasswordPost)
	r.POST("/admin/logout", h.HandleAdminLogout)

	adminProtected := r.Group("/admin", h.RequireAdminAuth(), h.RequireAdminCSRF())
	{
		adminProtected.GET("/settings", h.HandleAdminSettingsGet)
		adminProtected.POST("/settings", h.HandleAdminSettingsPost)
		adminProtected.POST("/users/add", h.HandleAdminUserAddPost)
		adminProtected.POST("/users/reset-mfa", h.HandleAdminUserResetMFAPost)
	}
	return r
}

func extractAdminCSRF(t *testing.T, body string) string {
	t.Helper()
	reMeta := regexp.MustCompile(`<meta name="csrf-token" content="([^"]+)"`)
	if m := reMeta.FindStringSubmatch(body); len(m) >= 2 && m[1] != "" {
		return m[1]
	}
	reInput := regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)
	if m := reInput.FindStringSubmatch(body); len(m) >= 2 && m[1] != "" {
		return m[1]
	}
	t.Fatalf("expected CSRF token in HTML response")
	return ""
}

func TestAdminAuth_CompleteLifecycle(t *testing.T) {
	_, h, _ := setupTestAdminHandler(t)
	r := setupAdminAuthEngine(h)

	// 1. Unauthenticated access to /admin/settings should redirect to /admin/login
	req := httptest.NewRequest("GET", "/admin/settings", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/admin/login" {
		t.Fatalf("expected 303 redirect to /admin/login, got code=%d location=%s", w.Code, w.Header().Get("Location"))
	}

	// 2. Unauthenticated JSON request should return 401 Unauthorized
	reqJSON := httptest.NewRequest("POST", "/admin/users/add", strings.NewReader(`{"username":"test"}`))
	reqJSON.Header.Set("Accept", "application/json")
	wJSON := httptest.NewRecorder()
	r.ServeHTTP(wJSON, reqJSON)
	if wJSON.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for JSON request, got %d", wJSON.Code)
	}

	// 3. Login GET renders login page
	reqLoginGet := httptest.NewRequest("GET", "/admin/login", nil)
	wLoginGet := httptest.NewRecorder()
	r.ServeHTTP(wLoginGet, reqLoginGet)
	if wLoginGet.Code != http.StatusOK || !strings.Contains(wLoginGet.Body.String(), "SAMLGuard Admin Console") {
		t.Fatalf("expected 200 OK with admin login form, got %d", wLoginGet.Code)
	}

	// 4. Invalid credentials should fail
	badLoginForm := url.Values{
		"username": {"admin"},
		"password": {"wrongpass123"},
	}
	reqBadLogin := httptest.NewRequest("POST", "/admin/login", strings.NewReader(badLoginForm.Encode()))
	reqBadLogin.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	wBadLogin := httptest.NewRecorder()
	r.ServeHTTP(wBadLogin, reqBadLogin)
	if wBadLogin.Code != http.StatusOK || !strings.Contains(wBadLogin.Body.String(), "invalid administrator credentials") {
		t.Fatalf("expected login error banner, got code=%d body=%s", wBadLogin.Code, wBadLogin.Body.String())
	}

	// 5. Valid default credentials (admin / admin) -> should redirect to /admin/change-password
	validLoginForm := url.Values{
		"username": {"admin"},
		"password": {"admin"},
	}
	reqLogin := httptest.NewRequest("POST", "/admin/login", strings.NewReader(validLoginForm.Encode()))
	reqLogin.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	wLogin := httptest.NewRecorder()
	r.ServeHTTP(wLogin, reqLogin)

	if wLogin.Code != http.StatusSeeOther || wLogin.Header().Get("Location") != "/admin/change-password" {
		t.Fatalf("expected 303 redirect to /admin/change-password, got code=%d location=%s", wLogin.Code, wLogin.Header().Get("Location"))
	}

	// Extract session cookie
	sessionCookie := ""
	for _, cookie := range wLogin.Result().Cookies() {
		if cookie.Name == "samlguard_admin_session" {
			sessionCookie = cookie.Value
			break
		}
	}
	if sessionCookie == "" {
		t.Fatalf("expected samlguard_admin_session cookie to be set")
	}

	// 6. Accessing /admin/settings before changing default password MUST be blocked and redirected to /admin/change-password
	reqBlockedSettings := httptest.NewRequest("GET", "/admin/settings", nil)
	reqBlockedSettings.AddCookie(&http.Cookie{Name: "samlguard_admin_session", Value: sessionCookie})
	wBlockedSettings := httptest.NewRecorder()
	r.ServeHTTP(wBlockedSettings, reqBlockedSettings)

	if wBlockedSettings.Code != http.StatusSeeOther || wBlockedSettings.Header().Get("Location") != "/admin/change-password" {
		t.Fatalf("expected redirect to /admin/change-password when must_change_password=1, got code=%d loc=%s", wBlockedSettings.Code, wBlockedSettings.Header().Get("Location"))
	}

	// 7. GET /admin/change-password with session works and includes a CSRF token
	reqChangePwdGet := httptest.NewRequest("GET", "/admin/change-password", nil)
	reqChangePwdGet.AddCookie(&http.Cookie{Name: "samlguard_admin_session", Value: sessionCookie})
	wChangePwdGet := httptest.NewRecorder()
	r.ServeHTTP(wChangePwdGet, reqChangePwdGet)
	if wChangePwdGet.Code != http.StatusOK || !strings.Contains(wChangePwdGet.Body.String(), "Change Administrator Password") {
		t.Fatalf("expected change password page, got %d", wChangePwdGet.Code)
	}
	changePwdCSRF := extractAdminCSRF(t, wChangePwdGet.Body.String())

	// 7b. Missing CSRF token on POST /admin/change-password must be blocked with 403
	reqNoCSRF := httptest.NewRequest("POST", "/admin/change-password", strings.NewReader(url.Values{
		"new_password":     {"Admin@SecurePass2026!"},
		"confirm_password": {"Admin@SecurePass2026!"},
	}.Encode()))
	reqNoCSRF.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqNoCSRF.AddCookie(&http.Cookie{Name: "samlguard_admin_session", Value: sessionCookie})
	wNoCSRF := httptest.NewRecorder()
	r.ServeHTTP(wNoCSRF, reqNoCSRF)
	if wNoCSRF.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden without CSRF token on /admin/change-password, got %d", wNoCSRF.Code)
	}

	// 8. Attempting to set password shorter than 8 chars should fail
	shortPwdForm := url.Values{
		"csrf_token":       {changePwdCSRF},
		"new_password":     {"short"},
		"confirm_password": {"short"},
	}
	reqShortPwd := httptest.NewRequest("POST", "/admin/change-password", strings.NewReader(shortPwdForm.Encode()))
	reqShortPwd.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqShortPwd.AddCookie(&http.Cookie{Name: "samlguard_admin_session", Value: sessionCookie})
	wShortPwd := httptest.NewRecorder()
	r.ServeHTTP(wShortPwd, reqShortPwd)
	if !strings.Contains(wShortPwd.Body.String(), "at least 8 characters long") {
		t.Fatalf("expected minimum length validation error, got: %s", wShortPwd.Body.String())
	}

	// 9. Attempting to reuse default password should fail
	defaultPwdForm := url.Values{
		"csrf_token":       {changePwdCSRF},
		"new_password":     {"admin123"},
		"confirm_password": {"admin123"},
	}
	reqDefaultPwd := httptest.NewRequest("POST", "/admin/change-password", strings.NewReader(defaultPwdForm.Encode()))
	reqDefaultPwd.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqDefaultPwd.AddCookie(&http.Cookie{Name: "samlguard_admin_session", Value: sessionCookie})
	wDefaultPwd := httptest.NewRecorder()
	r.ServeHTTP(wDefaultPwd, reqDefaultPwd)
	if !strings.Contains(wDefaultPwd.Body.String(), "cannot be the default password") {
		t.Fatalf("expected default password rejection error, got: %s", wDefaultPwd.Body.String())
	}

	// 10. Valid new password change
	validPwdForm := url.Values{
		"csrf_token":       {changePwdCSRF},
		"new_password":     {"Admin@SecurePass2026!"},
		"confirm_password": {"Admin@SecurePass2026!"},
	}
	reqValidPwd := httptest.NewRequest("POST", "/admin/change-password", strings.NewReader(validPwdForm.Encode()))
	reqValidPwd.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqValidPwd.AddCookie(&http.Cookie{Name: "samlguard_admin_session", Value: sessionCookie})
	wValidPwd := httptest.NewRecorder()
	r.ServeHTTP(wValidPwd, reqValidPwd)

	if wValidPwd.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 redirect after successful password change, got %d", wValidPwd.Code)
	}

	// Get updated session cookie
	updatedCookie := ""
	for _, cookie := range wValidPwd.Result().Cookies() {
		if cookie.Name == "samlguard_admin_session" {
			updatedCookie = cookie.Value
			break
		}
	}
	if updatedCookie == "" {
		t.Fatalf("expected updated session cookie after password change")
	}

	// 11. Now /admin/settings is accessible!
	reqAllowedSettings := httptest.NewRequest("GET", "/admin/settings", nil)
	reqAllowedSettings.AddCookie(&http.Cookie{Name: "samlguard_admin_session", Value: updatedCookie})
	wAllowedSettings := httptest.NewRecorder()
	r.ServeHTTP(wAllowedSettings, reqAllowedSettings)
	if wAllowedSettings.Code != http.StatusOK {
		t.Fatalf("expected 200 OK after password change, got %d: %s", wAllowedSettings.Code, wAllowedSettings.Body.String())
	}
	if !strings.Contains(wAllowedSettings.Body.String(), "👤 admin") {
		t.Errorf("expected admin username badge in settings header")
	}
	settingsCSRF := extractAdminCSRF(t, wAllowedSettings.Body.String())

	// 11b. Protected JSON route without X-CSRF-Token must be blocked with 403
	reqResetNoCSRF := httptest.NewRequest("POST", "/admin/users/reset-mfa", strings.NewReader(`{"username":"apc"}`))
	reqResetNoCSRF.Header.Set("Content-Type", "application/json")
	reqResetNoCSRF.AddCookie(&http.Cookie{Name: "samlguard_admin_session", Value: updatedCookie})
	wResetNoCSRF := httptest.NewRecorder()
	r.ServeHTTP(wResetNoCSRF, reqResetNoCSRF)
	if wResetNoCSRF.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden without X-CSRF-Token, got %d", wResetNoCSRF.Code)
	}

	// 11c. Protected JSON route with valid X-CSRF-Token succeeds
	reqResetOK := httptest.NewRequest("POST", "/admin/users/reset-mfa", strings.NewReader(`{"username":"apc"}`))
	reqResetOK.Header.Set("Content-Type", "application/json")
	reqResetOK.Header.Set("X-CSRF-Token", settingsCSRF)
	reqResetOK.AddCookie(&http.Cookie{Name: "samlguard_admin_session", Value: updatedCookie})
	wResetOK := httptest.NewRecorder()
	r.ServeHTTP(wResetOK, reqResetOK)
	if wResetOK.Code != http.StatusOK || !strings.Contains(wResetOK.Body.String(), `"success":true`) {
		t.Fatalf("expected 200 success from /admin/users/reset-mfa, got %d: %s", wResetOK.Code, wResetOK.Body.String())
	}

	// 12. Logout requires valid CSRF token when session is present
	reqLogoutNoCSRF := httptest.NewRequest("POST", "/admin/logout", nil)
	reqLogoutNoCSRF.AddCookie(&http.Cookie{Name: "samlguard_admin_session", Value: updatedCookie})
	wLogoutNoCSRF := httptest.NewRecorder()
	r.ServeHTTP(wLogoutNoCSRF, reqLogoutNoCSRF)
	if wLogoutNoCSRF.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden on /admin/logout without CSRF, got %d", wLogoutNoCSRF.Code)
	}

	logoutForm := url.Values{"csrf_token": {settingsCSRF}}
	reqLogout := httptest.NewRequest("POST", "/admin/logout", strings.NewReader(logoutForm.Encode()))
	reqLogout.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqLogout.AddCookie(&http.Cookie{Name: "samlguard_admin_session", Value: updatedCookie})
	wLogout := httptest.NewRecorder()
	r.ServeHTTP(wLogout, reqLogout)
	if wLogout.Code != http.StatusSeeOther || wLogout.Header().Get("Location") != "/admin/login" {
		t.Fatalf("expected redirect to /admin/login after logout, got %d", wLogout.Code)
	}
}

func TestAdminCertDownload_ValidationAndNoPathLeak(t *testing.T) {
	cfg := &config.Config{
		Env: "development",
		SAML: config.SAMLConfig{
			CertFile: "/nonexistent/internal/secret/saml.crt",
		},
		TLS: config.TLSConfig{
			CertFile: "/nonexistent/internal/secret/server.crt",
		},
	}
	h := &SAMLHandler{cfg: cfg, logger: zap.NewNop()}
	r := gin.New()
	r.GET("/admin/cert/download", h.HandleAdminCertDownload)

	wBad := httptest.NewRecorder()
	reqBad := httptest.NewRequest(http.MethodGet, "/admin/cert/download?type=../../etc/passwd", nil)
	r.ServeHTTP(wBad, reqBad)
	if wBad.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for invalid cert type, got %d", wBad.Code)
	}

	wMissing := httptest.NewRecorder()
	reqMissing := httptest.NewRequest(http.MethodGet, "/admin/cert/download?type=server", nil)
	r.ServeHTTP(wMissing, reqMissing)
	if wMissing.Code != http.StatusNotFound {
		t.Fatalf("expected 404 Not Found for missing cert, got %d", wMissing.Code)
	}
	if strings.Contains(wMissing.Body.String(), "/nonexistent/internal/secret") {
		t.Fatalf("expected 404 body not to leak filesystem path, got: %s", wMissing.Body.String())
	}
}

func TestAdminSettings_UpstreamIdPAndMultiOTP(t *testing.T) {
	r, h, _ := setupTestAdminHandler(t)

	// 1. Verify GET renders selectable Upstream IdPs, Multi-OTP toggles, and consolidated Email OTP/SMTP settings without duplicate IDs
	reqGet := httptest.NewRequest("GET", "/admin/settings", nil)
	wGet := httptest.NewRecorder()
	r.ServeHTTP(wGet, reqGet)
	if wGet.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", wGet.Code)
	}
	body := wGet.Body.String()
	for _, needle := range []string{
		`selectUpstreamIdP('simulator')`,
		`selectUpstreamIdP('entra')`,
		`selectUpstreamIdP('keycloak')`,
		`selectUpstreamIdP('custom')`,
		`name="mfa_enabled_providers[]"`,
		`name="mfa_providers_submitted"`,
		`Email OTP (SMTP)`,
	} {
		if !strings.Contains(body, needle) {
			t.Errorf("expected admin settings HTML to contain %q", needle)
		}
	}
	if count := strings.Count(body, `id="smtp_host"`); count != 1 {
		t.Errorf("expected exactly 1 id=\"smtp_host\" across consolidated form, got %d", count)
	}
	if count := strings.Count(body, `id="mfa_issuer"`); count != 1 {
		t.Errorf("expected exactly 1 id=\"mfa_issuer\" across consolidated form, got %d", count)
	}

	// 2. Reject form submission with mfa_providers_submitted=1 and zero enabled OTP providers
	emptyOTPForm := url.Values{
		"active_idp":              {"simulator"},
		"idp_entity_id":           {"https://samlguard.example.com:8443"},
		"idp_sso_url":             {"https://samlguard.example.com:8443/mock-idp-login"},
		"entity_id":               {"https://samlguard.example.com:8443"},
		"acs_url":                 {"https://ita.example.com/callback"},
		"mfa_providers_submitted": {"1"},
		"mfa_issuer":              {"SAMLGuard"},
	}
	reqEmptyOTP := httptest.NewRequest("POST", "/admin/settings", strings.NewReader(emptyOTPForm.Encode()))
	reqEmptyOTP.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	wEmptyOTP := httptest.NewRecorder()
	r.ServeHTTP(wEmptyOTP, reqEmptyOTP)
	if !strings.Contains(wEmptyOTP.Body.String(), "at least one OTP verification method") {
		t.Fatalf("expected rejection error when disabling all OTP methods, got: %s", wEmptyOTP.Body.String())
	}

	// 3. Activate Microsoft Entra ID + both TOTP and Email OTP simultaneously (with Email OTP default)
	profilesJSON := `{"simulator":{"entity_id":"https://samlguard.example.com:8443","sso_url":"https://samlguard.example.com:8443/mock-idp-login","cert_file":"./cert/saml-signing.crt"}}`
	multiOTPForm := url.Values{
		"active_idp":              {"entra"},
		"idp_profiles_json":       {profilesJSON},
		"idp_entity_id":           {"https://sts.windows.net/tenant-multi/"},
		"idp_sso_url":             {"https://login.microsoftonline.com/tenant-multi/saml2"},
		"idp_cert_file":           {h.cfg.SAML.CertFile},
		"entity_id":               {"https://samlguard.example.com:8443"},
		"acs_url":                 {"https://ita.example.com/callback"},
		"mfa_providers_submitted": {"1"},
		"mfa_enabled_providers[]": {"totp", "email"},
		"mfa_default_provider":    {"email"},
		"mfa_issuer":              {"SAMLGuard Multi"},
		"otp_expiry":              {"5m"},
		"resend_cooldown":         {"60s"},
		"smtp_host":               {"smtp.office365.com"},
		"smtp_port":               {"587"},
	}
	reqMulti := httptest.NewRequest("POST", "/admin/settings", strings.NewReader(multiOTPForm.Encode()))
	reqMulti.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	wMulti := httptest.NewRecorder()
	r.ServeHTTP(wMulti, reqMulti)
	if wMulti.Code != http.StatusOK || !strings.Contains(wMulti.Body.String(), "Configuration updated successfully") {
		t.Fatalf("expected multi-OTP settings save success, got status %d body: %s", wMulti.Code, wMulti.Body.String())
	}
	if h.cfg.SAML.ActiveIdP != "entra" {
		t.Errorf("expected ActiveIdP 'entra', got %q", h.cfg.SAML.ActiveIdP)
	}
	if _, ok := h.cfg.SAML.IdPProfiles["simulator"]; !ok {
		t.Errorf("expected simulator profile preserved in IdPProfiles")
	}
	if !h.cfg.MFA.IsProviderEnabled("totp") || !h.cfg.MFA.IsProviderEnabled("email") {
		t.Errorf("expected both totp and email active, got %v", h.cfg.MFA.ActiveProviders())
	}
	if h.cfg.MFA.DefaultProvider != "email" {
		t.Errorf("expected DefaultProvider 'email', got %q", h.cfg.MFA.DefaultProvider)
	}

	// 4. Switch to Email-OTP-only while submitting stale mfa_default_provider=totp -> auto-aligns to email
	emailOnlyForm := url.Values{
		"active_idp":              {"keycloak"},
		"idp_entity_id":           {"https://kc.example.com/realms/main"},
		"idp_sso_url":             {"https://kc.example.com/realms/main/protocol/saml"},
		"entity_id":               {"https://samlguard.example.com:8443"},
		"acs_url":                 {"https://ita.example.com/callback"},
		"mfa_providers_submitted": {"1"},
		"mfa_enabled_providers[]": {"email"},
		"mfa_default_provider":    {"totp"},
		"otp_expiry":              {"5m"},
		"resend_cooldown":         {"60s"},
		"smtp_host":               {"smtp.office365.com"},
		"smtp_port":               {"587"},
	}
	reqEmailOnly := httptest.NewRequest("POST", "/admin/settings", strings.NewReader(emailOnlyForm.Encode()))
	reqEmailOnly.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	wEmailOnly := httptest.NewRecorder()
	r.ServeHTTP(wEmailOnly, reqEmailOnly)
	if wEmailOnly.Code != http.StatusOK || !strings.Contains(wEmailOnly.Body.String(), "Configuration updated successfully") {
		t.Fatalf("expected email-only save success, got %d: %s", wEmailOnly.Code, wEmailOnly.Body.String())
	}
	if h.cfg.MFA.IsProviderEnabled("totp") || !h.cfg.MFA.IsProviderEnabled("email") {
		t.Errorf("expected only email enabled, got %v", h.cfg.MFA.ActiveProviders())
	}
	if h.cfg.MFA.DefaultProvider != "email" {
		t.Errorf("expected DefaultProvider auto-aligned to 'email', got %q", h.cfg.MFA.DefaultProvider)
	}
}

func TestAdminSettings_MultiIdPAndSelectFlow(t *testing.T) {
	r, h, _ := setupTestAdminHandler(t)

	// 1. Reject idp_providers_submitted=1 with zero enabled_idps[]
	emptyIdPForm := url.Values{
		"idp_providers_submitted": {"1"},
		"entity_id":               {"https://samlguard.example.com:8443"},
		"acs_url":                 {"https://ita.example.com/callback"},
		"mfa_providers_submitted": {"1"},
		"mfa_enabled_providers[]": {"totp"},
		"mfa_default_provider":    {"totp"},
		"mfa_issuer":              {"SAMLGuard"},
	}
	reqEmptyIdP := httptest.NewRequest("POST", "/admin/settings", strings.NewReader(emptyIdPForm.Encode()))
	reqEmptyIdP.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	wEmptyIdP := httptest.NewRecorder()
	r.ServeHTTP(wEmptyIdP, reqEmptyIdP)
	if !strings.Contains(wEmptyIdP.Body.String(), "at least one Upstream Identity Provider") {
		t.Fatalf("expected rejection error when disabling all upstream IdPs, got: %s", wEmptyIdP.Body.String())
	}

	// 2. Enable multiple Upstream IdPs (simulator + entra) with isolated profiles and MFA default = select
	profilesJSON := `{"simulator":{"entity_id":"https://samlguard.example.com:8443","sso_url":"https://samlguard.example.com:8443/mock-idp-login","cert_file":"./cert/saml-signing.crt"}}`
	multiIdPForm := url.Values{
		"idp_providers_submitted": {"1"},
		"enabled_idps[]":          {"simulator", "entra"},
		"active_idp":              {"entra"},
		"idp_profiles_json":       {profilesJSON},
		"idp_entity_id":           {"https://sts.windows.net/tenant-123/"},
		"idp_sso_url":             {"https://login.microsoftonline.com/tenant-123/saml2"},
		"idp_cert_file":           {h.cfg.SAML.CertFile},
		"entity_id":               {"https://samlguard.example.com:8443"},
		"acs_url":                 {"https://ita.example.com/callback"},
		"mfa_providers_submitted": {"1"},
		"mfa_enabled_providers[]": {"totp", "email"},
		"mfa_default_provider":    {"select"},
		"mfa_issuer":              {"SAMLGuard"},
		"otp_expiry":              {"5m"},
		"resend_cooldown":         {"60s"},
		"smtp_host":               {"smtp.office365.com"},
		"smtp_port":               {"587"},
	}
	reqMulti := httptest.NewRequest("POST", "/admin/settings", strings.NewReader(multiIdPForm.Encode()))
	reqMulti.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	wMulti := httptest.NewRecorder()
	r.ServeHTTP(wMulti, reqMulti)
	if wMulti.Code != http.StatusOK || !strings.Contains(wMulti.Body.String(), "Configuration updated successfully") {
		t.Fatalf("expected multi-IdP settings save success, got status %d body: %s", wMulti.Code, wMulti.Body.String())
	}
	if !h.cfg.SAML.IsIdPEnabled("simulator") || !h.cfg.SAML.IsIdPEnabled("entra") {
		t.Errorf("expected both simulator and entra enabled, got %v", h.cfg.SAML.ActiveIdPs())
	}
	if h.cfg.SAML.ProfileForIdP("simulator").SSOURL != "https://samlguard.example.com:8443/mock-idp-login" {
		t.Errorf("expected simulator profile preserved independently, got %+v", h.cfg.SAML.ProfileForIdP("simulator"))
	}
	if h.cfg.SAML.ProfileForIdP("entra").EntityID != "https://sts.windows.net/tenant-123/" {
		t.Errorf("expected entra profile saved independently, got %+v", h.cfg.SAML.ProfileForIdP("entra"))
	}
	if h.cfg.MFA.DefaultProvider != "select" || !h.cfg.MFA.IsMethodSelectDefault() {
		t.Errorf("expected DefaultProvider 'select' preserved, got %q", h.cfg.MFA.DefaultProvider)
	}
}

func TestAdminSettings_SMSProfilesTestAndUserPhone(t *testing.T) {
	r, h, _ := setupTestAdminHandler(t)

	// 1. Save Multi-OTP including SMS with Twilio + SendQuick integration profiles
	smsProfilesJSON := `{"twilio":{"api_url":"https://api.twilio.com/2010-04-01","account_id":"AC111","auth_token":"twilio-secret-token","sender_id":"+15550001234","http_method":"POST"}}`
	form := url.Values{
		"idp_providers_submitted": {"1"},
		"enabled_idps[]":          {"simulator"},
		"active_idp":              {"simulator"},
		"idp_entity_id":           {h.cfg.SAML.IdPEntityID},
		"idp_sso_url":             {h.cfg.SAML.IdPSSOURL},
		"entity_id":               {h.cfg.SAML.EntityID},
		"acs_url":                 {h.cfg.SAML.ACSURL},
		"mfa_providers_submitted": {"1"},
		"mfa_enabled_providers[]": {"totp", "email", "sms"},
		"mfa_default_provider":    {"select"},
		"mfa_issuer":              {"SAMLGuard"},
		"otp_expiry":              {"5m"},
		"resend_cooldown":         {"60s"},
		"smtp_host":               {"localhost"},
		"smtp_port":               {"1025"},
		"sms_provider":            {"sendquick"},
		"sms_api_url":             {"mock://dev"},
		"sms_account_id":          {"sq_user"},
		"sms_auth_token":          {"sq-secret-token"},
		"sms_sender_id":           {"SAMLGuard"},
		"sms_http_method":         {"POST"},
		"sms_message_template":    {"Your SAMLGuard OTP is {code}"},
		"sms_profiles_json":       {smsProfilesJSON},
	}

	req := httptest.NewRequest(http.MethodPost, "/admin/settings", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Configuration updated successfully") {
		t.Fatalf("expected SMS settings save success, got %d: %s", w.Code, w.Body.String())
	}
	if !h.cfg.MFA.IsProviderEnabled("sms") || h.cfg.SMS.Provider != "sendquick" || h.cfg.SMS.AuthToken != "sq-secret-token" {
		t.Fatalf("unexpected runtime SMS config after save: %+v", h.cfg.SMS)
	}
	if h.cfg.SMS.ProfileForProvider("twilio").AuthToken != "twilio-secret-token" {
		t.Fatalf("expected Twilio profile token saved alongside SendQuick")
	}

	// 2. Re-submit with blank sms_auth_token -> preserves existing sq-secret-token
	form.Set("sms_auth_token", "")
	form.Set("sms_profiles_json", "")
	req2 := httptest.NewRequest(http.MethodPost, "/admin/settings", strings.NewReader(form.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK || h.cfg.SMS.AuthToken != "sq-secret-token" {
		t.Fatalf("expected blank sms_auth_token submission to preserve stored secret, got %q", h.cfg.SMS.AuthToken)
	}

	// 3. Test live SMS gateway test endpoint (/admin/settings/test-sms)
	r.POST("/admin/settings/test-sms", h.HandleAdminTestSMSPost)
	r.POST("/admin/users/update-phone", h.HandleAdminUserUpdatePhonePost)

	testSMSBody := `{"recipient":"+60123456789","provider":"sendquick","api_url":"mock://dev","account_id":"sq_user","sender_id":"SAMLGuard"}`
	reqTest := httptest.NewRequest(http.MethodPost, "/admin/settings/test-sms", bytes.NewBufferString(testSMSBody))
	reqTest.Header.Set("Content-Type", "application/json")
	wTest := httptest.NewRecorder()
	r.ServeHTTP(wTest, reqTest)
	var testResp map[string]any
	if err := json.Unmarshal(wTest.Body.Bytes(), &testResp); err != nil || testResp["success"] != true {
		t.Fatalf("expected HandleAdminTestSMSPost success, got %s", wTest.Body.String())
	}

	// 4. Add authorized user with phone & update phone via /admin/users/update-phone
	addBody := `{"username":"alice_sms","email":"alice@example.com","phone":"+60129998877","full_name":"Alice SMS"}`
	reqAdd := httptest.NewRequest(http.MethodPost, "/admin/users/add", bytes.NewBufferString(addBody))
	reqAdd.Header.Set("Content-Type", "application/json")
	wAdd := httptest.NewRecorder()
	r.ServeHTTP(wAdd, reqAdd)
	if !strings.Contains(wAdd.Body.String(), `"success":true`) {
		t.Fatalf("expected user add success, got: %s", wAdd.Body.String())
	}

	updBody := `{"username":"alice_sms","phone":"+6581112222"}`
	reqUpd := httptest.NewRequest(http.MethodPost, "/admin/users/update-phone", bytes.NewBufferString(updBody))
	reqUpd.Header.Set("Content-Type", "application/json")
	wUpd := httptest.NewRecorder()
	r.ServeHTTP(wUpd, reqUpd)
	if !strings.Contains(wUpd.Body.String(), `+6581112222`) {
		t.Fatalf("expected updated phone response, got: %s", wUpd.Body.String())
	}
	if got := h.mfaService.LookupUserPhone(context.Background(), "alice_sms"); got != "+6581112222" {
		t.Fatalf("expected persisted updated phone '+6581112222', got %q", got)
	}

	// 5. Render /admin/settings and verify hardware SMS gateway presets (SendQuick, SMSEagle, MultiTech, Teltonika) render
	wSettings := httptest.NewRecorder()
	r.ServeHTTP(wSettings, httptest.NewRequest(http.MethodGet, "/admin/settings", nil))
	if wSettings.Code != http.StatusOK {
		t.Fatalf("expected 200 GET /admin/settings, got %d", wSettings.Code)
	}
	settingsBody := wSettings.Body.String()
	for _, want := range []string{"SendQuick", "SMSEagle", "MultiTech iSMS", "Teltonika RUT/TRB", "data-sms-choice=\"smseagle\"", "data-sms-choice=\"multitech\"", "data-sms-choice=\"teltonika\""} {
		if !strings.Contains(settingsBody, want) {
			t.Errorf("expected admin settings HTML to include hardware SMS provider %q", want)
		}
	}
}

func TestAdminSettings_CustomThemeProfilesAndBrandingAssets(t *testing.T) {
	r, h, _ := setupTestAdminHandler(t)
	r.POST("/admin/branding/upload", h.HandleAdminBrandingUploadPost)
	r.GET("/branding/assets/:id", h.HandleBrandingAssetGet)
	r.GET("/admin/login", h.HandleAdminLoginGet)

	uploadFile := func(filename string, content []byte) *httptest.ResponseRecorder {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		_ = mw.WriteField("slot", "app_icon")
		part, err := mw.CreateFormFile("file", filename)
		if err != nil {
			t.Fatalf("CreateFormFile failed: %v", err)
		}
		if _, err := part.Write(content); err != nil {
			t.Fatalf("Write part failed: %v", err)
		}
		_ = mw.Close()

		req := httptest.NewRequest(http.MethodPost, "/admin/branding/upload", &buf)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}

	// 1. Valid PNG upload succeeds and is retrievable from /branding/assets/:id
	pngBytes := []byte{
		0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
		0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
		0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4, 0x89,
		0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41, 0x54,
		0x78, 0x9C, 0x63, 0x00, 0x01, 0x00, 0x00, 0x05, 0x00, 0x01,
		0x0D, 0x0A, 0x2D, 0xB4, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
	}
	wPNG := uploadFile("logo.png", pngBytes)
	if wPNG.Code != http.StatusOK {
		t.Fatalf("expected 200 on PNG upload, got %d: %s", wPNG.Code, wPNG.Body.String())
	}
	var pngResp map[string]any
	if err := json.Unmarshal(wPNG.Body.Bytes(), &pngResp); err != nil || pngResp["success"] != true {
		t.Fatalf("unexpected PNG upload JSON: %s", wPNG.Body.String())
	}
	uploadedURL, _ := pngResp["url"].(string)
	if !strings.HasPrefix(uploadedURL, "/branding/assets/") {
		t.Fatalf("expected /branding/assets/ URL, got %q", uploadedURL)
	}

	wGet := httptest.NewRecorder()
	r.ServeHTTP(wGet, httptest.NewRequest(http.MethodGet, uploadedURL, nil))
	if wGet.Code != http.StatusOK || wGet.Header().Get("Content-Type") != "image/png" || wGet.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("unexpected GET %s response: code=%d headers=%v", uploadedURL, wGet.Code, wGet.Header())
	}
	if !bytes.Equal(wGet.Body.Bytes(), pngBytes) {
		t.Fatalf("served asset bytes mismatch")
	}

	// 2. Reject unsafe SVG with embedded <script> or event handlers; allow clean SVG
	wBadSVG := uploadFile("evil.svg", []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`))
	if wBadSVG.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 rejecting scripted SVG, got %d: %s", wBadSVG.Code, wBadSVG.Body.String())
	}
	wGoodSVG := uploadFile("clean.svg", []byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/></svg>`))
	if wGoodSVG.Code != http.StatusOK {
		t.Fatalf("expected 200 for safe SVG, got %d: %s", wGoodSVG.Code, wGoodSVG.Body.String())
	}

	// 3. Persist custom theme profile in /admin/settings
	profilesPayload, _ := json.Marshal(map[string]config.ThemeProfile{
		"default": config.DefaultThemeProfile(),
		"acme-app": {
			Name:            "Acme Portal Theme",
			AppName:         "AcmeGuard",
			TargetAppName:   "Acme Cloud ERP",
			Subtitle:        "Enterprise SSO",
			AccentColor:     "#2563EB",
			AppIcon:         uploadedURL,
			OrgLogo:         uploadedURL,
			LoginBgDark:     uploadedURL,
			ConsoleBgDark:   uploadedURL,
			HeaderLogoDark:  uploadedURL,
			HeaderLogoLight: uploadedURL,
		},
	})

	form := url.Values{
		"idp_entity_id":           {h.cfg.SAML.IdPEntityID},
		"idp_sso_url":             {h.cfg.SAML.IdPSSOURL},
		"entity_id":               {h.cfg.SAML.EntityID},
		"acs_url":                 {h.cfg.SAML.ACSURL},
		"mfa_default_provider":    {"totp"},
		"mfa_issuer":              {"SAMLGuard"},
		"otp_expiry":              {"5m"},
		"resend_cooldown":         {"60s"},
		"smtp_host":               {"localhost"},
		"smtp_port":               {"1025"},
		"branding_active_profile": {"acme-app"},
		"branding_profiles_json":  {string(profilesPayload)},
	}
	reqSave := httptest.NewRequest(http.MethodPost, "/admin/settings", strings.NewReader(form.Encode()))
	reqSave.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	wSave := httptest.NewRecorder()
	r.ServeHTTP(wSave, reqSave)
	if wSave.Code != http.StatusOK || !strings.Contains(wSave.Body.String(), "Configuration updated successfully") {
		t.Fatalf("expected settings save 200 OK, got %d: %s", wSave.Code, wSave.Body.String())
	}
	if h.cfg.Branding.EffectiveActiveProfile() != "acme-app" || h.cfg.Branding.Resolve().AppName != "AcmeGuard" {
		t.Fatalf("expected runtime branding updated to acme-app/AcmeGuard, got %+v", h.cfg.Branding.Resolve())
	}

	// 4. Subsequent settings POST without branding fields preserves saved branding profiles
	formWithoutBranding := url.Values{
		"idp_entity_id":        {h.cfg.SAML.IdPEntityID},
		"idp_sso_url":          {h.cfg.SAML.IdPSSOURL},
		"entity_id":            {h.cfg.SAML.EntityID},
		"acs_url":              {h.cfg.SAML.ACSURL},
		"mfa_default_provider": {"totp"},
		"mfa_issuer":           {"SAMLGuard"},
		"otp_expiry":           {"5m"},
		"resend_cooldown":      {"60s"},
		"smtp_host":            {"localhost"},
		"smtp_port":            {"1025"},
	}
	reqSave2 := httptest.NewRequest(http.MethodPost, "/admin/settings", strings.NewReader(formWithoutBranding.Encode()))
	reqSave2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	wSave2 := httptest.NewRecorder()
	r.ServeHTTP(wSave2, reqSave2)
	if wSave2.Code != http.StatusOK || h.cfg.Branding.Resolve().AppName != "AcmeGuard" {
		t.Fatalf("expected branding profile preserved when omitted from POST, got %+v", h.cfg.Branding.Resolve())
	}

	// 5. Render admin settings & admin login and verify custom branding values appear
	wSettings := httptest.NewRecorder()
	r.ServeHTTP(wSettings, httptest.NewRequest(http.MethodGet, "/admin/settings", nil))
	settingsHTML := wSettings.Body.String()
	for _, want := range []string{"Custom Theme &amp; Branding Profiles", "AcmeGuard", "#2563EB", uploadedURL, "Enterprise SSO", `href="/admin/guide"`} {
		if !strings.Contains(settingsHTML, want) {
			t.Errorf("expected admin settings HTML to include %q", want)
		}
	}

	wLogin := httptest.NewRecorder()
	r.ServeHTTP(wLogin, httptest.NewRequest(http.MethodGet, "/admin/login", nil))
	loginHTML := wLogin.Body.String()
	for _, want := range []string{"AcmeGuard", "#2563EB", uploadedURL, "Enterprise SSO"} {
		if !strings.Contains(loginHTML, want) {
			t.Errorf("expected admin login HTML to reflect custom branding %q", want)
		}
	}

	// 6. Verify User Guide page (/admin/guide) renders with guide sections and custom branding
	r.GET("/admin/guide", h.HandleAdminGuideGet)
	wGuide := httptest.NewRecorder()
	r.ServeHTTP(wGuide, httptest.NewRequest(http.MethodGet, "/admin/guide", nil))
	if wGuide.Code != http.StatusOK {
		t.Fatalf("expected 200 GET /admin/guide, got %d", wGuide.Code)
	}
	guideHTML := wGuide.Body.String()
	for _, want := range []string{
		"User Guide",
		"Overview &amp; SAML 2.0 Proxy Architecture",
		"Custom Theme &amp; Branding Profiles",
		"AcmeGuard",
		"#2563EB",
		uploadedURL,
		`href="/admin/settings"`,
	} {
		if !strings.Contains(guideHTML, want) {
			t.Errorf("expected user guide HTML to include %q", want)
		}
	}
}

func TestAdminCustomerTenants_SaveAndRender(t *testing.T) {
	r, h, _ := setupTestAdminHandler(t)

	form := url.Values{
		"customer_tenants_submitted": {"1"},
		"customer_tenants_json": {`[
			{"name":"Acme Corp","sp_entity_id":"https://acme.example.com/sp","acs_url":"https://acme.example.com/acs","notes":"Primary customer","enabled":true},
			{"name":"Beta LLC","sp_entity_id":"https://beta.example.com/sp","acs_url":"https://beta.example.com/acs","enabled":false}
		]`},
		"idp_entity_id":        {h.cfg.SAML.IdPEntityID},
		"idp_sso_url":          {h.cfg.SAML.IdPSSOURL},
		"entity_id":            {h.cfg.SAML.EntityID},
		"acs_url":              {h.cfg.SAML.ACSURL},
		"mfa_default_provider": {"totp"},
		"mfa_issuer":           {"SAMLGuard"},
		"otp_expiry":           {"5m"},
		"resend_cooldown":      {"60s"},
		"smtp_host":            {"localhost"},
		"smtp_port":            {"1025"},
	}

	req := httptest.NewRequest(http.MethodPost, "/admin/settings", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on settings POST, got %d: %s", w.Code, w.Body.String())
	}
	if len(h.cfg.SAML.CustomerTenants) != 2 {
		t.Fatalf("expected 2 customer tenants in config, got %d", len(h.cfg.SAML.CustomerTenants))
	}
	if h.cfg.SAML.CustomerTenants[0].ID != "acme-corp" {
		t.Errorf("expected normalized id 'acme-corp', got %q", h.cfg.SAML.CustomerTenants[0].ID)
	}

	wGet := httptest.NewRecorder()
	r.ServeHTTP(wGet, httptest.NewRequest(http.MethodGet, "/admin/settings", nil))
	if wGet.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on settings GET, got %d", wGet.Code)
	}
	body := wGet.Body.String()
	for _, want := range []string{
		"2 Connected SP Environments",
		"Acme Corp",
		"https://acme.example.com/acs",
		"Beta LLC",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("expected settings HTML to contain %q", want)
		}
	}
}

func TestAdminAutoTLS_SaveAndValidation(t *testing.T) {
	r, h, _ := setupTestAdminHandler(t)

	// 1. Reject raw IP address for Let's Encrypt domain
	badForm := url.Values{
		"tls_submitted":        {"1"},
		"tls_enabled":          {"on"},
		"auto_tls_enabled":     {"on"},
		"auto_tls_domains_str": {"192.168.0.178"},
		"idp_entity_id":        {h.cfg.SAML.IdPEntityID},
		"idp_sso_url":          {h.cfg.SAML.IdPSSOURL},
		"entity_id":            {h.cfg.SAML.EntityID},
		"acs_url":              {h.cfg.SAML.ACSURL},
		"mfa_default_provider": {"totp"},
		"mfa_issuer":           {"SAMLGuard"},
		"otp_expiry":           {"5m"},
		"resend_cooldown":      {"60s"},
		"smtp_host":            {"localhost"},
		"smtp_port":            {"1025"},
	}
	reqBad := httptest.NewRequest(http.MethodPost, "/admin/settings", strings.NewReader(badForm.Encode()))
	reqBad.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	wBad := httptest.NewRecorder()
	r.ServeHTTP(wBad, reqBad)
	if !strings.Contains(wBad.Body.String(), "not an IP address") {
		t.Fatalf("expected IP rejection message, got: %s", wBad.Body.String())
	}

	// 2. Accept valid public DNS domain
	goodForm := url.Values{
		"tls_submitted":               {"1"},
		"tls_enabled":                 {"on"},
		"auto_tls_enabled":            {"on"},
		"auto_tls_domains_str":        {"sso.example.com"},
		"auto_tls_email":              {"admin@example.com"},
		"auto_tls_cache_dir":          {"certs/autocert"},
		"auto_tls_http_challenge_addr": {":80"},
		"idp_entity_id":               {h.cfg.SAML.IdPEntityID},
		"idp_sso_url":                 {h.cfg.SAML.IdPSSOURL},
		"entity_id":                   {h.cfg.SAML.EntityID},
		"acs_url":                     {h.cfg.SAML.ACSURL},
		"mfa_default_provider":        {"totp"},
		"mfa_issuer":                  {"SAMLGuard"},
		"otp_expiry":                  {"5m"},
		"resend_cooldown":             {"60s"},
		"smtp_host":                   {"localhost"},
		"smtp_port":                   {"1025"},
	}
	reqGood := httptest.NewRequest(http.MethodPost, "/admin/settings", strings.NewReader(goodForm.Encode()))
	reqGood.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	wGood := httptest.NewRecorder()
	r.ServeHTTP(wGood, reqGood)
	if wGood.Code != http.StatusOK || !strings.Contains(wGood.Body.String(), "Configuration updated successfully") {
		t.Fatalf("expected 200 OK on valid AutoTLS settings, got %d", wGood.Code)
	}
	if !h.cfg.TLS.Enabled || !h.cfg.TLS.AutoTLS.Enabled || len(h.cfg.TLS.AutoTLS.Domains) != 1 || h.cfg.TLS.AutoTLS.Domains[0] != "sso.example.com" {
		t.Fatalf("unexpected AutoTLS config state: %+v", h.cfg.TLS)
	}
}

func TestAdminDeploymentGuide_Render(t *testing.T) {
	r, h, _ := setupTestAdminHandler(t)
	r.GET("/admin/guide/deployment", h.HandleAdminDeploymentGuideGet)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/admin/guide/deployment", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 GET /admin/guide/deployment, got %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{
		"Webmin",
		"Ubuntu, Debian, RHEL",
		"Windows Server",
		"config.yaml",
		"samlguard-webmin.wbm.gz",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("expected deployment guide HTML to contain %q", want)
		}
	}
}

