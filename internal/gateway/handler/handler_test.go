package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/hidayat-SE/samlguard/internal/config"
	"github.com/hidayat-SE/samlguard/internal/gateway"
	"github.com/hidayat-SE/samlguard/internal/gateway/model"
	"github.com/hidayat-SE/samlguard/internal/gateway/pipeline"
	"github.com/hidayat-SE/samlguard/internal/mfa"
	"go.uber.org/zap"
)

func init() {
	gin.SetMode(gin.TestMode)
}

type mockPipeline struct {
	executeFunc func(ctx context.Context, input interface{}) (*model.AuthenticationContext, error)
}

func (m *mockPipeline) Execute(ctx context.Context, input interface{}) (*model.AuthenticationContext, error) {
	if m.executeFunc != nil {
		return m.executeFunc(ctx, input)
	}
	return &model.AuthenticationContext{
		RequestID: "test-req-123",
		Issuer:    "https://idp.example.com",
		ValidationResult: model.ValidationResult{
			IsValid: true,
		},
	}, nil
}

func (m *mockPipeline) Validate() error {
	return nil
}

func setupTestHandler(t *testing.T, p pipeline.AuthnPipeline) (*SAMLHandler, *config.Config) {
	cfg := &config.Config{
		SAML: config.SAMLConfig{
			EntityID:  "https://192.168.0.178:18080",
			SSOURL:    "https://192.168.0.178:18080/saml/sso",
			ACSURL:    "https://192.168.0.178:18080/saml/acs",
			IdPSSOURL: "https://mock-idp.samlguard.local/sso",
			CertFile:  "../../../cert/saml-signing.crt",
			KeyFile:   "../../../cert/saml-signing.key",
		},
	}
	dbPath := filepath.Join(t.TempDir(), "test_handler.db")
	storage, err := mfa.NewSQLiteStorage(dbPath)
	if err != nil {
		t.Fatalf("setup storage: %v", err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	mfaSvc := mfa.NewService(storage, nil, cfg, zap.NewNop())
	respGen, err := gateway.NewResponseGenerator(cfg)
	if err != nil {
		t.Fatalf("setup respGen: %v", err)
	}
	h, err := NewSAMLHandler(p, mfaSvc, respGen, cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("setup handler: %v", err)
	}
	return h, cfg
}

func TestNewSAMLHandler_NilPipeline(t *testing.T) {
	cfg := &config.Config{}
	_, err := NewSAMLHandler(nil, nil, nil, cfg, zap.NewNop())
	if err == nil {
		t.Fatal("expected error when constructing SAMLHandler with nil pipeline, got nil")
	}
}

func TestHandler_HandleSSO_Success(t *testing.T) {
	p := &mockPipeline{}
	h, _ := setupTestHandler(t, p)

	r := gin.New()
	r.GET("/saml/sso", h.HandleSSO)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/saml/sso?request_id=ita-123&RelayState=state-abc", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200 for mock IdP login, got %d", w.Code)
	}
}

func TestHandler_HandleSSO_PipelineError(t *testing.T) {
	p := &mockPipeline{
		executeFunc: func(ctx context.Context, input interface{}) (*model.AuthenticationContext, error) {
			return nil, errors.New("pipeline validation failed: malformed XML")
		},
	}
	h, _ := setupTestHandler(t, p)

	r := gin.New()
	r.GET("/saml/sso", h.HandleSSO)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/saml/sso?request_id=bad", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400 Bad Request, got %d", w.Code)
	}
}

func TestHandler_HandleMetadata(t *testing.T) {
	p := &mockPipeline{}
	h, _ := setupTestHandler(t, p)

	r := gin.New()
	r.GET("/saml/metadata", h.HandleMetadata)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/saml/metadata", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}

func buildSignedUpstreamResponse(t *testing.T, respGen *gateway.ResponseGenerator, issuer, recipient, inResponseTo string) string {
	t.Helper()
	req := gateway.SAMLResponseRequest{
		InResponseTo:        inResponseTo,
		Destination:         recipient,
		Audience:            "https://192.168.0.178:18080",
		Issuer:              issuer,
		SubjectNameID:       "test-user",
		SubjectNameIDFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
		Email:               "test@example.com",
		DisplayName:         "Test User",
		RawGroups:           []string{"ita-admins"},
	}
	res, err := respGen.GenerateResponse(req)
	if err != nil {
		t.Fatalf("failed to generate response: %v", err)
	}
	return res.SAMLResponse
}

func TestValidateUpstreamSAMLResponse_IssuerValidation(t *testing.T) {
	p := &mockPipeline{}
	h, cfg := setupTestHandler(t, p)
	cfg.SAML.IdPEntityID = "https://trusted-idp.example.com"

	// 1. Valid Issuer
	validB64 := buildSignedUpstreamResponse(t, h.responseGen, "https://trusted-idp.example.com", cfg.SAML.ACSURL, "outbound-1")
	claims, err := h.validateUpstreamSAMLResponse(validB64, "outbound-1")
	if err != nil {
		t.Fatalf("expected valid issuer to pass, got error: %v", err)
	}
	if claims.SubjectNameID != "test-user" {
		t.Errorf("expected subject test-user, got %s", claims.SubjectNameID)
	}

	// 2. Mismatched Issuer
	mismatchedB64 := buildSignedUpstreamResponse(t, h.responseGen, "https://evil-idp.attacker.com", cfg.SAML.ACSURL, "outbound-1")
	_, err = h.validateUpstreamSAMLResponse(mismatchedB64, "outbound-1")
	if err == nil || !strings.Contains(err.Error(), "Issuer mismatch") {
		t.Fatalf("expected Issuer mismatch error, got: %v", err)
	}
}

func TestValidateUpstreamSAMLResponse_RecipientValidation(t *testing.T) {
	p := &mockPipeline{}
	h, cfg := setupTestHandler(t, p)
	cfg.SAML.IdPEntityID = "https://trusted-idp.example.com"

	// 1. Valid Recipient
	validB64 := buildSignedUpstreamResponse(t, h.responseGen, "https://trusted-idp.example.com", cfg.SAML.ACSURL, "outbound-2")
	claims, err := h.validateUpstreamSAMLResponse(validB64, "outbound-2")
	if err != nil {
		t.Fatalf("expected valid recipient to pass, got error: %v", err)
	}
	if claims.Email != "test@example.com" {
		t.Errorf("expected email test@example.com, got %s", claims.Email)
	}

	// 2. Mismatched Recipient (exact matching, reject different endpoint)
	mismatchedB64 := buildSignedUpstreamResponse(t, h.responseGen, "https://trusted-idp.example.com", "https://attacker-sp.example.com/callback", "outbound-2")
	_, err = h.validateUpstreamSAMLResponse(mismatchedB64, "outbound-2")
	if err == nil || !strings.Contains(err.Error(), "Recipient mismatch") {
		t.Fatalf("expected Recipient mismatch error, got: %v", err)
	}

	// 3. Substring match rejection (must not accept prefix or substring)
	substringB64 := buildSignedUpstreamResponse(t, h.responseGen, "https://trusted-idp.example.com", cfg.SAML.ACSURL+"/extra/path", "outbound-2")
	_, err = h.validateUpstreamSAMLResponse(substringB64, "outbound-2")
	if err == nil || !strings.Contains(err.Error(), "Recipient mismatch") {
		t.Fatalf("expected Recipient mismatch error for substring, got: %v", err)
	}
}

func TestDetermineAuthnContextClassRef(t *testing.T) {
	const (
		TimeSyncToken = "urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken"
		Unspecified   = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified"
	)

	// Case 1: TOTP with empty global configuration
	if got := DetermineAuthnContextClassRef("totp", ""); got != TimeSyncToken {
		t.Errorf("expected TOTP with empty config to produce %s, got %s", TimeSyncToken, got)
	}

	// Case 2: Email OTP with empty global configuration
	if got := DetermineAuthnContextClassRef("email", ""); got != Unspecified {
		t.Errorf("expected Email OTP with empty config to produce %s, got %s", Unspecified, got)
	}

	// Case 3: TOTP with global TimeSyncToken
	if got := DetermineAuthnContextClassRef("totp", TimeSyncToken); got != TimeSyncToken {
		t.Errorf("expected TOTP with global TimeSyncToken to produce %s, got %s", TimeSyncToken, got)
	}

	// Case 4: Email OTP with global TimeSyncToken -> MUST NOT produce TimeSyncToken!
	if got := DetermineAuthnContextClassRef("email", TimeSyncToken); got != Unspecified {
		t.Errorf("SECURITY ERROR: Email OTP inherited global TimeSyncToken! Expected %s, got %s", Unspecified, got)
	}

	// Case 5: Verify Email OTP never produces TimeSyncToken under any variation
	variations := []string{
		TimeSyncToken,
		"urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken",
	}
	for _, v := range variations {
		if got := DetermineAuthnContextClassRef("email", v); got == TimeSyncToken {
			t.Fatalf("SECURITY VIOLATION: Email OTP produced TimeSyncToken for input %s", v)
		}
	}
}

func TestValidateUpstreamSAMLResponse_Production_ProhibitsMockFallback(t *testing.T) {
	p := &mockPipeline{}
	h, cfg := setupTestHandler(t, p)
	cfg.Env = "production"

	// 1. In production, empty IdPEntityID must reject mock IdP fallback
	cfg.SAML.IdPEntityID = ""
	cfg.SAML.ACSURL = "https://samlguard.prod.example/saml/acs"
	b64 := buildSignedUpstreamResponse(t, h.responseGen, "https://mock-idp.samlguard.local", cfg.SAML.ACSURL, "outbound-prod-1")
	_, err := h.validateUpstreamSAMLResponse(b64, "outbound-prod-1")
	if err == nil || !strings.Contains(err.Error(), "mock IdP issuer fallback is forbidden") {
		t.Fatalf("expected error prohibiting mock IdP fallback in production, got: %v", err)
	}

	// 2. In production, empty ACSURL must reject /saml/acs fallback
	cfg.SAML.IdPEntityID = "https://real-idp.prod.example"
	cfg.SAML.ACSURL = ""
	b64 = buildSignedUpstreamResponse(t, h.responseGen, "https://real-idp.prod.example", "/saml/acs", "outbound-prod-2")
	_, err = h.validateUpstreamSAMLResponse(b64, "outbound-prod-2")
	if err == nil || !strings.Contains(err.Error(), "/saml/acs fallback is forbidden") {
		t.Fatalf("expected error prohibiting /saml/acs fallback in production, got: %v", err)
	}

	// 3. In production, an assertion signed with mock IdP issuer is rejected when real IdP is configured
	cfg.SAML.IdPEntityID = "https://real-idp.prod.example"
	cfg.SAML.ACSURL = "https://samlguard.prod.example/saml/acs"
	b64 = buildSignedUpstreamResponse(t, h.responseGen, "https://mock-idp.samlguard.local", cfg.SAML.ACSURL, "outbound-prod-3")
	_, err = h.validateUpstreamSAMLResponse(b64, "outbound-prod-3")
	if err == nil || !strings.Contains(err.Error(), "Issuer mismatch") {
		t.Fatalf("expected Issuer mismatch when mock IdP issuer is received in production, got: %v", err)
	}
}

func TestValidateUpstreamSAMLResponse_DevMode_AllowsMockFallback(t *testing.T) {
	p := &mockPipeline{}
	h, cfg := setupTestHandler(t, p)
	cfg.Env = "development"
	cfg.SAML.IdPEntityID = ""
	cfg.SAML.ACSURL = ""

	b64 := buildSignedUpstreamResponse(t, h.responseGen, "https://mock-idp.samlguard.local", "/saml/acs", "outbound-dev-1")
	claims, err := h.validateUpstreamSAMLResponse(b64, "outbound-dev-1")
	if err != nil {
		t.Fatalf("expected mock fallback to be allowed in development mode, got error: %v", err)
	}
	if claims.SubjectNameID != "test-user" {
		t.Errorf("expected subject test-user, got %s", claims.SubjectNameID)
	}
}
