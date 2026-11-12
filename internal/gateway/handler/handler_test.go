package handler

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crewjam/saml"
	"github.com/gin-gonic/gin"
	"github.com/hidayat-SE/samlguard/internal/config"
	fedmetadata "github.com/hidayat-SE/samlguard/internal/federation/metadata"
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
			EntityID:  "https://samlguard.example.com:8443",
			SSOURL:    "https://samlguard.example.com:8443/saml/sso",
			ACSURL:    "https://samlguard.example.com:8443/saml/acs",
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
	body := w.Body.String()
	for _, want := range []string{
		"/static/js/theme.js",
		"/assets/backgrounds/bg-login-dark.png",
		"/assets/backgrounds/bg-login-light.png",
		"Corporate Sign In",
		"Secure access to Schneider Electric IT Advisor",
		"Continue to Verification",
		"/static/img/schneider-electric.png",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("expected corporate login HTML to contain %q", want)
		}
	}
	if strings.Contains(body, "🛡️") {
		t.Errorf("expected corporate login HTML to use SVG shield instead of emoji")
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

	body := w.Body.String()
	if !strings.Contains(body, "IDPSSODescriptor") {
		t.Error("expected metadata to contain IDPSSODescriptor for ITA")
	}
	if !strings.Contains(body, "SPSSODescriptor") {
		t.Error("expected metadata to contain SPSSODescriptor for Entra ID")
	}
	if !strings.Contains(body, "KeyDescriptor") {
		t.Error("expected metadata to contain KeyDescriptor with signing certificate")
	}
}

func TestHandler_DualFederationMetadata_DedicatedRoles(t *testing.T) {
	p := &mockPipeline{}
	h, _ := setupTestHandler(t, p)

	r := gin.New()
	r.GET("/saml/metadata", h.HandleMetadata)
	r.GET("/saml/metadata/idp", h.HandleIdPMetadata)
	r.GET("/saml/metadata/sp", h.HandleSPMetadata)

	// 1. Verify Pure Downstream IdP Metadata (for Schneider Electric IT Advisor)
	t.Run("Pure Downstream IdP Metadata", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/saml/metadata/idp", nil)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", w.Code)
		}
		if ct := w.Header().Get("Content-Type"); ct != "application/samlmetadata+xml" {
			t.Errorf("expected application/samlmetadata+xml, got %s", ct)
		}

		body := w.Body.String()
		if !strings.Contains(body, "<md:IDPSSODescriptor") {
			t.Error("IdP metadata MUST contain IDPSSODescriptor")
		}
		if strings.Contains(body, "<md:SPSSODescriptor") {
			t.Error("IdP metadata MUST NOT contain SPSSODescriptor (role separation failure)")
		}
		if !strings.Contains(body, "HTTP-Redirect") || !strings.Contains(body, "HTTP-POST") {
			t.Error("IdP metadata must offer both HTTP-Redirect and HTTP-POST SSO bindings")
		}

		// Parse with independent SAML metadata parser (internal/federation/metadata)
		parser := &fedmetadata.Parser{}
		desc, err := parser.Parse([]byte(body))
		if err != nil {
			t.Fatalf("independent metadata parser failed to parse IdP metadata: %v", err)
		}
		if desc.EntityID != h.cfg.SAML.EntityID {
			t.Errorf("expected EntityID %q, got %q", h.cfg.SAML.EntityID, desc.EntityID)
		}
		if len(desc.SSOEndpoints) != 2 {
			t.Errorf("expected 2 SSO endpoints (Redirect & POST), got %d", len(desc.SSOEndpoints))
		}
		if len(desc.Certificates) == 0 {
			t.Error("expected at least 1 signing certificate in IdP metadata")
		}
	})

	// 2. Verify Pure Upstream SP Metadata (for Microsoft Entra ID / Keycloak)
	t.Run("Pure Upstream SP Metadata", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/saml/metadata/sp", nil)
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", w.Code)
		}
		if ct := w.Header().Get("Content-Type"); ct != "application/samlmetadata+xml" {
			t.Errorf("expected application/samlmetadata+xml, got %s", ct)
		}

		body := w.Body.String()
		if !strings.Contains(body, "<md:SPSSODescriptor") {
			t.Error("SP metadata MUST contain SPSSODescriptor")
		}
		if strings.Contains(body, "<md:IDPSSODescriptor") {
			t.Error("SP metadata MUST NOT contain IDPSSODescriptor (role separation failure)")
		}
		if !strings.Contains(body, "<md:AssertionConsumerService") {
			t.Error("SP metadata MUST contain AssertionConsumerService")
		}

		// Parse with standard crewjam/saml parser
		var ed saml.EntityDescriptor
		if err := xml.Unmarshal([]byte(body), &ed); err != nil {
			t.Fatalf("crewjam XML unmarshal failed for SP metadata: %v", err)
		}
		if ed.EntityID != h.cfg.SAML.EntityID {
			t.Errorf("expected EntityID %q, got %q", h.cfg.SAML.EntityID, ed.EntityID)
		}
		if len(ed.SPSSODescriptors) != 1 {
			t.Fatalf("expected exactly 1 SPSSODescriptor, got %d", len(ed.SPSSODescriptors))
		}
		if len(ed.IDPSSODescriptors) != 0 {
			t.Errorf("expected 0 IDPSSODescriptors in pure SP metadata, got %d", len(ed.IDPSSODescriptors))
		}
		spDesc := ed.SPSSODescriptors[0]
		if len(spDesc.AssertionConsumerServices) == 0 {
			t.Error("expected at least 1 AssertionConsumerService in SP metadata")
		}
		if spDesc.AssertionConsumerServices[0].Binding != "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" {
			t.Errorf("expected HTTP-POST ACS binding, got %s", spDesc.AssertionConsumerServices[0].Binding)
		}
	})

	// 3. Verify Query Parameter Role Dispatch (?role=idp and ?role=sp)
	t.Run("Query Parameter Role Dispatch", func(t *testing.T) {
		// Test ?role=idp
		wIdP := httptest.NewRecorder()
		reqIdP := httptest.NewRequest(http.MethodGet, "/saml/metadata?role=idp", nil)
		r.ServeHTTP(wIdP, reqIdP)
		if !strings.Contains(wIdP.Body.String(), "<md:IDPSSODescriptor") || strings.Contains(wIdP.Body.String(), "<md:SPSSODescriptor") {
			t.Error("expected ?role=idp to serve pure IdP metadata without SPSSODescriptor")
		}

		// Test ?role=sp
		wSP := httptest.NewRecorder()
		reqSP := httptest.NewRequest(http.MethodGet, "/saml/metadata?role=sp", nil)
		r.ServeHTTP(wSP, reqSP)
		if !strings.Contains(wSP.Body.String(), "<md:SPSSODescriptor") || strings.Contains(wSP.Body.String(), "<md:IDPSSODescriptor") {
			t.Error("expected ?role=sp to serve pure SP metadata without IDPSSODescriptor")
		}
	})
}

func buildSignedUpstreamResponse(t *testing.T, respGen *gateway.ResponseGenerator, issuer, recipient, inResponseTo string) string {
	t.Helper()
	req := gateway.SAMLResponseRequest{
		InResponseTo:        inResponseTo,
		Destination:         recipient,
		Audience:            "https://samlguard.example.com:8443",
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

func TestHandler_EmbeddedTemplateFallbackOutsideRepo(t *testing.T) {
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}

	absCert, _ := filepath.Abs("../../../cert/saml-signing.crt")
	absKey, _ := filepath.Abs("../../../cert/saml-signing.key")

	emptyDir := t.TempDir()
	if err := os.Chdir(emptyDir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer os.Chdir(origDir)

	cfg := &config.Config{
		SAML: config.SAMLConfig{
			EntityID:  "https://samlguard.example.com:8443",
			SSOURL:    "https://samlguard.example.com:8443/saml/sso",
			ACSURL:    "https://samlguard.example.com:8443/saml/acs",
			IdPSSOURL: "https://mock-idp.samlguard.local/sso",
			CertFile:  absCert,
			KeyFile:   absKey,
		},
	}
	dbPath := filepath.Join(emptyDir, "test_handler.db")
	storage, err := mfa.NewSQLiteStorage(dbPath)
	if err != nil {
		t.Fatalf("setup storage: %v", err)
	}
	defer storage.Close()

	mfaSvc := mfa.NewService(storage, nil, cfg, zap.NewNop())
	respGen, err := gateway.NewResponseGenerator(cfg)
	if err != nil {
		t.Fatalf("setup respGen: %v", err)
	}
	p := &mockPipeline{}
	h, err := NewSAMLHandler(p, mfaSvc, respGen, cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("setup handler: %v", err)
	}

	if h.templates == nil {
		t.Fatal("expected handler to load embedded template when working directory lacks external web/ templates")
	}
}

func TestNewSAMLHandler_IdPCertificateRolloverBundle(t *testing.T) {
	tempDir := t.TempDir()
	certBundlePath := filepath.Join(tempDir, "idp-bundle.crt")

	// Read existing signing cert to duplicate into a 2-cert bundle
	singleCert, err := os.ReadFile("../../../cert/saml-signing.crt")
	if err != nil {
		t.Fatalf("failed to read signing cert: %v", err)
	}

	bundleContent := append(singleCert, []byte("\n")...)
	bundleContent = append(bundleContent, singleCert...)
	if err := os.WriteFile(certBundlePath, bundleContent, 0600); err != nil {
		t.Fatalf("failed to write bundle: %v", err)
	}

	absKey, _ := filepath.Abs("../../../cert/saml-signing.key")
	cfg := &config.Config{
		SAML: config.SAMLConfig{
			EntityID:    "https://samlguard.example.com:8443",
			SSOURL:      "https://samlguard.example.com:8443/saml/sso",
			ACSURL:      "https://samlguard.example.com:8443/saml/acs",
			IdPSSOURL:   "https://idp.example.com/sso",
			IdPEntityID: "https://idp.example.com",
			IdPCertFile: certBundlePath,
			CertFile:    certBundlePath,
			KeyFile:     absKey,
		},
	}
	dbPath := filepath.Join(tempDir, "bundle_test.db")
	storage, err := mfa.NewSQLiteStorage(dbPath)
	if err != nil {
		t.Fatalf("setup storage: %v", err)
	}
	defer storage.Close()

	mfaSvc := mfa.NewService(storage, nil, cfg, zap.NewNop())
	respGen, err := gateway.NewResponseGenerator(cfg)
	if err != nil {
		t.Fatalf("setup respGen: %v", err)
	}

	p := &mockPipeline{}
	h, err := NewSAMLHandler(p, mfaSvc, respGen, cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("NewSAMLHandler failed: %v", err)
	}

	if h.idpCertStore == nil {
		t.Fatal("expected idpCertStore to be initialized")
	}
	if len(h.idpCertStore.Roots) != 2 {
		t.Fatalf("expected 2 certificates in idpCertStore.Roots for rollover bundle, got: %d", len(h.idpCertStore.Roots))
	}
}

func TestValidateUpstreamSAMLResponse_HardenedChecks(t *testing.T) {
	p := &mockPipeline{}
	h, cfg := setupTestHandler(t, p)
	cfg.SAML.IdPEntityID = "https://trusted-idp.example.com"

	// 1. First valid response succeeds; replaying the exact same Assertion ID is blocked
	b64 := buildSignedUpstreamResponse(t, h.responseGen, "https://trusted-idp.example.com", cfg.SAML.ACSURL, "outbound-replay-1")
	if _, err := h.validateUpstreamSAMLResponse(b64, "outbound-replay-1"); err != nil {
		t.Fatalf("expected first assertion validation to succeed, got: %v", err)
	}
	if _, err := h.validateUpstreamSAMLResponse(b64, "outbound-replay-1"); err == nil || !strings.Contains(err.Error(), "replay detected") {
		t.Fatalf("expected SAML assertion replay error on second submission, got: %v", err)
	}

	// 2. Spoofed Destination containing "/acs" on a different host must be rejected
	resSpoofDest, err := h.responseGen.GenerateResponse(gateway.SAMLResponseRequest{
		InResponseTo:  "outbound-dest-1",
		Destination:   "https://evil.attacker.example/acs",
		Audience:      cfg.SAML.EntityID,
		Issuer:        "https://trusted-idp.example.com",
		SubjectNameID: "alice",
		Email:         "alice@example.com",
	})
	if err != nil {
		t.Fatalf("generate spoofed destination response: %v", err)
	}
	// Replace SubjectConfirmationData Recipient so it passes recipient check and hits Destination check
	spoofDestB64 := b64WithModifiedDestination(t, resSpoofDest.PostFormHTML, h, "https://evil.attacker.example/acs", cfg.SAML.ACSURL)
	if _, err := h.validateUpstreamSAMLResponse(spoofDestB64, "outbound-dest-1"); err == nil || !strings.Contains(err.Error(), "destination mismatch") {
		t.Fatalf("expected destination mismatch for https://evil.attacker.example/acs, got: %v", err)
	}

	// 3. CorrelationStore respects maxSessions cap
	store := NewCorrelationStore(5 * time.Minute)
	store.maxSessions = 2
	if _, err := store.Create(&AuthSessionState{OutboundRequestID: "1"}); err != nil {
		t.Fatalf("create 1: %v", err)
	}
	if _, err := store.Create(&AuthSessionState{OutboundRequestID: "2"}); err != nil {
		t.Fatalf("create 2: %v", err)
	}
	if _, err := store.Create(&AuthSessionState{OutboundRequestID: "3"}); !errors.Is(err, ErrCorrelationStoreFull) {
		t.Fatalf("expected ErrCorrelationStoreFull when capacity reached, got: %v", err)
	}
}

func b64WithModifiedDestination(t *testing.T, postFormHTML string, h *SAMLHandler, dest, recipient string) string {
	t.Helper()
	res, err := h.responseGen.GenerateResponse(gateway.SAMLResponseRequest{
		InResponseTo:  "outbound-dest-1",
		Destination:   recipient,
		Audience:      h.cfg.SAML.EntityID,
		Issuer:        "https://trusted-idp.example.com",
		SubjectNameID: "alice",
		Email:         "alice@example.com",
	})
	if err != nil {
		t.Fatalf("generate base response: %v", err)
	}
	// Sign Response has Signature inside Assertion, so Response Destination can be edited for testing Destination check cleanly
	_ = postFormHTML
	rawXML, decErr := base64.StdEncoding.DecodeString(res.SAMLResponse)
	if decErr != nil {
		t.Fatalf("decode SAMLResponse: %v", decErr)
	}
	xmlStr := strings.Replace(string(rawXML), `Destination="`+recipient+`"`, `Destination="`+dest+`"`, 1)
	return base64.StdEncoding.EncodeToString([]byte(xmlStr))
}

func TestNewSAMLHandler_FiltersExpiredIdPCertificate(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}

	now := time.Now().UTC()
	makeCertPEM := func(notBefore, notAfter time.Time, serial int64) []byte {
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: "idp.example.com"},
			NotBefore:    notBefore,
			NotAfter:     notAfter,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			t.Fatalf("create certificate: %v", err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	}

	expiredPEM := makeCertPEM(now.Add(-48*time.Hour), now.Add(-24*time.Hour), 1001)
	validPEM := makeCertPEM(now.Add(-1*time.Hour), now.Add(365*24*time.Hour), 1002)

	tmpDir := t.TempDir()
	expiredOnlyPath := filepath.Join(tmpDir, "expired-idp.crt")
	if err := os.WriteFile(expiredOnlyPath, expiredPEM, 0o600); err != nil {
		t.Fatalf("write expired cert: %v", err)
	}

	cfg := &config.Config{
		Env: "development",
		SAML: config.SAMLConfig{
			IdPCertFile: expiredOnlyPath,
		},
	}
	hExpired, err := NewSAMLHandler(&mockPipeline{}, nil, nil, cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("NewSAMLHandler failed: %v", err)
	}
	if hExpired.idpCertStore != nil {
		t.Fatalf("expected expired-only IdP certificate store to be nil, got %d roots", len(hExpired.idpCertStore.Roots))
	}

	bundlePath := filepath.Join(tmpDir, "bundle-idp.crt")
	if err := os.WriteFile(bundlePath, append(expiredPEM, validPEM...), 0o600); err != nil {
		t.Fatalf("write bundle cert: %v", err)
	}
	cfg.SAML.IdPCertFile = bundlePath
	hBundle, err := NewSAMLHandler(&mockPipeline{}, nil, nil, cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("NewSAMLHandler bundle failed: %v", err)
	}
	if hBundle.idpCertStore == nil || len(hBundle.idpCertStore.Roots) != 1 {
		t.Fatalf("expected exactly 1 non-expired root certificate, got %+v", hBundle.idpCertStore)
	}
	if hBundle.idpCertStore.Roots[0].SerialNumber.Int64() != 1002 {
		t.Fatalf("expected valid cert serial 1002 to remain, got %v", hBundle.idpCertStore.Roots[0].SerialNumber)
	}
}

func TestMFA_MultiOTPAndProviderEnforcement(t *testing.T) {
	h, cfg := setupTestHandler(t, &mockPipeline{})
	h.mfaService.UpdateSMTPSender(mfa.NewSMTPSender("localhost", 1025, "", "", "noreply@example.com", "SAMLGuard", "none", zap.NewNop()))
	cfg.MFA.EnabledProviders = []string{"email"}
	cfg.MFA.DefaultProvider = "email"

	state := &AuthSessionState{
		SubjectNameID:   "alice",
		UserIdentityKey: "alice",
		UserEmail:       "alice@example.com",
	}
	sessionID, err := h.correlationStore.Create(state)
	if err != nil {
		t.Fatalf("create correlation session: %v", err)
	}
	csrfToken := state.CSRFToken

	r := gin.New()
	r.GET("/saml/acs", h.HandleACSGet)
	r.POST("/mfa/verify", h.HandleMFAVerify)
	r.POST("/mfa/resend", h.HandleMFAResend)
	r.POST("/mfa/re-enroll", h.HandleMFAReEnroll)

	// 1. Email-OTP-only mode: GET /saml/acs?method=totp resolves to Email OTP and hides Authenticator tab
	wACS := httptest.NewRecorder()
	reqACS := httptest.NewRequest(http.MethodGet, "/saml/acs?session_id="+sessionID+"&method=totp", nil)
	r.ServeHTTP(wACS, reqACS)
	if wACS.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from GET /saml/acs, got %d", wACS.Code)
	}
	bodyEmailOnly := wACS.Body.String()
	if !strings.Contains(bodyEmailOnly, "Email OTP") {
		t.Errorf("expected Email OTP tab when email is enabled")
	}
	if strings.Contains(bodyEmailOnly, "Authenticator App") {
		t.Errorf("expected Authenticator App tab to be hidden when totp is disabled")
	}

	// 2. Disabled TOTP verify & re-enroll must be rejected with 403 Forbidden
	verifyTotpForm := url.Values{
		"session_id": {sessionID},
		"csrf_token": {csrfToken},
		"method":     {"totp"},
		"code":       {"000000"},
	}
	wVerifyTotp := httptest.NewRecorder()
	reqVerifyTotp := httptest.NewRequest(http.MethodPost, "/mfa/verify", strings.NewReader(verifyTotpForm.Encode()))
	reqVerifyTotp.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ServeHTTP(wVerifyTotp, reqVerifyTotp)
	if wVerifyTotp.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden verifying disabled totp method, got %d", wVerifyTotp.Code)
	}

	reEnrollForm := url.Values{
		"session_id": {sessionID},
		"csrf_token": {csrfToken},
	}
	wReEnroll := httptest.NewRecorder()
	reqReEnroll := httptest.NewRequest(http.MethodPost, "/mfa/re-enroll", strings.NewReader(reEnrollForm.Encode()))
	reqReEnroll.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ServeHTTP(wReEnroll, reqReEnroll)
	if wReEnroll.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden re-enrolling totp while totp disabled, got %d", wReEnroll.Code)
	}

	// 3. Multi-OTP mode (both totp and email active): customer can see and switch between both tabs
	cfg.MFA.EnabledProviders = []string{"totp", "email"}
	cfg.MFA.DefaultProvider = "totp"
	wMulti := httptest.NewRecorder()
	reqMulti := httptest.NewRequest(http.MethodGet, "/saml/acs?session_id="+sessionID, nil)
	r.ServeHTTP(wMulti, reqMulti)
	if wMulti.Code != http.StatusOK {
		t.Fatalf("expected 200 OK in multi-OTP mode, got %d", wMulti.Code)
	}
	bodyMulti := wMulti.Body.String()
	if !strings.Contains(bodyMulti, "Authenticator App") || !strings.Contains(bodyMulti, "Email OTP") {
		t.Errorf("expected both Authenticator App and Email OTP tabs rendered when multi-OTP enabled")
	}

	// 4. TOTP-only mode: /mfa/resend must return 403 Forbidden
	cfg.MFA.EnabledProviders = []string{"totp"}
	resendForm := url.Values{
		"session_id": {sessionID},
		"csrf_token": {csrfToken},
	}
	wResendDisabled := httptest.NewRecorder()
	reqResendDisabled := httptest.NewRequest(http.MethodPost, "/mfa/resend", strings.NewReader(resendForm.Encode()))
	reqResendDisabled.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ServeHTTP(wResendDisabled, reqResendDisabled)
	if wResendDisabled.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for /mfa/resend when email OTP is disabled, got %d", wResendDisabled.Code)
	}
}

func TestSAMLHandler_ReloadIDPCertStore(t *testing.T) {
	cfg := &config.Config{Env: "development"}
	h, err := NewSAMLHandler(&mockPipeline{}, nil, nil, cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("NewSAMLHandler failed: %v", err)
	}
	if h.idpCertStore != nil {
		t.Fatalf("expected nil idpCertStore initially")
	}

	certPath, _ := filepath.Abs("../../../cert/saml-signing.crt")
	cfg.SAML.IdPCertFile = certPath
	h.ReloadIDPCertStore()

	h.idpCertMu.RLock()
	store := h.idpCertStore
	h.idpCertMu.RUnlock()
	if store == nil || len(store.Roots) == 0 {
		t.Fatalf("expected ReloadIDPCertStore to load root certificate(s)")
	}
}

func TestFrontEnd_MultiIdPChooserAndMFAMethodList(t *testing.T) {
	h, cfg := setupTestHandler(t, &mockPipeline{})
	cfg.SAML.ActiveIdP = "simulator"
	cfg.SAML.EnabledIdPs = []string{"simulator", "entra"}
	cfg.SAML.IdPProfiles = map[string]config.UpstreamIdPProfile{
		"simulator": {
			EntityID: "https://mock-idp.samlguard.local",
			SSOURL:   "https://localhost:8443/mock-idp-login",
		},
		"entra": {
			EntityID: "https://sts.windows.net/tenant-abc/",
			SSOURL:   "https://login.microsoftonline.com/tenant-abc/saml2",
		},
	}
	cfg.MFA.EnabledProviders = []string{"totp", "email"}
	cfg.MFA.DefaultProvider = "select"

	r := gin.New()
	r.GET("/saml/sso", h.HandleSSO)
	r.GET("/saml/acs", h.HandleACSGet)

	// 1. /saml/sso shows "Select a sign-in method" list with both enabled upstream IdPs
	wChooser := httptest.NewRecorder()
	reqChooser := httptest.NewRequest(http.MethodGet, "/saml/sso", nil)
	r.ServeHTTP(wChooser, reqChooser)
	if wChooser.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for multi-IdP chooser, got %d", wChooser.Code)
	}
	chooserBody := wChooser.Body.String()
	for _, want := range []string{"Select a sign-in method", "Corporate Account (Local Sign-In)", "Microsoft Entra ID", "idp=simulator", "idp=entra"} {
		if !strings.Contains(chooserBody, want) {
			t.Errorf("expected chooser HTML to contain %q", want)
		}
	}

	// Extract session_id from chooser link and click Simulator -> shows Corporate Sign In with back link
	var sessionID string
	for _, cookie := range wChooser.Result().Cookies() {
		if cookie.Name == "samlguard_auth_state" {
			sessionID = cookie.Value
		}
	}
	if sessionID == "" {
		t.Fatalf("expected samlguard_auth_state cookie from /saml/sso chooser")
	}

	wSim := httptest.NewRecorder()
	reqSim := httptest.NewRequest(http.MethodGet, "/saml/sso?session_id="+sessionID+"&idp=simulator", nil)
	r.ServeHTTP(wSim, reqSim)
	if wSim.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for simulator login form, got %d", wSim.Code)
	}
	simBody := wSim.Body.String()
	if !strings.Contains(simBody, "Corporate Sign In") || !strings.Contains(simBody, "&view=providers") {
		t.Errorf("expected Corporate Sign In form with back-to-providers link when multiple IdPs are enabled")
	}

	// 2. With MFA default_provider="select", /saml/acs renders "Select a method to verify your identity" list
	state, err := h.correlationStore.Get(sessionID)
	if err != nil {
		t.Fatalf("get session state: %v", err)
	}
	state.UserIdentityKey = "https://mock-idp.samlguard.local|apc"
	state.UserEmail = "apc@example.com"
	_ = h.correlationStore.Update(sessionID, state)

	wSelect := httptest.NewRecorder()
	reqSelect := httptest.NewRequest(http.MethodGet, "/saml/acs?session_id="+sessionID, nil)
	r.ServeHTTP(wSelect, reqSelect)
	if wSelect.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for MFA method selection view, got %d", wSelect.Code)
	}
	selectBody := wSelect.Body.String()
	for _, want := range []string{"Select a method to verify your identity", "Authenticator App", "Email", "?method=totp&amp;session_id=" + sessionID, "?method=email&amp;session_id=" + sessionID} {
		if !strings.Contains(selectBody, want) {
			t.Errorf("expected MFA select HTML to contain %q", want)
		}
	}
	if strings.Contains(selectBody, `id="mfa-form"`) {
		t.Errorf("did not expect direct code entry form while on method selection screen")
	}

	// 3. Selecting ?method=totp renders verification form, back chevron (?view=methods), and "Or verify another way"
	wTotp := httptest.NewRecorder()
	reqTotp := httptest.NewRequest(http.MethodGet, "/saml/acs?session_id="+sessionID+"&method=totp", nil)
	r.ServeHTTP(wTotp, reqTotp)
	if wTotp.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for ?method=totp, got %d", wTotp.Code)
	}
	totpBody := wTotp.Body.String()
	for _, want := range []string{"Multi-Factor Verification", "?view=methods&session_id=" + sessionID, "Or verify another way", `id="mfa-form"`} {
		if !strings.Contains(totpBody, want) {
			t.Errorf("expected totp challenge HTML to contain %q", want)
		}
	}
}
