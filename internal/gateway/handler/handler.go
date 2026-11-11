package handler

import (
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"html"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/beevik/etree"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	goxmldsig "github.com/russellhaering/goxmldsig"
	"github.com/hidayat-SE/samlguard/internal/config"
	fedmodel "github.com/hidayat-SE/samlguard/internal/federation/model"
	"github.com/hidayat-SE/samlguard/internal/gateway"
	"github.com/hidayat-SE/samlguard/internal/gateway/pipeline"
	"github.com/hidayat-SE/samlguard/internal/mfa"
	"github.com/hidayat-SE/samlguard/pkg/replay"
	"github.com/hidayat-SE/samlguard/pkg/response"
	"github.com/hidayat-SE/samlguard/web"
	"go.uber.org/zap"
)

type SAMLHandler struct {
	pipeline             pipeline.AuthnPipeline
	mfaService           *mfa.Service
	responseGen          *gateway.ResponseGenerator
	correlationStore     *CorrelationStore
	idpCertStore         *goxmldsig.MemoryX509CertificateStore
	cfg                  *config.Config
	templates            *template.Template
	corporateLoginTmpl   *template.Template
	logger               *zap.Logger
	adminSecretMu        sync.Mutex
	ephemeralAdminSecret []byte
	assertionReplayMu    sync.Mutex
	assertionReplay      *replay.MemoryReplayDetector
}

type CorporateLoginViewModel struct {
	SessionID         string
	OutboundID        string
	SAMLResponseInput template.HTML
	Username          string
	ErrorMessage      string
}

type ChallengeViewModel struct {
	SessionID          string
	CSRFToken          string
	Email              string
	MaskedEmail        string
	Method             string // "totp", "email"
	EnrollmentRequired bool
	SecretKey          string
	QRCodeDataURI      template.URL
	Message            string
	ErrorMessage       string
	ResendCooldown     int
}

type UpstreamClaims struct {
	SubjectNameID       string
	SubjectNameIDFormat string
	Email               string
	DisplayName         string
	Groups              []string
}

func NewSAMLHandler(
	p pipeline.AuthnPipeline,
	mfaSvc *mfa.Service,
	respGen *gateway.ResponseGenerator,
	cfg *config.Config,
	log *zap.Logger,
) (*SAMLHandler, error) {
	if p == nil {
		return nil, errors.New("pipeline is required and cannot be nil")
	}

	var tmpl *template.Template
	// 1. Try external template file if present (allows operator customization)
	templatePath := filepath.Join("web", "templates", "mfa_challenge.html")
	if t, err := template.ParseFiles(templatePath); err == nil {
		tmpl = t
	} else if embeddedTmpl, err := web.ParseMFAChallengeTemplate(); err == nil {
		// 2. Fall back to embedded template baked into the binary via go:embed
		tmpl = embeddedTmpl
	}

	var corpTmpl *template.Template
	corpTemplatePath := filepath.Join("web", "templates", "corporate_login.html")
	if t, err := template.ParseFiles(corpTemplatePath); err == nil {
		corpTmpl = t
	} else if embeddedCorpTmpl, err := web.ParseCorporateLoginTemplate(); err == nil {
		corpTmpl = embeddedCorpTmpl
	}

	var idpCertStore *goxmldsig.MemoryX509CertificateStore
	certPath := cfg.SAML.IdPCertFile
	if certPath == "" {
		certPath = cfg.SAML.CertFile
	}
	if certPath != "" {
		certData, err := os.ReadFile(certPath)
		if err == nil {
			var roots []*x509.Certificate
			rest := certData
			for len(rest) > 0 {
				var block *pem.Block
				block, rest = pem.Decode(rest)
				if block == nil {
					break
				}
				if block.Type == "CERTIFICATE" {
					if parsedCert, err := x509.ParseCertificate(block.Bytes); err == nil {
						roots = append(roots, parsedCert)
					}
				}
			}
			if len(roots) > 0 {
				idpCertStore = &goxmldsig.MemoryX509CertificateStore{
					Roots: roots,
				}
			}
		}
	}

	var ephemeralSecret []byte
	if cfg == nil || !cfg.IsProduction() {
		ephemeralSecret = make([]byte, 32)
		_, _ = rand.Read(ephemeralSecret)
	}

	return &SAMLHandler{
		pipeline:             p,
		mfaService:           mfaSvc,
		responseGen:          respGen,
		correlationStore:     NewCorrelationStore(15 * time.Minute),
		idpCertStore:         idpCertStore,
		cfg:                  cfg,
		templates:            tmpl,
		corporateLoginTmpl:   corpTmpl,
		logger:               log,
		ephemeralAdminSecret: ephemeralSecret,
		assertionReplay:      replay.NewMemoryReplayDetector(),
	}, nil
}

func (h *SAMLHandler) getAssertionReplay() *replay.MemoryReplayDetector {
	h.assertionReplayMu.Lock()
	defer h.assertionReplayMu.Unlock()
	if h.assertionReplay == nil {
		h.assertionReplay = replay.NewMemoryReplayDetector()
	}
	return h.assertionReplay
}

// isHTTPSRequest reports whether Secure cookies should be set for the current request.
// X-Forwarded-Proto is honored only when trusted proxies are explicitly configured.
func (h *SAMLHandler) isHTTPSRequest(c *gin.Context) bool {
	if h.cfg != nil {
		if h.cfg.TLS.Enabled || strings.HasPrefix(strings.ToLower(strings.TrimSpace(h.cfg.SAML.SSOURL)), "https://") {
			return true
		}
	}
	if c != nil && c.Request != nil && c.Request.TLS != nil {
		return true
	}
	if c != nil && h.cfg != nil && len(h.cfg.Security.TrustedProxies) > 0 {
		return strings.EqualFold(strings.TrimSpace(c.GetHeader("X-Forwarded-Proto")), "https")
	}
	return false
}

// DetermineAuthnContextClassRef resolves the appropriate AuthnContextClassRef for the verified MFA method.
// Enforces that Email OTP can NEVER claim TimeSyncToken or any other time-synchronized hardware/software token class.
func DetermineAuthnContextClassRef(method string, globalConfig string) string {
	const (
		TimeSyncToken = "urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken"
		Unspecified   = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified"
	)

	normMethod := strings.ToLower(strings.TrimSpace(method))

	if normMethod == "totp" {
		if globalConfig != "" && globalConfig != Unspecified {
			return globalConfig
		}
		return TimeSyncToken
	}

	// For Email OTP:
	// Email OTP is an out-of-band asynchronous token, NOT a time-synchronized token.
	// It must NEVER claim TimeSyncToken, regardless of global configuration.
	if globalConfig != "" && globalConfig != TimeSyncToken {
		return globalConfig
	}
	return Unspecified
}

func (h *SAMLHandler) SetIDPCertStore(store *goxmldsig.MemoryX509CertificateStore) {
	h.idpCertStore = store
}

func (h *SAMLHandler) SetIDPCertificate(cert *x509.Certificate) {
	if cert != nil {
		h.idpCertStore = &goxmldsig.MemoryX509CertificateStore{
			Roots: []*x509.Certificate{cert},
		}
	}
}

// HandleSSO accepts GET /saml/sso or /login (HTTP-Redirect from ITA)
func (h *SAMLHandler) HandleSSO(c *gin.Context) {
	ctx := c.Request.Context()

	authCtx, err := h.pipeline.Execute(ctx, c.Request)
	if err != nil {
		response.Error(c, http.StatusBadRequest, err)
		return
	}

	itaRequestID := authCtx.RequestIDFromSP
	if itaRequestID == "" {
		itaRequestID = c.Query("request_id")
	}
	itaRelayState := authCtx.RelayState
	if itaRelayState == "" {
		itaRelayState = c.Query("RelayState")
	}
	itaACSURL := strings.TrimSpace(authCtx.AssertionConsumerServiceURL)
	if itaACSURL != "" {
		var metaEndpoints []string
		if md, ok := authCtx.Metadata.(*fedmodel.MetadataDescriptor); ok && md != nil {
			for _, ep := range md.SSOEndpoints {
				if ep.Location != "" {
					metaEndpoints = append(metaEndpoints, ep.Location)
				}
			}
		}
		if !h.cfg.IsAllowedDownstreamACSURL(itaACSURL, metaEndpoints...) {
			if h.logger != nil {
				h.logger.Warn("rejected untrusted AssertionConsumerServiceURL in inbound AuthnRequest",
					zap.String("acs_url", itaACSURL),
					zap.String("issuer", authCtx.Issuer),
				)
			}
			response.Error(c, http.StatusBadRequest, errors.New("security violation: AssertionConsumerServiceURL is not in configured downstream allowlist"))
			return
		}
	} else {
		itaACSURL = h.cfg.SAML.ACSURL
	}

	// Generate outbound request ID for correlation
	outboundID := "SG_" + uuid.New().String()

	state := &AuthSessionState{
		ITAAuthnRequestID: itaRequestID,
		ITARelayState:     itaRelayState,
		ITAACSURL:         itaACSURL,
		OutboundRequestID: outboundID,
	}

	sessionID, err := h.correlationStore.Create(state)
	if err != nil {
		if errors.Is(err, ErrCorrelationStoreFull) {
			response.Error(c, http.StatusServiceUnavailable, err)
			return
		}
		response.Error(c, http.StatusInternalServerError, errors.New("failed to initialize auth correlation state"))
		return
	}

	isSecure := h.isHTTPSRequest(c)
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("samlguard_auth_state", sessionID, 900, "/", "", isSecure, true)

	// If mock IdP is configured or used for development testing
	mockURL := h.cfg.SAML.IdPSSOURL
	if mockURL != "" && strings.Contains(mockURL, "mock-idp") {
		if h.cfg.IsProduction() {
			response.Error(c, http.StatusForbidden, errors.New("mock IdP login is forbidden in production mode"))
			return
		}
		// Render mock upstream login form that posts a signed SAMLResponse to /saml/acs
		h.renderMockUpstreamLogin(c, sessionID, outboundID, "", "")
		return
	}

	// For standard upstream IdP: redirect with preserved RelayState (bound to sessionID)
	redirectURL := fmt.Sprintf("%s?SAMLRequest=%s&RelayState=%s", mockURL, outboundID, sessionID)
	c.Redirect(http.StatusFound, redirectURL)
}

// validateUpstreamSAMLResponse decodes and verifies the upstream SAML 2.0 Response XMLDSig and assertions
func (h *SAMLHandler) validateUpstreamSAMLResponse(rawB64 string, expectedOutboundID string) (*UpstreamClaims, error) {
	if strings.TrimSpace(rawB64) == "" {
		return nil, errors.New("missing SAMLResponse parameter")
	}

	rawXML, err := base64.StdEncoding.DecodeString(rawB64)
	if err != nil {
		rawXML, err = base64.URLEncoding.DecodeString(rawB64)
		if err != nil {
			return nil, fmt.Errorf("decoding base64 SAMLResponse: %w", err)
		}
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(rawXML); err != nil {
		return nil, fmt.Errorf("parsing SAML response XML: %w", err)
	}

	root := doc.Root()
	if root == nil {
		return nil, errors.New("empty XML document")
	}
	if root.Tag != "Response" && !strings.HasSuffix(root.Tag, ":Response") {
		return nil, fmt.Errorf("unexpected root XML element: %s", root.Tag)
	}

	// Reject Signature Wrapping (XSW) attempts with multiple assertions
	allAssertions := doc.FindElements("//Assertion")
	if len(allAssertions) > 1 {
		return nil, errors.New("security violation: multiple Assertion elements detected (signature wrapping attempt)")
	}
	if len(allAssertions) == 0 {
		return nil, errors.New("missing Assertion element in SAMLResponse")
	}
	assertionEl := allAssertions[0]
	assertionID := strings.TrimSpace(assertionEl.SelectAttrValue("ID", ""))
	if h.cfg != nil && h.cfg.IsProduction() && assertionID == "" {
		return nil, errors.New("upstream SAML validation failed: missing Assertion ID attribute")
	}

	// Reject duplicate XML ID attributes
	idSet := make(map[string]bool)
	for _, el := range doc.FindElements("//*[@ID]") {
		id := el.SelectAttrValue("ID", "")
		if id != "" {
			if idSet[id] {
				return nil, fmt.Errorf("security violation: duplicate XML ID detected: %s", id)
			}
			idSet[id] = true
		}
	}

	// Validate XMLDSig
	if h.idpCertStore == nil {
		return nil, errors.New("upstream IdP certificate store not configured: cannot verify XMLDSig")
	}
	valCtx := goxmldsig.NewDefaultValidationContext(h.idpCertStore)

	hasAssertionSig := assertionEl.FindElement("./Signature") != nil || assertionEl.FindElement("./{http://www.w3.org/2000/09/xmldsig#}Signature") != nil
	hasResponseSig := root.FindElement("./Signature") != nil || root.FindElement("./{http://www.w3.org/2000/09/xmldsig#}Signature") != nil

	if !hasAssertionSig && !hasResponseSig {
		return nil, errors.New("SAML response rejected: missing digital signature on both Response and Assertion")
	}

	if hasAssertionSig {
		_, err = valCtx.Validate(assertionEl)
		if err != nil {
			return nil, fmt.Errorf("assertion digital signature validation failed: %w", err)
		}
	} else if hasResponseSig {
		_, err = valCtx.Validate(root)
		if err != nil {
			return nil, fmt.Errorf("response digital signature validation failed: %w", err)
		}
	}

	// Issuer validation
	issuerEl := assertionEl.FindElement(".//Issuer")
	if issuerEl == nil {
		issuerEl = root.FindElement(".//Issuer")
	}
	if issuerEl == nil {
		return nil, errors.New("upstream SAML validation failed: missing Issuer element")
	}
	issuer := strings.TrimSpace(issuerEl.Text())
	if issuer == "" {
		return nil, errors.New("upstream SAML validation failed: empty Issuer in upstream SAML response")
	}
	expectedIssuer := strings.TrimSpace(h.cfg.SAML.IdPEntityID)
	if expectedIssuer == "" {
		if h.cfg.IsProduction() {
			return nil, errors.New("upstream SAML validation failed: saml.idp_entity_id is mandatory in production mode; mock IdP issuer fallback is forbidden")
		}
		expectedIssuer = "https://mock-idp.samlguard.local"
	}
	if issuer != expectedIssuer {
		return nil, fmt.Errorf("upstream SAML validation failed: Issuer mismatch: expected %s, got %s", expectedIssuer, issuer)
	}

	// Correlation check: InResponseTo
	if expectedOutboundID != "" {
		respInResponseTo := root.SelectAttrValue("InResponseTo", "")
		subjConf := assertionEl.FindElement(".//SubjectConfirmationData")
		var subjInResponseTo string
		if subjConf != nil {
			subjInResponseTo = subjConf.SelectAttrValue("InResponseTo", "")
		}

		if respInResponseTo != "" && respInResponseTo != expectedOutboundID {
			return nil, fmt.Errorf("InResponseTo mismatch on Response: expected %s, got %s", expectedOutboundID, respInResponseTo)
		}
		if subjInResponseTo != "" && subjInResponseTo != expectedOutboundID {
			return nil, fmt.Errorf("InResponseTo mismatch on SubjectConfirmationData: expected %s, got %s", expectedOutboundID, subjInResponseTo)
		}
		if respInResponseTo == "" && subjInResponseTo == "" {
			return nil, errors.New("unsolicited response rejected: missing InResponseTo correlation")
		}
	}

	// SubjectConfirmationData Recipient validation (exact matching after safe URL normalization)
	subjConfData := assertionEl.FindElement(".//SubjectConfirmationData")
	if subjConfData == nil {
		return nil, errors.New("upstream SAML validation failed: missing SubjectConfirmationData element")
	}
	recipient := strings.TrimSpace(subjConfData.SelectAttrValue("Recipient", ""))
	if recipient == "" {
		return nil, errors.New("upstream SAML validation failed: missing or empty SubjectConfirmationData Recipient")
	}
	expectedACS := strings.TrimSpace(h.cfg.SAML.ACSURL)
	if expectedACS == "" {
		if h.cfg.IsProduction() {
			return nil, errors.New("upstream SAML validation failed: saml.acs_url is mandatory in production mode; /saml/acs fallback is forbidden")
		}
		expectedACS = "/saml/acs"
	}
	normRecipient := strings.TrimRight(recipient, "/")
	normExpectedACS := strings.TrimRight(expectedACS, "/")
	if normRecipient != normExpectedACS {
		return nil, fmt.Errorf("upstream SAML validation failed: SubjectConfirmationData Recipient mismatch: expected %s, got %s", expectedACS, recipient)
	}

	// Destination check (strict match against expected ACS URL)
	dest := strings.TrimSpace(root.SelectAttrValue("Destination", ""))
	if dest != "" {
		if !matchesExpectedDestination(dest, expectedACS, h.cfg != nil && h.cfg.IsProduction()) {
			return nil, fmt.Errorf("destination mismatch: %s does not match SAMLGuard ACS", dest)
		}
	}

	// AudienceRestriction check
	audEl := assertionEl.FindElement(".//Conditions/AudienceRestriction/Audience")
	if audEl != nil {
		aud := strings.TrimSpace(audEl.Text())
		matched := false
		if h.cfg.SAML.EntityID != "" && aud == h.cfg.SAML.EntityID {
			matched = true
		}
		for _, allowed := range h.cfg.SAML.AllowedAudiences {
			if aud == allowed {
				matched = true
				break
			}
		}
		if !matched && h.cfg.SAML.EntityID != "" {
			return nil, fmt.Errorf("audience mismatch: %s not recognized", aud)
		}
	}

	// Temporal bounds check on SubjectConfirmationData & Conditions (5 minutes clock skew tolerance)
	now := time.Now().UTC()
	skew := 5 * time.Minute
	replayTTL := 15 * time.Minute

	if nbStr := strings.TrimSpace(subjConfData.SelectAttrValue("NotBefore", "")); nbStr != "" {
		nb, err := parseSAMLTimestamp(nbStr)
		if err != nil {
			return nil, fmt.Errorf("invalid SubjectConfirmationData NotBefore timestamp: %w", err)
		}
		if now.Add(skew).Before(nb) {
			return nil, fmt.Errorf("SubjectConfirmationData NotBefore condition not met: %s", nbStr)
		}
	}
	if noaStr := strings.TrimSpace(subjConfData.SelectAttrValue("NotOnOrAfter", "")); noaStr != "" {
		noa, err := parseSAMLTimestamp(noaStr)
		if err != nil {
			return nil, fmt.Errorf("invalid SubjectConfirmationData NotOnOrAfter timestamp: %w", err)
		}
		if now.Add(-skew).After(noa) {
			return nil, fmt.Errorf("SubjectConfirmationData expired: NotOnOrAfter %s", noaStr)
		}
		if rem := noa.Add(skew).Sub(now); rem > 0 {
			replayTTL = rem
		}
	}

	condEl := assertionEl.FindElement(".//Conditions")
	if condEl != nil {
		if nbStr := strings.TrimSpace(condEl.SelectAttrValue("NotBefore", "")); nbStr != "" {
			nb, err := parseSAMLTimestamp(nbStr)
			if err != nil {
				return nil, fmt.Errorf("invalid assertion NotBefore timestamp: %w", err)
			}
			if now.Add(skew).Before(nb) {
				return nil, fmt.Errorf("assertion NotBefore condition not met: %s", nbStr)
			}
		}
		if noaStr := strings.TrimSpace(condEl.SelectAttrValue("NotOnOrAfter", "")); noaStr != "" {
			noa, err := parseSAMLTimestamp(noaStr)
			if err != nil {
				return nil, fmt.Errorf("invalid assertion NotOnOrAfter timestamp: %w", err)
			}
			if now.Add(-skew).After(noa) {
				return nil, fmt.Errorf("assertion expired: NotOnOrAfter %s", noaStr)
			}
			if rem := noa.Add(skew).Sub(now); rem > replayTTL {
				replayTTL = rem
			}
		}
	}
	if replayTTL > 30*time.Minute {
		replayTTL = 30 * time.Minute
	}

	// Subject extraction
	nameIDEl := assertionEl.FindElement(".//Subject/NameID")
	if nameIDEl == nil {
		return nil, errors.New("missing Subject NameID in upstream assertion")
	}
	subjectNameID := strings.TrimSpace(nameIDEl.Text())
	subjectFormat := nameIDEl.SelectAttrValue("Format", "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent")
	if subjectNameID == "" {
		return nil, errors.New("empty Subject NameID in upstream assertion")
	}

	var email, displayName string
	var groups []string

	attrElements := assertionEl.FindElements(".//Attribute")
	for _, attr := range attrElements {
		attrName := attr.SelectAttrValue("Name", "")
		for _, valEl := range attr.FindElements("AttributeValue") {
			val := strings.TrimSpace(valEl.Text())
			if val == "" {
				continue
			}
			switch strings.ToLower(attrName) {
			case "email", "mail", "emailaddress", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress":
				if email == "" {
					email = val
				}
			case "displayname", "name", "cn", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name":
				if displayName == "" {
					displayName = val
				}
			case "groups", "group", "memberof", "roles", "role", "http://schemas.xmlsoap.org/claims/group":
				groups = append(groups, val)
			case "oid", "uid", "sub", "immutable_id", "http://schemas.microsoft.com/identity/claims/objectidentifier":
				if strings.Contains(subjectFormat, "transient") {
					subjectNameID = val
				}
			}
		}
	}

	if strings.Contains(subjectFormat, "transient") && subjectNameID == strings.TrimSpace(nameIDEl.Text()) {
		return nil, errors.New("transient NameID rejected: immutable identity claim (e.g. oid) required")
	}

	if email == "" && strings.Contains(subjectFormat, "emailAddress") && strings.Contains(subjectNameID, "@") {
		email = subjectNameID
	}
	if displayName == "" {
		displayName = subjectNameID
	}

	// Enforce Assertion ID replay protection only after signature and claim validation pass
	if assertionID != "" {
		if h.getAssertionReplay().CheckAndMark("assertion:"+assertionID, replayTTL) {
			return nil, fmt.Errorf("security violation: SAML assertion replay detected (ID %s)", assertionID)
		}
	}

	return &UpstreamClaims{
		SubjectNameID:       subjectNameID,
		SubjectNameIDFormat: subjectFormat,
		Email:               email,
		DisplayName:         displayName,
		Groups:              groups,
	}, nil
}

func parseSAMLTimestamp(raw string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return t, nil
	}
	return time.Parse(time.RFC3339, raw)
}

func matchesExpectedDestination(dest, expectedACS string, isProd bool) bool {
	normDest := strings.TrimRight(strings.TrimSpace(dest), "/")
	normExpected := strings.TrimRight(strings.TrimSpace(expectedACS), "/")
	if normDest == "" {
		return true
	}
	if normDest == normExpected {
		return true
	}
	if strings.HasPrefix(strings.ToLower(normExpected), "https://") || strings.HasPrefix(strings.ToLower(normExpected), "http://") {
		return false
	}
	// Non-production fallback when ACSURL is relative ("/saml/acs")
	if !isProd && normExpected == "/saml/acs" {
		if u, err := url.Parse(normDest); err == nil {
			p := strings.TrimRight(u.Path, "/")
			return p == "/saml/acs" || p == "/acs"
		}
	}
	return false
}

// HandleACS accepts POST /saml/acs (HTTP-POST from Upstream IdP)
func (h *SAMLHandler) HandleACS(c *gin.Context) {
	sessionID, _ := c.Cookie("samlguard_auth_state")
	if sessionID == "" {
		sessionID = c.PostForm("RelayState")
	}

	if sessionID == "" {
		response.Error(c, http.StatusBadRequest, errors.New("missing correlation session: RelayState or cookie not found"))
		return
	}

	state, err := h.correlationStore.Get(sessionID)
	if err != nil {
		response.Error(c, http.StatusBadRequest, fmt.Errorf("correlation state invalid: %w", err))
		return
	}

	if state.AssertionConsumed {
		response.Error(c, http.StatusConflict, errors.New("upstream SAML assertion already processed for this authentication session"))
		return
	}

	samlRespB64 := c.PostForm("SAMLResponse")
	if samlRespB64 == "" {
		response.Error(c, http.StatusBadRequest, errors.New("missing SAMLResponse POST parameter"))
		return
	}

	claims, err := h.validateUpstreamSAMLResponse(samlRespB64, state.OutboundRequestID)
	if err != nil {
		if h.logger != nil {
			h.logger.Warn("upstream SAML validation failed", zap.Error(err))
		}
		response.Error(c, http.StatusUnauthorized, fmt.Errorf("upstream SAML assertion rejected: %w", err))
		return
	}

	upstreamEntityID := strings.TrimSpace(h.cfg.SAML.IdPEntityID)
	if upstreamEntityID == "" {
		if h.cfg.IsProduction() {
			response.Error(c, http.StatusInternalServerError, errors.New("upstream IdP Entity ID is mandatory in production mode"))
			return
		}
		upstreamEntityID = "https://mock-idp.samlguard.local"
	}

	userKey := fmt.Sprintf("%s|%s", upstreamEntityID, claims.SubjectNameID)

	// Whitelist verification for inbound claims
	if h.cfg.ITA.EnforceUserWhitelist {
		authorized, _ := h.mfaService.IsUserAuthorized(c.Request.Context(), claims.SubjectNameID)
		if !authorized && claims.Email != "" {
			authorized, _ = h.mfaService.IsUserAuthorized(c.Request.Context(), claims.Email)
		}
		if !authorized {
			h.logger.Warn("inbound assertion user rejected by ITA whitelist policy",
				zap.String("subject", claims.SubjectNameID),
				zap.String("email", claims.Email),
			)
			c.Header("Content-Type", "text/html; charset=utf-8")
			c.String(http.StatusForbidden, `<div style="font-family: sans-serif; padding: 2.5rem; background: #0f172a; color: #fecaca; min-height: 100vh; text-align: center;"><div style="max-width: 500px; margin: 3rem auto; background: #1e293b; padding: 2rem; border-radius: 12px; border: 1px solid #b91c1c;"><h2 style="color: #f87171; margin-top: 0;">⚠️ Access Denied</h2><p style="color: #e2e8f0; line-height: 1.6;">The account <strong>%s</strong> was not found in Schneider IT Advisor records. Please contact your system administrator for access invitation.</p></div></div>`, html.EscapeString(claims.SubjectNameID))
			return
		}
	}

	state.UpstreamEntityID = upstreamEntityID
	state.SubjectNameID = claims.SubjectNameID
	state.SubjectNameIDFormat = claims.SubjectNameIDFormat
	state.UserIdentityKey = userKey
	state.UserEmail = claims.Email
	state.UserDisplayName = claims.DisplayName
	state.UserGroups = claims.Groups
	state.AssertionConsumed = true

	_ = h.correlationStore.Update(sessionID, state)

	// Check MFA status for user and render challenge
	h.renderMFAChallengeView(c, state, "totp", "")
}

// HandleACSGet handles GET /saml/acs and GET /acs (for method switching, tab clicks, and page reloads)
func (h *SAMLHandler) HandleACSGet(c *gin.Context) {
	sessionID, _ := c.Cookie("samlguard_auth_state")
	if sessionID == "" {
		sessionID = c.Query("session_id")
	}

	if sessionID == "" {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	state, err := h.correlationStore.Get(sessionID)
	if err != nil || state == nil || state.UserIdentityKey == "" {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	method := c.DefaultQuery("method", "totp")
	if method != "totp" && method != "email" {
		method = "totp"
	}

	h.renderMFAChallengeView(c, state, method, "")
}

// HandleMFAVerify accepts POST /mfa/verify
func (h *SAMLHandler) HandleMFAVerify(c *gin.Context) {
	sessionID, _ := c.Cookie("samlguard_auth_state")
	if sessionID == "" {
		sessionID = c.PostForm("session_id")
	}

	state, err := h.correlationStore.Get(sessionID)
	if err != nil {
		response.Error(c, http.StatusUnauthorized, fmt.Errorf("session invalid or expired: %w", err))
		return
	}

	// CSRF validation
	csrfToken := c.PostForm("csrf_token")
	if csrfToken == "" || subtle.ConstantTimeCompare([]byte(csrfToken), []byte(state.CSRFToken)) != 1 {
		response.Error(c, http.StatusForbidden, errors.New("invalid or missing CSRF token"))
		return
	}

	code := strings.TrimSpace(c.PostForm("code"))
	method := strings.TrimSpace(c.PostForm("method"))
	if method == "" {
		method = "totp"
	}

	var verified bool
	ctx := c.Request.Context()

	if method == "totp" {
		isPending := c.PostForm("is_pending") == "true"
		if isPending {
			if h.mfaService.HasActiveTOTP(ctx, state.UserIdentityKey) && !state.ReEnrollAuthorized {
				if h.logger != nil {
					h.logger.Warn("blocked unauthorized pending TOTP activation attempt",
						zap.String("user_key", state.UserIdentityKey),
					)
				}
				response.Error(c, http.StatusForbidden, errors.New("re-enrollment not authorized: verify current factor first"))
				return
			}
			verified, err = h.mfaService.VerifyAndActivatePendingTOTP(ctx, state.UserIdentityKey, code)
		} else {
			verified, err = h.mfaService.VerifyTOTP(ctx, state.UserIdentityKey, code)
		}
	} else if method == "email" {
		verified, err = h.mfaService.VerifyEmailOTP(ctx, state.UserIdentityKey, code)
	} else {
		err = errors.New("unsupported MFA method")
	}

	// If MFA verification fails: NEVER emit a SAML response!
	if err != nil || !verified {
		if h.logger != nil {
			h.logger.Warn("MFA verification failed",
				zap.String("user_key", state.UserIdentityKey),
				zap.String("method", method),
				zap.Error(err),
			)
		}
		errMsg := "Invalid verification code. Please check and try again."
		if err != nil && (strings.Contains(err.Error(), "locked") || strings.Contains(err.Error(), "too many")) {
			errMsg = err.Error()
		}
		h.renderMFAChallengeView(c, state, method, errMsg)
		return
	}

	// MFA Succeeded: Atomically consume correlation session (enforce single-use)
	consumedState, err := h.correlationStore.Consume(sessionID)
	if err != nil {
		response.Error(c, http.StatusConflict, errors.New("authentication state already consumed or expired"))
		return
	}

	// Clear session cookie
	isSecure := h.isHTTPSRequest(c)
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("samlguard_auth_state", "", -1, "/", "", isSecure, true)

	// Determine AuthnContextClassRef: Email OTP can NEVER claim TimeSyncToken
	authnContext := DetermineAuthnContextClassRef(method, h.cfg.SAML.AuthnContextClassRef)

	// Determine Audience (Downstream SP Entity ID)
	audience := h.cfg.ResolveDownstreamSPEntityID()

	// Generate signed SAML Response targeting downstream ITA ACS
	samlReq := gateway.SAMLResponseRequest{
		InResponseTo:         consumedState.ITAAuthnRequestID, // Downstream InResponseTo matches ITA original ID!
		Destination:          consumedState.ITAACSURL,
		RelayState:           consumedState.ITARelayState, // Preserve original ITA RelayState!
		Audience:             audience,
		Issuer:               h.cfg.SAML.EntityID,
		SubjectNameID:        consumedState.SubjectNameID,
		SubjectNameIDFormat:  consumedState.SubjectNameIDFormat,
		Email:                consumedState.UserEmail,
		DisplayName:          consumedState.UserDisplayName,
		RawGroups:            consumedState.UserGroups,
		AuthnContextClassRef: authnContext,
	}

	result, err := h.responseGen.GenerateResponse(samlReq)
	if err != nil {
		if h.logger != nil {
			h.logger.Error("failed to generate signed SAML response", zap.Error(err))
		}
		response.Error(c, http.StatusInternalServerError, errors.New("failed to generate SAML response for ITA"))
		return
	}

	// Deliver auto-submitting POST form to ITA ACS
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(result.PostFormHTML))
}

// HandleMFAResend handles POST /mfa/resend for Email OTP
func (h *SAMLHandler) HandleMFAResend(c *gin.Context) {
	sessionID, _ := c.Cookie("samlguard_auth_state")
	if sessionID == "" {
		sessionID = c.PostForm("session_id")
	}

	state, err := h.correlationStore.Get(sessionID)
	if err != nil {
		response.Error(c, http.StatusUnauthorized, errors.New("invalid or expired session"))
		return
	}

	// CSRF validation
	csrfToken := c.PostForm("csrf_token")
	if csrfToken == "" || subtle.ConstantTimeCompare([]byte(csrfToken), []byte(state.CSRFToken)) != 1 {
		response.Error(c, http.StatusForbidden, errors.New("invalid or missing CSRF token"))
		return
	}

	ctx := c.Request.Context()
	err = h.mfaService.GenerateAndSendEmailOTP(ctx, state.UserIdentityKey, state.UserEmail)
	if err != nil {
		h.renderMFAChallengeView(c, state, "email", err.Error())
		return
	}

	h.renderMFAChallengeView(c, state, "email", "A new one-time code has been sent to your email.")
}

// HandleMFAReEnroll handles POST /mfa/re-enroll to generate a new TOTP enrollment without destroying existing active TOTP.
// If the user already has an active TOTP enrollment, they MUST prove possession of an existing factor first.
func (h *SAMLHandler) HandleMFAReEnroll(c *gin.Context) {
	sessionID, _ := c.Cookie("samlguard_auth_state")
	if sessionID == "" {
		sessionID = c.PostForm("session_id")
	}

	state, err := h.correlationStore.Get(sessionID)
	if err != nil {
		response.Error(c, http.StatusUnauthorized, errors.New("invalid or expired session"))
		return
	}

	// CSRF validation
	csrfToken := c.PostForm("csrf_token")
	if csrfToken == "" || subtle.ConstantTimeCompare([]byte(csrfToken), []byte(state.CSRFToken)) != 1 {
		response.Error(c, http.StatusForbidden, errors.New("invalid or missing CSRF token"))
		return
	}

	ctx := c.Request.Context()
	hasActiveTOTP := h.mfaService.HasActiveTOTP(ctx, state.UserIdentityKey)
	if hasActiveTOTP && !state.ReEnrollAuthorized {
		currentCode := strings.TrimSpace(c.PostForm("current_code"))
		verifyMethod := strings.ToLower(strings.TrimSpace(c.PostForm("verify_method")))
		if verifyMethod == "" {
			verifyMethod = "totp"
		}

		if currentCode == "" {
			h.renderMFAChallengeViewWithStatus(c, http.StatusForbidden, state, "totp", "Enter your current verification code to authorize authenticator re-enrollment.")
			return
		}

		var ok bool
		var verifyErr error
		if verifyMethod == "email" {
			ok, verifyErr = h.mfaService.VerifyEmailOTP(ctx, state.UserIdentityKey, currentCode)
		} else {
			ok, verifyErr = h.mfaService.VerifyTOTP(ctx, state.UserIdentityKey, currentCode)
		}

		if verifyErr != nil || !ok {
			if h.logger != nil {
				h.logger.Warn("blocked TOTP re-enrollment attempt with invalid current code",
					zap.String("user_key", state.UserIdentityKey),
					zap.String("verify_method", verifyMethod),
					zap.Error(verifyErr),
				)
			}
			errMsg := "Current verification code is invalid. Re-enrollment denied."
			if verifyErr != nil && (strings.Contains(verifyErr.Error(), "locked") || strings.Contains(verifyErr.Error(), "too many")) {
				errMsg = verifyErr.Error()
			}
			h.renderMFAChallengeViewWithStatus(c, http.StatusForbidden, state, "totp", errMsg)
			return
		}

		state.ReEnrollAuthorized = true
		_ = h.correlationStore.Update(sessionID, state)
	}

	enrollData, err := h.mfaService.StartTOTPEnrollmentForce(ctx, state.UserIdentityKey, state.UserEmail)
	if err != nil {
		h.renderMFAChallengeView(c, state, "totp", fmt.Sprintf("Failed to generate new TOTP secret: %v", err))
		return
	}

	vm := ChallengeViewModel{
		SessionID:          state.SessionID,
		CSRFToken:          state.CSRFToken,
		Email:              state.UserEmail,
		MaskedEmail:        maskEmail(state.UserEmail),
		Method:             "totp",
		EnrollmentRequired: true,
		SecretKey:          enrollData.SecretKey,
		QRCodeDataURI:      template.URL(enrollData.QRCodeDataURI),
		Message:            "New authenticator key generated. Scan QR code and verify to activate.",
		ResendCooldown:     60,
	}

	c.Header("Content-Type", "text/html; charset=utf-8")
	if h.templates != nil {
		if err := h.templates.Execute(c.Writer, vm); err == nil {
			return
		}
	}

	c.String(http.StatusOK, renderInlineMFAPage(vm))
}

func (h *SAMLHandler) renderMFAChallengeView(c *gin.Context, state *AuthSessionState, method, errorMsg string) {
	h.renderMFAChallengeViewWithStatus(c, http.StatusOK, state, method, errorMsg)
}

func (h *SAMLHandler) renderMFAChallengeViewWithStatus(c *gin.Context, statusCode int, state *AuthSessionState, method, errorMsg string) {
	ctx := c.Request.Context()
	hasActiveTOTP := h.mfaService.HasActiveTOTP(ctx, state.UserIdentityKey)

	vm := ChallengeViewModel{
		SessionID:      state.SessionID,
		CSRFToken:      state.CSRFToken,
		Email:          state.UserEmail,
		MaskedEmail:    maskEmail(state.UserEmail),
		Method:         method,
		ErrorMessage:   errorMsg,
		ResendCooldown: 60,
	}

	if method == "totp" {
		if !hasActiveTOTP {
			// Needs enrollment: generate pending secret & QR code
			enrollData, err := h.mfaService.StartTOTPEnrollment(ctx, state.UserIdentityKey, state.UserEmail)
			if err != nil {
				if h.logger != nil {
					h.logger.Error("failed to start totp enrollment", zap.Error(err))
				}
				if vm.ErrorMessage == "" {
					vm.ErrorMessage = fmt.Sprintf("Failed to generate authenticator setup: %v", err)
				}
			} else if enrollData != nil {
				vm.EnrollmentRequired = true
				vm.SecretKey = enrollData.SecretKey
				vm.QRCodeDataURI = template.URL(enrollData.QRCodeDataURI)
			}
		}
	} else if method == "email" {
		// Send initial email OTP if not already sent
		_ = h.mfaService.GenerateAndSendEmailOTP(ctx, state.UserIdentityKey, state.UserEmail)
	}

	c.Header("Content-Type", "text/html; charset=utf-8")
	if h.templates != nil {
		c.Status(statusCode)
		if err := h.templates.Execute(c.Writer, vm); err == nil {
			return
		}
	}

	// Fallback inline HTML render
	c.String(statusCode, renderInlineMFAPage(vm))
}

func (h *SAMLHandler) renderMockUpstreamLogin(c *gin.Context, sessionID, outboundID, prefillUser, errorMessage string) {
	mockDestination := h.cfg.SAML.ACSURL
	if mockDestination == "" {
		mockDestination = "/saml/acs"
	}
	mockIssuer := h.cfg.SAML.IdPEntityID
	if mockIssuer == "" {
		mockIssuer = "https://mock-idp.samlguard.local"
	}
	mockAudience := h.cfg.SAML.EntityID
	if mockAudience == "" {
		mockAudience = "urn:samlguard:idp"
	}

	mockReq := gateway.SAMLResponseRequest{
		InResponseTo:         outboundID,
		Destination:          mockDestination,
		RelayState:           sessionID,
		Audience:             mockAudience,
		Issuer:               mockIssuer,
		SubjectNameID:        "apc",
		SubjectNameIDFormat:  "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
		Email:                "apc@example.com",
		DisplayName:          "APC Administrator",
		RawGroups:            []string{"ita-admins"},
		AuthnContextClassRef: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
	}

	result, _ := h.responseGen.GenerateResponse(mockReq)
	defaultSAMLResponse := ""
	if result != nil {
		defaultSAMLResponse = result.SAMLResponse
	}

	vm := CorporateLoginViewModel{
		SessionID:         sessionID,
		OutboundID:        outboundID,
		SAMLResponseInput: template.HTML(fmt.Sprintf(`<input type="hidden" name="SAMLResponse" value="%s"/>`, html.EscapeString(defaultSAMLResponse))),
		Username:          prefillUser,
		ErrorMessage:      errorMessage,
	}

	tmpl := h.corporateLoginTmpl
	if tmpl == nil {
		tmpl, _ = web.ParseCorporateLoginTemplate()
	}

	c.Header("Content-Type", "text/html; charset=utf-8")
	if tmpl != nil {
		c.Status(http.StatusOK)
		if err := tmpl.Execute(c.Writer, vm); err == nil {
			return
		}
	}

	c.String(http.StatusInternalServerError, "Failed to render corporate login page")
}

// HandleMockIDPSubmit processes the user's entered username or email and generates the SAML response
func (h *SAMLHandler) HandleMockIDPSubmit(c *gin.Context) {
	sessionID := c.PostForm("session_id")
	outboundID := c.PostForm("outbound_id")
	rawUser := strings.TrimSpace(c.PostForm("username"))

	if sessionID == "" || rawUser == "" {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	state, err := h.correlationStore.Get(sessionID)
	if err != nil || state == nil {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	// Whitelist verification: block unauthorized users before generating any SAML token
	if h.cfg.ITA.EnforceUserWhitelist {
		authorized, err := h.mfaService.IsUserAuthorized(c.Request.Context(), rawUser)
		if err != nil || !authorized {
			h.logger.Warn("unauthorized login attempt blocked: user not found in ITA record",
				zap.String("identifier", rawUser),
				zap.String("session_id", sessionID),
			)
			h.renderMockUpstreamLogin(c, sessionID, outboundID, rawUser, fmt.Sprintf("Account '%s' was not found in IT Advisor records. Please contact your system administrator for access invitation.", rawUser))
			return
		}
	}

	mockDestination := h.cfg.SAML.ACSURL
	if mockDestination == "" {
		mockDestination = "/saml/acs"
	}
	mockIssuer := h.cfg.SAML.IdPEntityID
	if mockIssuer == "" {
		mockIssuer = "https://mock-idp.samlguard.local"
	}
	mockAudience := h.cfg.SAML.EntityID
	if mockAudience == "" {
		mockAudience = "urn:samlguard:idp"
	}

	nameID := rawUser
	email := rawUser
	if !strings.Contains(rawUser, "@") {
		email = rawUser + "@example.local"
	}

	mockReq := gateway.SAMLResponseRequest{
		InResponseTo:         outboundID,
		Destination:          mockDestination,
		RelayState:           sessionID,
		Audience:             mockAudience,
		Issuer:               mockIssuer,
		SubjectNameID:        nameID,
		SubjectNameIDFormat:  "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
		Email:                email,
		DisplayName:          rawUser,
		RawGroups:            []string{"ita-admins"},
		AuthnContextClassRef: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
	}

	result, err := h.responseGen.GenerateResponse(mockReq)
	if err != nil {
		response.Error(c, http.StatusInternalServerError, fmt.Errorf("failed to generate upstream SAML response: %w", err))
		return
	}

	formHTML := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>SAMLGuard - Redirecting to MFA</title></head>
<body onload="document.forms[0].submit()">
	<noscript><p>Redirecting to verification...</p></noscript>
	<form method="POST" action="/saml/acs">
		<input type="hidden" name="RelayState" value="%s"/>
		<input type="hidden" name="SAMLResponse" value="%s"/>
		<noscript><button type="submit">Continue to Verification &rarr;</button></noscript>
	</form>
</body>
</html>`, html.EscapeString(sessionID), html.EscapeString(result.SAMLResponse))

	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(formHTML))
}

func (h *SAMLHandler) getKeyDescriptorXML() string {
	if h.responseGen != nil && h.responseGen.Certificate() != nil {
		certB64 := base64.StdEncoding.EncodeToString(h.responseGen.Certificate().Raw)
		if certB64 != "" {
			return fmt.Sprintf(`    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>%s</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
`, certB64)
		}
	}
	return ""
}

func (h *SAMLHandler) getACSLocation() string {
	if h.cfg.SAML.ACSURL != "" {
		return h.cfg.SAML.ACSURL
	}
	return h.cfg.SAML.EntityID + "/saml/acs"
}

// HandleIdPMetadata renders SAML 2.0 Identity Provider metadata strictly for downstream SPs (Schneider Electric IT Advisor).
func (h *SAMLHandler) HandleIdPMetadata(c *gin.Context) {
	keyDescriptor := h.getKeyDescriptorXML()

	metadataXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="%s">
  <md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
%s    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="%s"/>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="%s"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>`, h.cfg.SAML.EntityID, keyDescriptor, h.cfg.SAML.SSOURL, h.cfg.SAML.SSOURL)

	c.Data(http.StatusOK, "application/samlmetadata+xml", []byte(metadataXML))
}

// HandleSPMetadata renders SAML 2.0 Service Provider metadata strictly for upstream IdPs (Microsoft Entra ID / Keycloak).
func (h *SAMLHandler) HandleSPMetadata(c *gin.Context) {
	keyDescriptor := h.getKeyDescriptorXML()
	acsLocation := h.getACSLocation()

	metadataXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="%s">
  <md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
%s    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="%s" index="0" isDefault="true"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>`, h.cfg.SAML.EntityID, keyDescriptor, acsLocation)

	c.Data(http.StatusOK, "application/samlmetadata+xml", []byte(metadataXML))
}

// HandleMetadata renders SAML 2.0 metadata with role parameter dispatch:
// ?role=idp -> downstream IdP metadata for ITA
// ?role=sp  -> upstream SP metadata for Entra ID
// default   -> combined EntityDescriptor containing both IDPSSODescriptor and SPSSODescriptor
func (h *SAMLHandler) HandleMetadata(c *gin.Context) {
	role := strings.ToLower(strings.TrimSpace(c.Query("role")))
	if role == "idp" {
		h.HandleIdPMetadata(c)
		return
	}
	if role == "sp" {
		h.HandleSPMetadata(c)
		return
	}

	keyDescriptor := h.getKeyDescriptorXML()
	acsLocation := h.getACSLocation()

	metadataXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="%s">
  <md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
%s    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="%s"/>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="%s"/>
  </md:IDPSSODescriptor>
  <md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
%s    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="%s" index="0" isDefault="true"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>`, h.cfg.SAML.EntityID, keyDescriptor, h.cfg.SAML.SSOURL, h.cfg.SAML.SSOURL, keyDescriptor, acsLocation)

	c.Data(http.StatusOK, "application/samlmetadata+xml", []byte(metadataXML))
}

func maskEmail(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return "***"
	}
	u := parts[0]
	if len(u) <= 2 {
		return u[:1] + "***@" + parts[1]
	}
	return u[:2] + "***@" + parts[1]
}

func renderInlineMFAPage(vm ChallengeViewModel) string {
	escSessionID := html.EscapeString(vm.SessionID)
	escCSRFToken := html.EscapeString(vm.CSRFToken)
	escMethod := html.EscapeString(vm.Method)
	escMaskedEmail := html.EscapeString(vm.MaskedEmail)
	escSecretKey := html.EscapeString(vm.SecretKey)
	escQRDataURI := html.EscapeString(string(vm.QRCodeDataURI))
	escError := html.EscapeString(vm.ErrorMessage)

	var qrHTML string
	if vm.EnrollmentRequired && vm.QRCodeDataURI != "" {
		qrHTML = fmt.Sprintf(`
		<div style="text-align: center; margin-bottom: 1.25rem;">
			<p style="font-size: 0.85rem; color: #94a3b8; margin-bottom: 0.75rem;">Scan this QR code with Microsoft Authenticator, Google Authenticator or any standard TOTP app:</p>
			<img src="%s" alt="TOTP QR Code" style="display: block; margin: 0 auto; border-radius: 8px; width: 180px; height: 180px;"/>
			<div style="margin-top: 0.5rem; font-family: monospace; font-size: 0.8rem; color: #38bdf8;">Key: %s</div>
		</div>`, escQRDataURI, escSecretKey)
	}

	var errorHTML string
	if vm.ErrorMessage != "" {
		errorHTML = fmt.Sprintf(`<div style="padding: 0.75rem; border-radius: 8px; background: #3b1c26; border: 1px solid #dc2626; color: #fca5a5; margin-bottom: 1rem; font-size: 0.85rem;">%s</div>`, escError)
	}

	isPendingValue := "false"
	if vm.EnrollmentRequired {
		isPendingValue = "true"
	}

	var reenrollHTML string
	if !vm.EnrollmentRequired && vm.Method == "totp" {
		reenrollHTML = fmt.Sprintf(`
		<form method="POST" action="/mfa/re-enroll" style="margin-top: 1rem; text-align: center;">
			<input type="hidden" name="session_id" value="%s"/>
			<input type="hidden" name="csrf_token" value="%s"/>
			<input type="text" name="current_code" placeholder="Current 6-digit code" maxlength="8" autocomplete="one-time-code" required style="margin-bottom: 0.5rem; font-size: 0.95rem; padding: 0.5rem;"/>
			<button type="submit" style="background: none; border: none; color: #38bdf8; text-decoration: underline; cursor: pointer; font-size: 0.85rem;">Verify &amp; Re-enroll Authenticator</button>
		</form>`, escSessionID, escCSRFToken)
	}

	var resendHTML string
	if vm.Method == "email" {
		resendHTML = fmt.Sprintf(`
		<form method="POST" action="/mfa/resend" style="margin-top: 1rem; text-align: center;">
			<input type="hidden" name="session_id" value="%s"/>
			<input type="hidden" name="csrf_token" value="%s"/>
			<input type="hidden" name="method" value="email"/>
			<button type="submit" style="background: none; border: none; color: #38bdf8; text-decoration: underline; cursor: pointer; font-size: 0.85rem;">Resend OTP Code</button>
		</form>`, escSessionID, escCSRFToken)
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
	<title>SAMLGuard - MFA Verification</title>
	<style>
		body { font-family: -apple-system, sans-serif; background: #0f172a; color: #e2e8f0; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
		.card { background: #1e293b; padding: 2.25rem; border-radius: 14px; box-shadow: 0 20px 25px -5px rgba(0,0,0,0.5); max-width: 420px; width: 90%%; border: 1px solid #334155; }
		h1 { color: #38bdf8; font-size: 1.4rem; margin: 0 0 0.5rem; text-align: center; }
		.sub { color: #94a3b8; font-size: 0.85rem; text-align: center; margin-bottom: 1.25rem; }
		.tabs { display: flex; gap: 0.5rem; margin-bottom: 1.25rem; }
		.tab { flex: 1; padding: 0.6rem; text-align: center; font-size: 0.85rem; font-weight: 600; border-radius: 8px; border: 1px solid #334155; cursor: pointer; text-decoration: none; color: #94a3b8; }
		.tab.active { background: #2563eb; color: white; border-color: #2563eb; }
		input[type=text] { width: 100%%; padding: 0.8rem; font-size: 1.5rem; letter-spacing: 0.3em; text-align: center; border: 2px solid #334155; border-radius: 8px; background: #0f172a; color: #e2e8f0; box-sizing: border-box; margin-bottom: 1.25rem; }
		input[type=text]:focus { outline: none; border-color: #38bdf8; }
		button.submit-btn { width: 100%%; padding: 0.8rem; background: #2563eb; color: white; border: none; font-size: 1rem; font-weight: 600; border-radius: 8px; cursor: pointer; }
		button.submit-btn:hover { background: #1d4ed8; }
	</style>
</head>
<body>
	<div class="card">
		<h1>🔐 Multi-Factor Verification</h1>
		<div class="sub">Verified Identity: %s</div>
		<div class="tabs">
			<a class="tab %s" href="?method=totp&session_id=%s">Authenticator</a>
			<a class="tab %s" href="?method=email&session_id=%s">Email OTP</a>
		</div>
		%s
		%s
		<form method="POST" action="/mfa/verify">
			<input type="hidden" name="session_id" value="%s"/>
			<input type="hidden" name="csrf_token" value="%s"/>
			<input type="hidden" name="method" value="%s"/>
			<input type="hidden" name="is_pending" value="%s"/>
			<input type="text" name="code" placeholder="000000" maxlength="8" autocomplete="one-time-code" autofocus required/>
			<button type="submit" class="submit-btn">Verify Code</button>
		</form>
		%s
		%s
	</div>
</body>
</html>`,
		escMaskedEmail,
		activeTab(vm.Method == "totp"),
		escSessionID,
		activeTab(vm.Method == "email"),
		escSessionID,
		errorHTML,
		qrHTML,
		escSessionID,
		escCSRFToken,
		escMethod,
		isPendingValue,
		reenrollHTML,
		resendHTML,
	)
}

func activeTab(active bool) string {
	if active {
		return "active"
	}
	return ""
}
