package gateway

import (
	"fmt"
	"html/template"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/hidayat-SE/samlguard/internal/audit"
	"github.com/hidayat-SE/samlguard/internal/auth"
	intmfa "github.com/hidayat-SE/samlguard/internal/mfa"
	intsess "github.com/hidayat-SE/samlguard/internal/session"
	"github.com/hidayat-SE/samlguard/pkg/middleware"
	"github.com/hidayat-SE/samlguard/pkg/saml"
	"github.com/hidayat-SE/samlguard/pkg/utils"
)

// Handler handles HTTP requests for the Gateway service.
type Handler struct {
	service   *Service
	metadataGen *saml.MetadataGenerator
	templates *template.Template
	logger    *zap.Logger
}

// NewHandler creates a new gateway handler.
func NewHandler(service *Service, metadataGen *saml.MetadataGenerator, tmpl *template.Template, log *zap.Logger) *Handler {
	return &Handler{
		service:     service,
		metadataGen: metadataGen,
		templates:   tmpl,
		logger:      log,
	}
}

// Login handles GET /login — initiates SAML authentication.
func (h *Handler) Login(c *gin.Context) {
	relayState := c.Query("RelayState")
	if relayState == "" {
		relayState = c.Query("relay_state")
	}

	redirectURL, err := h.service.InitiateLogin(relayState)
	if err != nil {
		h.logger.Error("failed to initiate login", zap.Error(err))
		h.renderError(c, http.StatusInternalServerError, "Failed to initiate authentication")
		return
	}

	h.service.LogAuditEvent(c.Request.Context(), audit.LogEventRequest{
		EventType:     "login",
		Action:        "saml_authn_request_sent",
		IPAddress:     c.ClientIP(),
		UserAgent:     c.Request.UserAgent(),
		CorrelationID: middleware.GetCorrelationID(c),
		Severity:      "info",
	})

	c.Redirect(http.StatusFound, redirectURL)
}

// MockIdPLogin renders a simple mock login screen representing the upstream IdP.
func (h *Handler) MockIdPLogin(c *gin.Context) {
	relayState := c.Query("RelayState")

	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
	<title>Mock Identity Provider</title>
	<style>
		body {
			font-family: -apple-system, BlinkMacSystemFont, sans-serif;
			background: #0f172a;
			color: #e2e8f0;
			display: flex;
			justify-content: center;
			align-items: center;
			min-height: 100vh;
			margin: 0;
		}
		.card {
			background: #1e293b;
			padding: 2.5rem;
			border-radius: 12px;
			box-shadow: 0 20px 25px -5px rgba(0,0,0,0.5);
			max-width: 400px;
			width: 90%%;
			text-align: center;
		}
		h1 { color: #38bdf8; margin-top: 0; }
		p { color: #94a3b8; font-size: 0.95rem; margin-bottom: 2rem; }
		button {
			background: #2563eb;
			color: white;
			border: none;
			padding: 0.75rem 1.5rem;
			font-size: 1rem;
			font-weight: 600;
			border-radius: 6px;
			cursor: pointer;
			width: 100%%;
			transition: background 0.2s;
		}
		button:hover { background: #1d4ed8; }
	</style>
</head>
<body>
	<div class="card">
		<h1>Mock Upstream IdP</h1>
		<p>This is a simulated upstream identity provider (e.g. Keycloak/Okta) for local development testing.</p>
		<form method="POST" action="/acs">
			<input type="hidden" name="SAMLResponse" value="mock-saml-response-xml-data"/>
			<input type="hidden" name="RelayState" value="%s"/>
			<button type="submit">Sign In as test_user</button>
		</form>
	</div>
</body>
</html>`, relayState)

	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(html))
}


// ACS handles POST /acs — Assertion Consumer Service endpoint.
// Receives the SAML Response from the upstream IdP, validates it,
// triggers MFA, creates a session, generates a new assertion, and
// returns it to the SP.
func (h *Handler) ACS(c *gin.Context) {
	samlResponse := c.PostForm("SAMLResponse")
	relayState := c.PostForm("RelayState")

	if samlResponse == "" {
		utils.ErrorResponse(c, http.StatusBadRequest, "MISSING_SAML_RESPONSE", "SAMLResponse is required")
		return
	}

	ctx := c.Request.Context()

	validateResp, err := h.service.ValidateSAMLResponse(ctx, samlResponse, relayState)
	if err != nil {
		h.logger.Error("SAML validation failed", zap.Error(err))
		h.service.LogAuditEvent(ctx, audit.LogEventRequest{
			EventType:     "login",
			Action:        "saml_validation_failed",
			IPAddress:     c.ClientIP(),
			UserAgent:     c.Request.UserAgent(),
			CorrelationID: middleware.GetCorrelationID(c),
			Severity:      "error",
			Details:       fmt.Sprintf(`{"error": "%s"}`, err.Error()),
		})
		h.renderError(c, http.StatusBadRequest, "SAML authentication failed")
		return
	}

	if !validateResp.Valid {
		h.renderError(c, http.StatusBadRequest, "SAML assertion validation failed")
		return
	}

	h.service.LogAuditEvent(ctx, audit.LogEventRequest{
		UserID:        validateResp.UserID,
		EventType:     "login",
		Action:        "saml_validated",
		IPAddress:     c.ClientIP(),
		UserAgent:     c.Request.UserAgent(),
		CorrelationID: middleware.GetCorrelationID(c),
		Severity:      "info",
	})

	h.renderMFAChallenge(c, MFAChallengeData{
		UserID:     validateResp.UserID,
		Email:      validateResp.Email,
		Method:     "totp",
		RelayState: relayState,
		CSRFToken:  middleware.GetRequestID(c),
		Message:    "Enter your verification code",
		ExpiresIn:  30,
	})
}

// MFAVerify handles POST /mfa/verify — processes the MFA challenge form.
func (h *Handler) MFAVerify(c *gin.Context) {
	var req MFASubmitRequest
	if err := c.ShouldBind(&req); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}

	ctx := c.Request.Context()

	verifyResp, err := h.service.VerifyMFA(ctx, intmfa.VerifyRequest{
		UserID:            req.UserID,
		Code:              req.Code,
		Method:            req.Method,
		TrustDevice:       req.TrustDevice,
		DeviceFingerprint: req.DeviceFingerprint,
	})
	if err != nil {
		h.logger.Warn("MFA verification failed",
			zap.String("user_id", req.UserID),
			zap.Error(err),
		)
		h.service.LogAuditEvent(ctx, audit.LogEventRequest{
			UserID:        req.UserID,
			EventType:     "mfa",
			Action:        "mfa_verification_failed",
			IPAddress:     c.ClientIP(),
			UserAgent:     c.Request.UserAgent(),
			CorrelationID: middleware.GetCorrelationID(c),
			Severity:      "warn",
		})
		h.renderMFAChallenge(c, MFAChallengeData{
			UserID:     req.UserID,
			Email:      req.Email,
			Method:     req.Method,
			RelayState: req.RelayState,
			CSRFToken:  middleware.GetRequestID(c),
			Message:    "Invalid code. Please try again.",
		})
		return
	}

	if !verifyResp.Verified {
		h.renderMFAChallenge(c, MFAChallengeData{
			UserID:     req.UserID,
			Email:      req.Email,
			Method:     req.Method,
			RelayState: req.RelayState,
			CSRFToken:  middleware.GetRequestID(c),
			Message:    "Verification failed. Please try again.",
		})
		return
	}

	h.service.LogAuditEvent(ctx, audit.LogEventRequest{
		UserID:        req.UserID,
		EventType:     "mfa",
		Action:        "mfa_verified",
		IPAddress:     c.ClientIP(),
		UserAgent:     c.Request.UserAgent(),
		CorrelationID: middleware.GetCorrelationID(c),
		Severity:      "info",
	})

	sessResp, err := h.service.CreateSession(ctx, intsess.CreateSessionRequest{
		UserID:    req.UserID,
		IPAddress: c.ClientIP(),
		UserAgent: c.Request.UserAgent(),
	})
	if err != nil {
		h.logger.Error("session creation failed", zap.Error(err))
		h.renderError(c, http.StatusInternalServerError, "Failed to create session")
		return
	}

	email := req.Email
	if email == "" {
		email = req.UserID + "@samlguard.local"
	}

	assertionResp, err := h.service.GenerateAssertion(ctx, auth.GenerateAssertionRequest{
		UserID:      req.UserID,
		Email:       email,
		DisplayName: req.UserID,
		NameID:      req.UserID,
		SPEntityID:  h.service.samlCfg.EntityID,
		SPACSURL:    h.service.samlCfg.ACSURL,
		Audience:    h.service.samlCfg.EntityID,
		RelayState:  req.RelayState,
		Attributes: map[string]string{
			"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name":         req.UserID,
			"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": email,
			"http://schemas.xmlsoap.org/claims/CommonName":                       req.UserID,
			"http://schemas.xmlsoap.org/claims/Group":                            "Admin",
		},
	})
	if err != nil {
		h.logger.Error("assertion generation failed", zap.Error(err))
		h.renderError(c, http.StatusInternalServerError, "Failed to generate SAML assertion")
		return
	}

	h.service.LogAuditEvent(ctx, audit.LogEventRequest{
		UserID:        req.UserID,
		EventType:     "login",
		Action:        "login_success",
		IPAddress:     c.ClientIP(),
		UserAgent:     c.Request.UserAgent(),
		CorrelationID: middleware.GetCorrelationID(c),
		Severity:      "info",
		Details:       fmt.Sprintf(`{"session_id": "%s"}`, sessResp.SessionID),
	})

	h.renderSAMLPostForm(c, SAMLPostFormData{
		Destination:  assertionResp.Destination,
		SAMLResponse: assertionResp.SAMLResponse,
		RelayState:   assertionResp.RelayState,
	})
}

// Metadata handles GET /metadata — serves the proxy IdP SAML metadata XML.
func (h *Handler) Metadata(c *gin.Context) {
	metadataXML, err := h.metadataGen.GenerateIdPMetadata()
	if err != nil {
		h.logger.Error("metadata generation failed", zap.Error(err))
		utils.ErrorResponse(c, http.StatusInternalServerError, "METADATA_FAILED", "Failed to generate metadata")
		return
	}

	c.Data(http.StatusOK, "application/samlmetadata+xml", metadataXML)
}

// Logout handles GET /logout — destroys session and redirects.
func (h *Handler) Logout(c *gin.Context) {
	sessionID, _ := c.Cookie("samlguard_session")

	if sessionID != "" {
		ctx := c.Request.Context()

		h.service.LogAuditEvent(ctx, audit.LogEventRequest{
			EventType:     "logout",
			Action:        "logout_initiated",
			IPAddress:     c.ClientIP(),
			UserAgent:     c.Request.UserAgent(),
			CorrelationID: middleware.GetCorrelationID(c),
			Severity:      "info",
		})
	}

	c.SetCookie("samlguard_session", "", -1, "/", "", true, true)

	redirectURL := c.Query("redirect")
	if redirectURL == "" {
		redirectURL = "/login"
	}

	c.Redirect(http.StatusFound, redirectURL)
}

// Health handles GET /health — returns service health status.
func (h *Handler) Health(c *gin.Context) {
	c.JSON(http.StatusOK, HealthResponse{
		Status:  "healthy",
		Service: "gateway",
		Version: "1.0.0",
	})
}

func (h *Handler) renderMFAChallenge(c *gin.Context, data MFAChallengeData) {
	c.Header("Content-Type", "text/html; charset=utf-8")
	if h.templates != nil {
		if err := h.templates.ExecuteTemplate(c.Writer, "mfa_challenge.html", data); err != nil {
			h.logger.Error("template render failed", zap.Error(err))
			c.String(http.StatusInternalServerError, "Internal error")
		}
		return
	}

	c.String(http.StatusOK, renderInlineMFAPage(data))
}

func (h *Handler) renderError(c *gin.Context, status int, message string) {
	c.Header("Content-Type", "text/html; charset=utf-8")
	if h.templates != nil {
		if err := h.templates.ExecuteTemplate(c.Writer, "error.html", gin.H{"message": message, "status": status}); err != nil {
			h.logger.Error("error template render failed", zap.Error(err))
		}
		return
	}
	c.String(status, fmt.Sprintf("<html><body><h1>Error %d</h1><p>%s</p></body></html>", status, message))
}

func (h *Handler) renderSAMLPostForm(c *gin.Context, data SAMLPostFormData) {
	html := fmt.Sprintf(`<!DOCTYPE html>
<html><head><title>SAMLGuard - Redirecting</title></head>
<body onload="document.forms[0].submit()">
<noscript><p>JavaScript is required. Please click the button below.</p></noscript>
<form method="POST" action="%s">
<input type="hidden" name="SAMLResponse" value="%s"/>
<input type="hidden" name="RelayState" value="%s"/>
<noscript><button type="submit">Continue</button></noscript>
</form></body></html>`, data.Destination, data.SAMLResponse, data.RelayState)

	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(html))
}

func renderInlineMFAPage(data MFAChallengeData) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html><head><title>SAMLGuard - MFA Verification</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#0f172a;color:#e2e8f0}
.card{background:#1e293b;border-radius:12px;padding:2rem;max-width:400px;width:90%%;box-shadow:0 25px 50px -12px rgba(0,0,0,.5)}
h1{font-size:1.5rem;margin:0 0 .5rem;color:#38bdf8}
p{color:#94a3b8;margin:0 0 1.5rem}
.msg{padding:.75rem;border-radius:8px;background:#1e3a5f;border:1px solid #2563eb;margin-bottom:1rem;font-size:.875rem}
input[type=text]{width:100%%;padding:.75rem;border:1px solid #334155;border-radius:8px;background:#0f172a;color:#e2e8f0;font-size:1.25rem;letter-spacing:.3em;text-align:center;box-sizing:border-box;margin-bottom:1rem}
input[type=text]:focus{outline:none;border-color:#38bdf8;box-shadow:0 0 0 3px rgba(56,189,248,.2)}
button{width:100%%;padding:.75rem;border:none;border-radius:8px;background:#2563eb;color:white;font-size:1rem;font-weight:600;cursor:pointer;transition:background .2s}
button:hover{background:#1d4ed8}
.footer{text-align:center;margin-top:1rem;font-size:.75rem;color:#475569}
</style></head>
<body><div class="card">
<h1>🔐 MFA Verification</h1>
<p>%s</p>
<div class="msg">%s</div>
<form method="POST" action="/mfa/verify">
<input type="hidden" name="user_id" value="%s"/>
<input type="hidden" name="email" value="%s"/>
<input type="hidden" name="method" value="%s"/>
<input type="hidden" name="relay_state" value="%s"/>
<input type="hidden" name="csrf_token" value="%s"/>
<input type="text" name="code" placeholder="000000" maxlength="10" autocomplete="one-time-code" autofocus required/>
<button type="submit">Verify</button>
</form>
<div class="footer">SAMLGuard Enterprise MFA Gateway</div>
</div></body></html>`,
		data.Email, data.Message, data.UserID, data.Email, data.Method, data.RelayState, data.CSRFToken)
}
