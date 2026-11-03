package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/hidayat-SE/samlguard/internal/gateway/pipeline"
	"github.com/hidayat-SE/samlguard/pkg/response"
)

type SAMLHandler struct {
	pipeline pipeline.AuthnPipeline
}

func NewSAMLHandler(p pipeline.AuthnPipeline) *SAMLHandler {
	return &SAMLHandler{pipeline: p}
}

// HandleSSO accepts GET /saml/sso (HTTP-Redirect)
func (h *SAMLHandler) HandleSSO(c *gin.Context) {
	authCtx, err := h.pipeline.Execute(c.Request.Context(), c.Request)
	if err != nil {
		response.Error(c, http.StatusBadRequest, err)
		return
	}

	// Milestone 6: Return diagnostic information for ITA compatibility verification
	c.JSON(http.StatusNotImplemented, gin.H{
		"status":      "501 Not Implemented: SSO flow terminates here (Proxy generation not implemented)",
		"request_id":  authCtx.RequestID,
		"issuer":      authCtx.Issuer,
		"destination": authCtx.Destination,
		"is_valid":    authCtx.ValidationResult.IsValid,
	})
}

// HandleACS accepts POST /saml/acs (HTTP-POST)
func (h *SAMLHandler) HandleACS(c *gin.Context) {
	authCtx, err := h.pipeline.Execute(c.Request.Context(), c.Request)
	if err != nil {
		response.Error(c, http.StatusBadRequest, err)
		return
	}

	// Milestone 6: Return diagnostic information for ITA compatibility verification
	c.JSON(http.StatusNotImplemented, gin.H{
		"status":      "501 Not Implemented: ACS flow terminates here (Proxy generation not implemented)",
		"request_id":  authCtx.RequestID,
		"issuer":      authCtx.Issuer,
		"destination": authCtx.Destination,
		"is_valid":    authCtx.ValidationResult.IsValid,
	})
}

// HandleMetadata accepts GET /saml/metadata
func (h *SAMLHandler) HandleMetadata(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"status": "501 Not Implemented: Metadata generation pending"})
}
