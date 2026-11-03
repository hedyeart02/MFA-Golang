package auth

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/hidayat-SE/samlguard/pkg/utils"
)

// Handler handles HTTP requests for the auth service.
type Handler struct {
	service *Service
}

// NewHandler creates a new auth handler.
func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

// Validate handles POST /validate — validates a SAML response.
func (h *Handler) Validate(c *gin.Context) {
	var req ValidateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}

	resp, err := h.service.ValidateSAMLResponse(c.Request.Context(), req)
	if err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "VALIDATION_FAILED", err.Error())
		return
	}

	utils.SuccessResponse(c, http.StatusOK, resp)
}

// GenerateAssertion handles POST /assertion — generates a new signed SAML assertion.
func (h *Handler) GenerateAssertion(c *gin.Context) {
	var req GenerateAssertionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}

	if err := utils.ValidateEmail(req.Email); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "INVALID_EMAIL", err.Error())
		return
	}

	if err := utils.ValidateURL(req.SPACSURL); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "INVALID_ACS_URL", err.Error())
		return
	}

	resp, err := h.service.GenerateAssertion(c.Request.Context(), req)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "ASSERTION_FAILED", "Failed to generate assertion")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, resp)
}

// RegisterMetadata handles POST /metadata — registers SP or IdP metadata.
func (h *Handler) RegisterMetadata(c *gin.Context) {
	var req RegisterMetadataRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}

	if req.Type != "sp" && req.Type != "idp" {
		utils.ErrorResponse(c, http.StatusBadRequest, "INVALID_TYPE", "Type must be 'sp' or 'idp'")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, gin.H{
		"message":   "Metadata registered",
		"entity_id": req.EntityID,
		"type":      req.Type,
	})
}
