package mfa

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/hidayat-SE/samlguard/pkg/utils"
)

// Handler handles HTTP requests for the MFA service.
type Handler struct {
	service *Service
}

// NewHandler creates a new MFA handler.
func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

// Enroll handles POST /enroll — enrolls a user in MFA.
func (h *Handler) Enroll(c *gin.Context) {
	var req EnrollRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}

	if err := utils.ValidateMFAMethod(req.Method); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "INVALID_METHOD", err.Error())
		return
	}

	resp, err := h.service.Enroll(c.Request.Context(), req)
	if err != nil {
		if appErr, ok := err.(*utils.AppError); ok {
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
			return
		}
		utils.ErrorResponse(c, http.StatusInternalServerError, "ENROLL_FAILED", "Failed to enroll MFA")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, resp)
}

// Request handles POST /request — sends an MFA challenge.
func (h *Handler) Request(c *gin.Context) {
	var req ChallengeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}

	resp, err := h.service.Challenge(c.Request.Context(), req)
	if err != nil {
		if appErr, ok := err.(*utils.AppError); ok {
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
			return
		}
		utils.ErrorResponse(c, http.StatusInternalServerError, "CHALLENGE_FAILED", "Failed to send MFA challenge")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, resp)
}

// Verify handles POST /verify — verifies an MFA code.
func (h *Handler) Verify(c *gin.Context) {
	var req VerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}

	if err := utils.ValidateOTP(req.Code); err != nil {
		if req.Method != "backup" {
			utils.ErrorResponse(c, http.StatusBadRequest, "INVALID_CODE", err.Error())
			return
		}
	}

	resp, err := h.service.Verify(c.Request.Context(), req)
	if err != nil {
		if appErr, ok := err.(*utils.AppError); ok {
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
			return
		}
		utils.ErrorResponse(c, http.StatusInternalServerError, "VERIFY_FAILED", "Failed to verify MFA code")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, resp)
}

// Disable handles POST /disable — disables MFA for a user.
func (h *Handler) Disable(c *gin.Context) {
	var req DisableRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}

	if err := h.service.Disable(c.Request.Context(), req); err != nil {
		if appErr, ok := err.(*utils.AppError); ok {
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
			return
		}
		utils.ErrorResponse(c, http.StatusInternalServerError, "DISABLE_FAILED", "Failed to disable MFA")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, gin.H{"message": "MFA disabled successfully"})
}
