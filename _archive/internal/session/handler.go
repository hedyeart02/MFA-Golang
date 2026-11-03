package session

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/hidayat-SE/samlguard/pkg/utils"
)

// Handler handles HTTP requests for the session service.
type Handler struct {
	service *Service
}

// NewHandler creates a new session handler.
func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

// GetSession handles GET /session?id=<session_id>.
func (h *Handler) GetSession(c *gin.Context) {
	sessionID := c.Query("id")
	if sessionID == "" {
		utils.ErrorResponse(c, http.StatusBadRequest, "MISSING_ID", "Session ID is required")
		return
	}

	info, err := h.service.GetSessionInfo(c.Request.Context(), sessionID)
	if err != nil {
		if appErr, ok := err.(*utils.AppError); ok {
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
			return
		}
		utils.ErrorResponse(c, http.StatusInternalServerError, "QUERY_FAILED", "Failed to get session")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, info)
}

// CreateSession handles POST /session.
func (h *Handler) CreateSession(c *gin.Context) {
	var req CreateSessionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}

	sess, err := h.service.CreateSession(c.Request.Context(), req)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "CREATE_FAILED", "Failed to create session")
		return
	}

	utils.SuccessResponse(c, http.StatusCreated, CreateSessionResponse{
		SessionID: sess.ID,
		ExpiresAt: sess.ExpiresAt,
	})
}

// DeleteSession handles DELETE /session?id=<session_id>.
func (h *Handler) DeleteSession(c *gin.Context) {
	sessionID := c.Query("id")
	if sessionID == "" {
		utils.ErrorResponse(c, http.StatusBadRequest, "MISSING_ID", "Session ID is required")
		return
	}

	if err := h.service.RevokeSession(c.Request.Context(), sessionID); err != nil {
		if appErr, ok := err.(*utils.AppError); ok {
			utils.ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
			return
		}
		utils.ErrorResponse(c, http.StatusInternalServerError, "REVOKE_FAILED", "Failed to revoke session")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, gin.H{"message": "Session revoked"})
}

// DeleteUserSessions handles DELETE /session/user?user_id=<user_id>.
func (h *Handler) DeleteUserSessions(c *gin.Context) {
	userID := c.Query("user_id")
	if userID == "" {
		utils.ErrorResponse(c, http.StatusBadRequest, "MISSING_USER_ID", "User ID is required")
		return
	}

	if err := h.service.RevokeAllUserSessions(c.Request.Context(), userID); err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "REVOKE_FAILED", "Failed to revoke sessions")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, gin.H{"message": "All sessions revoked"})
}
