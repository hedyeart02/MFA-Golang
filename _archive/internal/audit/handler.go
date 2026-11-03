package audit

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/hidayat-SE/samlguard/pkg/utils"
)

// Handler handles HTTP requests for the audit service.
type Handler struct {
	service *Service
}

// NewHandler creates a new audit handler.
func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

// GetLogs handles GET /logs with pagination and filtering.
func (h *Handler) GetLogs(c *gin.Context) {
	var params LogQueryParams
	if err := c.ShouldBindQuery(&params); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "INVALID_PARAMS", err.Error())
		return
	}

	logs, total, err := h.service.QueryLogs(c.Request.Context(), params)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "QUERY_FAILED", "Failed to query audit logs")
		return
	}

	utils.PaginatedResponse(c, logs, total, params.Page, params.PageSize)
}

// GetEvents handles GET /events returning distinct event types.
func (h *Handler) GetEvents(c *gin.Context) {
	types, err := h.service.GetEventTypes(c.Request.Context())
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "QUERY_FAILED", "Failed to get event types")
		return
	}

	utils.SuccessResponse(c, http.StatusOK, EventTypeResponse{EventTypes: types})
}

// CreateLog handles POST /logs for internal service audit logging.
func (h *Handler) CreateLog(c *gin.Context) {
	var req LogEventRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}

	resp, err := h.service.LogEvent(c.Request.Context(), req)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "LOG_FAILED", "Failed to create audit log")
		return
	}

	utils.SuccessResponse(c, http.StatusCreated, resp)
}
