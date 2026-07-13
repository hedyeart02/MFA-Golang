// Package utils provides shared utility types for consistent API responses,
// application errors, cryptographic operations, and input validation.
package utils

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// APIResponse is the standardized response envelope for all API endpoints.
type APIResponse struct {
	Success   bool        `json:"success"`
	Data      interface{} `json:"data,omitempty"`
	Error     *APIError   `json:"error,omitempty"`
	RequestID string      `json:"request_id,omitempty"`
}

// APIError represents a structured error in an API response.
type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// PaginatedData wraps a paginated list response.
type PaginatedData struct {
	Items      interface{} `json:"items"`
	Total      int64       `json:"total"`
	Page       int         `json:"page"`
	PageSize   int         `json:"page_size"`
	TotalPages int         `json:"total_pages"`
}

// SuccessResponse sends a standardized success response.
func SuccessResponse(c *gin.Context, statusCode int, data interface{}) {
	requestID := ""
	if id, exists := c.Get("request_id"); exists {
		if s, ok := id.(string); ok {
			requestID = s
		}
	}

	c.JSON(statusCode, APIResponse{
		Success:   true,
		Data:      data,
		RequestID: requestID,
	})
}

// ErrorResponse sends a standardized error response.
func ErrorResponse(c *gin.Context, statusCode int, code, message string) {
	requestID := ""
	if id, exists := c.Get("request_id"); exists {
		if s, ok := id.(string); ok {
			requestID = s
		}
	}

	c.JSON(statusCode, APIResponse{
		Success: false,
		Error: &APIError{
			Code:    code,
			Message: message,
		},
		RequestID: requestID,
	})
}

// PaginatedResponse sends a standardized paginated response.
func PaginatedResponse(c *gin.Context, items interface{}, total int64, page, pageSize int) {
	totalPages := int(total) / pageSize
	if int(total)%pageSize > 0 {
		totalPages++
	}

	SuccessResponse(c, http.StatusOK, PaginatedData{
		Items:      items,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	})
}
