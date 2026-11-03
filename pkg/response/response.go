package response

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/hidayat-SE/samlguard/pkg/errors"
)

type APIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   *APIError   `json:"error,omitempty"`
}

type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func Success(c *gin.Context, data interface{}) {
	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Data:    data,
	})
}

func Error(c *gin.Context, status int, err error) {
	apiErr := &APIError{
		Code:    "ERR-UNKNOWN",
		Message: err.Error(),
	}

	if appErr, ok := err.(*errors.AppError); ok {
		apiErr.Code = string(appErr.Code)
		apiErr.Message = appErr.Message
	}

	c.JSON(status, APIResponse{
		Success: false,
		Error:   apiErr,
	})
}
