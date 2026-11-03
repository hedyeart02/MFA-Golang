package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/hidayat-SE/samlguard/pkg/utils"
)

// Recovery catches panics in handlers and returns a structured 500 response.
// Stack traces are logged but never exposed to clients.
func Recovery(log *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if r := recover(); r != nil {
				correlationID := GetCorrelationID(c)
				requestID := GetRequestID(c)

				log.Error("panic recovered",
					zap.Any("panic", r),
					zap.String("method", c.Request.Method),
					zap.String("path", c.Request.URL.Path),
					zap.String("client_ip", c.ClientIP()),
					zap.String("correlation_id", correlationID),
					zap.String("request_id", requestID),
				)

				utils.ErrorResponse(c, http.StatusInternalServerError,
					"INTERNAL_ERROR", "An internal error occurred")
				c.Abort()
			}
		}()

		c.Next()
	}
}
