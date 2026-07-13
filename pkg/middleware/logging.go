package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// RequestLogger logs structured information about every HTTP request and response.
// It captures method, path, status, latency, client IP, and IDs, but never
// logs request bodies to prevent secret leakage.
func RequestLogger(log *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		c.Next()

		latency := time.Since(start)
		statusCode := c.Writer.Status()

		fields := []zap.Field{
			zap.String("method", c.Request.Method),
			zap.String("path", c.Request.URL.Path),
			zap.String("query", c.Request.URL.RawQuery),
			zap.Int("status", statusCode),
			zap.Duration("latency", latency),
			zap.String("client_ip", c.ClientIP()),
			zap.String("user_agent", c.Request.UserAgent()),
			zap.Int("body_size", c.Writer.Size()),
			zap.String("correlation_id", GetCorrelationID(c)),
			zap.String("request_id", GetRequestID(c)),
		}

		switch {
		case statusCode >= 500:
			log.Error("server error", fields...)
		case statusCode >= 400:
			log.Warn("client error", fields...)
		default:
			log.Info("request completed", fields...)
		}
	}
}
