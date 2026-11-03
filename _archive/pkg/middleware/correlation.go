// Package middleware provides Gin middleware for correlation tracking,
// recovery, security headers, and structured request logging.
package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/hidayat-SE/samlguard/pkg/logger"
)

const (
	// HeaderCorrelationID is the HTTP header for correlation tracking.
	HeaderCorrelationID = "X-Correlation-ID"

	// HeaderRequestID is the HTTP header for request identification.
	HeaderRequestID = "X-Request-ID"

	// ContextCorrelationID is the Gin context key for correlation ID.
	ContextCorrelationID = "correlation_id"

	// ContextRequestID is the Gin context key for request ID.
	ContextRequestID = "request_id"
)

// CorrelationID extracts or generates X-Correlation-ID and X-Request-ID headers.
// These IDs are stored in both the Gin context and the Go context for
// downstream logging and inter-service propagation.
func CorrelationID() gin.HandlerFunc {
	return func(c *gin.Context) {
		correlationID := c.GetHeader(HeaderCorrelationID)
		if correlationID == "" {
			correlationID = uuid.New().String()
		}

		requestID := uuid.New().String()

		c.Set(ContextCorrelationID, correlationID)
		c.Set(ContextRequestID, requestID)

		ctx := c.Request.Context()
		ctx = logger.WithCorrelationID(ctx, correlationID)
		ctx = logger.WithRequestID(ctx, requestID)
		c.Request = c.Request.WithContext(ctx)

		c.Header(HeaderCorrelationID, correlationID)
		c.Header(HeaderRequestID, requestID)

		c.Next()
	}
}

// GetCorrelationID retrieves the correlation ID from the Gin context.
func GetCorrelationID(c *gin.Context) string {
	if id, exists := c.Get(ContextCorrelationID); exists {
		if s, ok := id.(string); ok {
			return s
		}
	}
	return ""
}

// GetRequestID retrieves the request ID from the Gin context.
func GetRequestID(c *gin.Context) string {
	if id, exists := c.Get(ContextRequestID); exists {
		if s, ok := id.(string); ok {
			return s
		}
	}
	return ""
}
