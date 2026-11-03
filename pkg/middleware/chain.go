package middleware

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/hidayat-SE/samlguard/internal/shared/context"
	"github.com/hidayat-SE/samlguard/pkg/logger"
	"github.com/hidayat-SE/samlguard/pkg/metrics"
	"go.uber.org/zap"
)

func Recovery() gin.HandlerFunc {
	return gin.Recovery()
}

func ContextInject(baseLogger *logger.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		reqID := c.GetHeader("X-Request-ID")
		if reqID == "" {
			reqID = uuid.New().String()
		}
		
		corrID := c.GetHeader("X-Correlation-ID")
		if corrID == "" {
			corrID = uuid.New().String()
		}

		traceID := c.GetHeader("X-Trace-ID")
		if traceID == "" {
			traceID = uuid.New().String()
		}

		spanID := c.GetHeader("X-Span-ID")
		if spanID == "" {
			spanID = uuid.New().String()
		}

		// Inject into header so downstream sees it
		c.Header("X-Request-ID", reqID)
		c.Header("X-Correlation-ID", corrID)

		reqCtx := &context.RequestContext{
			RequestID:     reqID,
			CorrelationID: corrID,
			TraceID:       traceID,
			SpanID:        spanID,
			ClientIP:      c.ClientIP(),
			UserAgent:     c.Request.UserAgent(),
			Logger:        baseLogger,
		}

		c.Set("ReqContext", reqCtx)
		c.Next()
	}
}

func Logger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		duration := time.Since(start)

		if ctxVal, ok := c.Get("ReqContext"); ok {
			if reqCtx, ok := ctxVal.(*context.RequestContext); ok {
				status := c.Writer.Status()
				metrics.RequestDuration.WithLabelValues(c.Request.Method, c.FullPath(), strconv.Itoa(status)).Observe(duration.Seconds())
				
				reqCtx.Logger.System().Info("http request",
					zap.String("method", c.Request.Method),
					zap.String("path", c.Request.URL.Path),
					zap.Int("status", status),
					zap.Duration("latency", duration),
					zap.String("request_id", reqCtx.RequestID),
					zap.String("client_ip", reqCtx.ClientIP),
				)
			}
		}
	}
}

func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; frame-ancestors 'none'; form-action *")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		
		// Remove server header (Gin does not set it by default but ensure it's empty if injected)
		c.Header("Server", "")

		c.Next()
	}
}

func IdentityMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extracts identity but does not enforce authentication
		sessionCookie, err := c.Cookie("session_id")
		if err == nil && sessionCookie != "" {
			if ctxVal, ok := c.Get("ReqContext"); ok {
				if reqCtx, ok := ctxVal.(*context.RequestContext); ok {
					reqCtx.SessionID = sessionCookie
				}
			}
		}
		c.Next()
	}
}
