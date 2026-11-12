package middleware

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/hidayat-SE/samlguard/internal/shared/context"
	"github.com/hidayat-SE/samlguard/pkg/logger"
	"github.com/hidayat-SE/samlguard/pkg/metrics"
	"github.com/hidayat-SE/samlguard/pkg/ratelimiter"
	"go.uber.org/zap"
)

// SecurityHeadersOptions configures dynamic HTTP security headers and CSP behavior.
type SecurityHeadersOptions struct {
	TLSEnabled      bool
	TrustProxyProto bool
	FormActionFunc  func() string
}

func sanitizeTraceHeader(val string) string {
	trimmed := strings.TrimSpace(val)
	if trimmed == "" || len(trimmed) > 128 {
		return uuid.New().String()
	}
	for i := 0; i < len(trimmed); i++ {
		ch := trimmed[i]
		isAlphaNum := (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')
		if !isAlphaNum && ch != '-' && ch != '_' && ch != '.' {
			return uuid.New().String()
		}
	}
	return trimmed
}

func Recovery() gin.HandlerFunc {
	return gin.Recovery()
}

func ContextInject(baseLogger *logger.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		reqID := sanitizeTraceHeader(c.GetHeader("X-Request-ID"))
		corrID := sanitizeTraceHeader(c.GetHeader("X-Correlation-ID"))
		traceID := sanitizeTraceHeader(c.GetHeader("X-Trace-ID"))
		spanID := sanitizeTraceHeader(c.GetHeader("X-Span-ID"))

		// Inject sanitized identifiers so downstream sees them without header/log injection risk
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

// SecurityHeaders applies strict default HTTP security headers.
func SecurityHeaders() gin.HandlerFunc {
	return SecurityHeadersWithConfig(SecurityHeadersOptions{})
}

// SecurityHeadersWithConfig applies strict HTTP security headers, dynamic CSP form-action
// allowlisting, conditional HSTS, and no-store caching on dynamic routes.
func SecurityHeadersWithConfig(opts SecurityHeadersOptions) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "0")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		c.Header("Cross-Origin-Opener-Policy", "same-origin")
		c.Header("Cross-Origin-Resource-Policy", "same-origin")

		isHTTPS := opts.TLSEnabled || c.Request.TLS != nil ||
			(opts.TrustProxyProto && strings.EqualFold(c.GetHeader("X-Forwarded-Proto"), "https"))
		if isHTTPS {
			c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		}

		formAction := "'self'"
		if opts.FormActionFunc != nil {
			if resolved := strings.TrimSpace(opts.FormActionFunc()); resolved != "" {
				formAction = resolved
			}
		}
		csp := fmt.Sprintf(
			"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action %s",
			formAction,
		)
		c.Header("Content-Security-Policy", csp)

		path := c.Request.URL.Path
		if !strings.HasPrefix(path, "/static/") && !strings.HasPrefix(path, "/assets/") && !strings.HasPrefix(path, "/branding/assets/") && path != "/favicon.ico" {
			c.Header("Cache-Control", "no-store, no-cache, must-revalidate, private")
			c.Header("Pragma", "no-cache")
		}

		// Suppress Server header if injected
		c.Header("Server", "")

		c.Next()
	}
}

// RateLimitMiddleware enforces per-client-IP rate limiting for a route scope.
func RateLimitMiddleware(limiter ratelimiter.DetailedRateLimiter, scope string, log *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		if limiter == nil {
			c.Next()
			return
		}
		key := scope + ":" + c.ClientIP()
		allowed, retryAfter, _, err := limiter.AllowDetailed(c.Request.Context(), key)
		if err != nil || !allowed {
			secs := int(retryAfter.Seconds())
			if secs < 1 {
				secs = 1
			}
			c.Header("Retry-After", strconv.Itoa(secs))
			if log != nil {
				log.Warn("rate limit exceeded",
					zap.String("scope", scope),
					zap.String("client_ip", c.ClientIP()),
					zap.String("path", c.Request.URL.Path),
				)
			}
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"success": false,
				"error":   "Too many requests. Please wait before trying again.",
			})
			return
		}
		c.Next()
	}
}

// MaxBodyBytesMiddleware caps incoming request bodies to defend against payload flooding.
func MaxBodyBytesMiddleware(maxBytes int64) gin.HandlerFunc {
	return MaxBodyBytesWithOverrides(maxBytes, nil)
}

// MaxBodyBytesWithOverrides caps incoming request bodies, applying route-specific overrides when present.
func MaxBodyBytesWithOverrides(defaultMaxBytes int64, overrides map[string]int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		maxBytes := defaultMaxBytes
		if overrides != nil {
			if override, ok := overrides[c.Request.URL.Path]; ok && override > 0 {
				maxBytes = override
			}
		}
		if maxBytes > 0 && c.Request.Body != nil {
			if c.Request.ContentLength > maxBytes {
				c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{
					"success": false,
					"error":   "Request payload exceeds maximum allowed size.",
				})
				return
			}
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)
		}
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
