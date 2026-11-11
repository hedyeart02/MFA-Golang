package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/hidayat-SE/samlguard/pkg/logger"
	"github.com/hidayat-SE/samlguard/pkg/ratelimiter"
	"go.uber.org/zap"
)

func TestSecurityHeadersWithConfig_StrictCSPAndNoStore(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(SecurityHeadersWithConfig(SecurityHeadersOptions{
		TLSEnabled: false,
		FormActionFunc: func() string {
			return "'self' https://ita.example.com https://login.microsoftonline.com"
		},
	}))
	r.GET("/mfa", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	r.GET("/static/app.js", func(c *gin.Context) {
		c.Header("Cache-Control", "public, max-age=86400")
		c.String(http.StatusOK, "ok")
	})

	// Plain HTTP dynamic route: strict CSP without wildcard form-action, no-store, NO HSTS
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/mfa", nil)
	r.ServeHTTP(w, req)

	csp := w.Header().Get("Content-Security-Policy")
	if strings.Contains(csp, "form-action *") {
		t.Fatalf("CSP must not contain wildcard form-action *, got: %s", csp)
	}
	if !strings.Contains(csp, "form-action 'self' https://ita.example.com https://login.microsoftonline.com") {
		t.Fatalf("expected scoped form-action origins in CSP, got: %s", csp)
	}
	if !strings.Contains(csp, "object-src 'none'") || !strings.Contains(csp, "base-uri 'self'") {
		t.Fatalf("expected object-src 'none' and base-uri 'self' in CSP, got: %s", csp)
	}
	if !strings.Contains(w.Header().Get("Cache-Control"), "no-store") {
		t.Fatalf("expected no-store Cache-Control on dynamic route, got: %s", w.Header().Get("Cache-Control"))
	}
	if w.Header().Get("Strict-Transport-Security") != "" {
		t.Fatalf("expected no HSTS header on plain HTTP non-TLS response, got: %s", w.Header().Get("Strict-Transport-Security"))
	}
	if w.Header().Get("Cross-Origin-Opener-Policy") != "same-origin" {
		t.Fatalf("expected Cross-Origin-Opener-Policy: same-origin, got: %s", w.Header().Get("Cross-Origin-Opener-Policy"))
	}

	// Static route retains cacheable headers
	wStatic := httptest.NewRecorder()
	reqStatic := httptest.NewRequest(http.MethodGet, "/static/app.js", nil)
	r.ServeHTTP(wStatic, reqStatic)
	if !strings.Contains(wStatic.Header().Get("Cache-Control"), "max-age=86400") {
		t.Fatalf("expected static asset to keep public cache control, got: %s", wStatic.Header().Get("Cache-Control"))
	}
}

func TestContextInject_SanitizesTraceHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(ContextInject(logger.New(zap.NewNop())))
	r.GET("/ping", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	req.Header.Set("X-Request-ID", "valid-req_123.abc")
	req.Header.Set("X-Correlation-ID", "evil\r\nInjected: header")
	r.ServeHTTP(w, req)

	if got := w.Header().Get("X-Request-ID"); got != "valid-req_123.abc" {
		t.Fatalf("expected valid X-Request-ID preserved, got %q", got)
	}
	if corr := w.Header().Get("X-Correlation-ID"); corr == "" || strings.ContainsAny(corr, "\r\n ") {
		t.Fatalf("expected unsafe X-Correlation-ID to be replaced with sanitized UUID, got %q", corr)
	}
}

func TestRateLimitAndMaxBodyMiddlewares(t *testing.T) {
	gin.SetMode(gin.TestMode)
	limiter := ratelimiter.NewMemoryRateLimiter(2, time.Minute)
	r := gin.New()
	r.Use(MaxBodyBytesMiddleware(16))
	r.POST("/auth", RateLimitMiddleware(limiter, "auth", zap.NewNop()), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/auth", strings.NewReader("a=1"))
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 on request %d, got %d", i+1, w.Code)
		}
	}

	wLimited := httptest.NewRecorder()
	reqLimited := httptest.NewRequest(http.MethodPost, "/auth", strings.NewReader("a=1"))
	r.ServeHTTP(wLimited, reqLimited)
	if wLimited.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 on 3rd request, got %d", wLimited.Code)
	}
	if wLimited.Header().Get("Retry-After") == "" {
		t.Fatal("expected Retry-After header on 429 response")
	}

	wBig := httptest.NewRecorder()
	reqBig := httptest.NewRequest(http.MethodPost, "/auth", strings.NewReader(strings.Repeat("x", 64)))
	r.ServeHTTP(wBig, reqBig)
	if wBig.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 for oversized body, got %d", wBig.Code)
	}
}
