package middleware

import (
	"github.com/gin-gonic/gin"
)

// SecurityHeaders sets defense-in-depth HTTP security headers on every response.
// These headers protect against common web attacks including XSS, clickjacking,
// MIME sniffing, and protocol downgrade attacks.
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; frame-ancestors 'none'; form-action *")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		c.Header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
		c.Header("Pragma", "no-cache")

		c.Next()
	}
}
