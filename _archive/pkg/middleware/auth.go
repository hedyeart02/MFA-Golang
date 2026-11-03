package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/hidayat-SE/samlguard/pkg/utils"
)

// APIKeyAuth validates internal service-to-service API key authentication.
// The key must be provided in the Authorization header as "Bearer <key>".
func APIKeyAuth(validKey string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if validKey == "" {
			c.Next()
			return
		}

		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			utils.ErrorResponse(c, http.StatusUnauthorized,
				"MISSING_AUTH", "Authorization header is required")
			c.Abort()
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			utils.ErrorResponse(c, http.StatusUnauthorized,
				"INVALID_AUTH_FORMAT", "Authorization header must be 'Bearer <key>'")
			c.Abort()
			return
		}

		if parts[1] != validKey {
			utils.ErrorResponse(c, http.StatusForbidden,
				"INVALID_API_KEY", "Invalid API key")
			c.Abort()
			return
		}

		c.Next()
	}
}
