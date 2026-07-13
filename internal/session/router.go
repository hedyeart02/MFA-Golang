package session

import (
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/hidayat-SE/samlguard/pkg/middleware"
)

// SetupRouter configures the Gin router for the session service.
func SetupRouter(handler *Handler, log *zap.Logger, apiKey string) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)

	router := gin.New()

	router.Use(
		middleware.CorrelationID(),
		middleware.RequestLogger(log),
		middleware.SecurityHeaders(),
		middleware.Recovery(log),
	)

	api := router.Group("/api/v1")
	{
		api.Use(middleware.APIKeyAuth(apiKey))

		api.GET("/session", handler.GetSession)
		api.POST("/session", handler.CreateSession)
		api.DELETE("/session", handler.DeleteSession)
		api.DELETE("/session/user", handler.DeleteUserSessions)
	}

	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "healthy", "service": "session"})
	})

	return router
}
