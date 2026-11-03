package gateway

import (
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/hidayat-SE/samlguard/pkg/middleware"
)

// SetupRouter configures the Gin router for the Gateway service.
func SetupRouter(handler *Handler, log *zap.Logger) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)

	router := gin.New()

	router.Use(
		middleware.CorrelationID(),
		middleware.RequestLogger(log),
		middleware.SecurityHeaders(),
		middleware.Recovery(log),
	)

	router.GET("/login", handler.Login)
	router.POST("/login", handler.Login)
	router.GET("/mock-idp-login", handler.MockIdPLogin)
	router.POST("/acs", handler.ACS)
	router.POST("/mfa/verify", handler.MFAVerify)
	router.GET("/metadata", handler.Metadata)
	router.GET("/logout", handler.Logout)
	router.GET("/health", handler.Health)

	return router
}
