package main

import (
	"github.com/gin-gonic/gin"
	"github.com/hidayat-SE/samlguard/internal/gateway/handler"
	"github.com/hidayat-SE/samlguard/pkg/logger"
	"github.com/hidayat-SE/samlguard/pkg/middleware"
	"github.com/hidayat-SE/samlguard/pkg/response"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

// Version string populated at build time
var Version = "1.0.0-dev"

func main() {
	r := gin.Default()

	// Initialize structured logger
	zapLogger, _ := zap.NewProduction()
	defer zapLogger.Sync()
	appLogger := logger.New(zapLogger)

	// Set up router with middleware chain: Recovery -> RequestID/Context -> Logger -> SecurityHeaders -> Identity
	r.Use(middleware.Recovery())
	r.Use(middleware.ContextInject(appLogger))
	r.Use(middleware.Logger())
	r.Use(middleware.SecurityHeaders())
	r.Use(middleware.IdentityMiddleware())

	// Setup SAML Pipeline & Handler (Milestone 5)
	// (Using nil for pipeline stub as this initializes the routes, actual pipeline injection happens in Gateway setup)
	samlHandler := handler.NewSAMLHandler(nil)
	
	samlGroup := r.Group("/saml")
	{
		samlGroup.GET("/sso", samlHandler.HandleSSO)
		samlGroup.POST("/acs", samlHandler.HandleACS)
		samlGroup.GET("/metadata", samlHandler.HandleMetadata)
	}

	// Health endpoint
	r.GET("/health", func(c *gin.Context) {
		response.Success(c, gin.H{"status": "ok"})
	})

	// Ready endpoint
	r.GET("/ready", func(c *gin.Context) {
		response.Success(c, gin.H{"status": "ready"})
	})

	// Live endpoint
	r.GET("/live", func(c *gin.Context) {
		response.Success(c, gin.H{"status": "live"})
	})

	// Version endpoint
	r.GET("/version", func(c *gin.Context) {
		response.Success(c, gin.H{"version": Version})
	})

	// Metrics endpoint
	r.GET("/metrics", gin.WrapH(promhttp.Handler()))

	// Run the server
	_ = r.Run(":8080")
}
