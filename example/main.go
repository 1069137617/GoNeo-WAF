package main

import (
	"fmt"
	"time"

	"github.com/waf-go/waf/core"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func main() {
	logger, _ := zap.NewProduction()
	defer logger.Sync()

	zap.ReplaceGlobals(logger)

	cfg := core.NewConfigBuilder().
		Enabled(true).
		WithCCProtection(true, 60, 10*time.Minute).
		WithAttackProtection(5, 1*time.Hour, 10*time.Minute).
		WithSQLInjection(true).
		WithUAFilter(true, nil).
		WithXSSProtection(true).
		WithSSRFProtection(true).
		WithCRLFProtection(true).
		WithZeroDayProtection(true).
		WithPathTraversalProtection(true).
		WithSensitiveParamProtection(true).
		WithMaxRequestSize(2 * 1024 * 1024).
		WithIP2RegionDBPath("./data/ip2region_v4.xdb").
		Build()

	wafInstance := core.New(cfg)

	r := gin.Default()

	r.Use(wafInstance.Middleware())

	r.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "pong",
		})
	})

	r.GET("/api/data", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"data": "some data",
		})
	})

	r.POST("/api/submit", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status": "success",
		})
	})

	r.GET("/waf/stats", func(c *gin.Context) {
		stats := wafInstance.GetStats()
		c.JSON(200, stats)
	})

	fmt.Println("WAF-protected server starting on :8080")
	if err := r.Run(":8080"); err != nil {
		logger.Fatal("server failed to start", zap.Error(err))
	}
}
