package main

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/casdoor/casdoor-go-sdk/casdoorsdk"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"

	"github.com/spf13/viper"
)

var db = make(map[string]string)

func setupRouter() *gin.Engine {
	// Disable Console Color
	// gin.DisableConsoleColor()
	r := gin.Default()

	// 定义 CORS 配置
	config := cors.DefaultConfig()
	config.AllowOrigins = []string{"http://localhost:3000", "http://127.0.0.1:3000"} // 允许的源
	config.AllowMethods = []string{"GET", "POST", "OPTIONS"}                         // 允许的方法
	config.AllowHeaders = []string{"Authorization", "Content-Type"}                  // 允许的请求头
	config.AllowCredentials = true

	r.Use(cors.New(config))
	r.POST("/api/signin", func(c *gin.Context) {
		code := c.Query("code")
		state := c.Query("state")

		token, err := casdoorsdk.GetOAuthToken(code, state)
		if err != nil {
			fmt.Println("GetOAuthToken() error", err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"code":    http.StatusInternalServerError,
				"message": "GetOAuthToken() error",
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"status": "ok",
			"data":   token.AccessToken,
		})
	})
	r.GET("/api/userinfo", func(c *gin.Context) {
		authHeader := c.Request.Header.Get("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"code":    http.StatusUnauthorized,
				"message": "authorization header is missing",
			})
			return
		}
		token := strings.Split(authHeader, "Bearer ")
		if len(token) != 2 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"code":    http.StatusUnauthorized,
				"message": "token is not valid Bearer token",
			})
			return
		}

		claims, err := casdoorsdk.ParseJwtToken(token[1])
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"code":    http.StatusUnauthorized,
				"message": err.Error(),
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"status": "ok",
			"data":   claims.User,
		})
	})

	return r
}

func init() {
	viper.SetConfigName("app")  // name of config file (without extension)
	viper.SetConfigType("yaml") // REQUIRED if the config file does not have the extension in the name
	viper.AddConfigPath(".")    // optionally look for config in the working directory
	err := viper.ReadInConfig() // Find and read the config file
	if err != nil {             // Handle errors reading the config file
		panic(fmt.Errorf("fatal error config file: %w", err))
	}
	casdoorsdk.InitConfig(
		viper.GetString("server.endpoint"),
		viper.GetString("server.client_id"),
		viper.GetString("server.client_secret"),
		viper.GetString("certificate"),
		viper.GetString("server.organization"),
		viper.GetString("server.application"),
	)
}

func main() {
	r := setupRouter()

	// Listen and Server in 0.0.0.0:8080
	r.Run(":8080")
}
