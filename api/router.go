package api

import (
	"net/http"

	"github.com/danmuck/the_cookie_jar/api/controllers"
	"github.com/danmuck/the_cookie_jar/api/middleware"
	"github.com/gin-gonic/gin"
)

func ServeHTML_demo(router *gin.Engine) {
	router.GET("/users/posts", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.tmpl", gin.H{
			"title":     "User Posts [tmp]",
			"sub_title": "Some Recent Post Maybe",
			"body":      "Some post text from a user that was in their recent post",
		})
	})
	router.GET("/users/info/:username", func(c *gin.Context) {
		username := c.Param("username")
		c.HTML(http.StatusOK, "index.tmpl", gin.H{
			"title":     "User Info",
			"sub_title": username,
			"body":      "Some user info.",
		})
	})
}

func BaseRouter() *gin.Engine {
	// init router
	router := gin.Default()
	// load templates (will error if none exist at path)
	router.LoadHTMLGlob("/root/public/templates/*")

	go ServeHTML_demo(router)

	// Public routes
	public := router.Group("/")
	public.Use(middleware.Logger())
	{
		public.GET("/", controllers.Root)
		public.POST("/register", controllers.PingPong)
		public.POST("/login", controllers.PingPong)
	}
	// Protected routes
	protected := router.Group("/users")
	protected.Use(middleware.AuthMiddleware())
	{
		protected.GET("/", controllers.PingPong)
		protected.POST("/:username", controllers.POST_user)
		protected.GET("/:username", controllers.GET_username)
		protected.PUT("/:username", controllers.Root)
		protected.DELETE("/:username", controllers.Root)
	}

	return router
}
