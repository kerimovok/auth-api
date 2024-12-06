package routes

import (
	"auth-api/internal/controllers"
	"auth-api/internal/middleware"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/monitor"
)

func SetupRoutes(app *fiber.App) {
	// API routes group
	api := app.Group("/api")
	v1 := api.Group("/v1")

	// Monitor route
	app.Get("/metrics", monitor.New())

	// Auth routes
	auth := v1.Group("/auth")

	// Public auth routes
	auth.Post("/register", controllers.Register)
	auth.Post("/login", controllers.Login)
	auth.Post("/request-password-reset", controllers.RequestPasswordReset)
	auth.Post("/reset-password", controllers.ResetPassword)
	auth.Get("/confirm-email", controllers.ConfirmEmail)

	// Protected auth routes
	authProtected := auth.Use(middleware.RequireAuth())
	authProtected.Post("/logout", controllers.Logout)
	authProtected.Get("/userinfo", controllers.UserInfo)

	// Protected + Verified auth routes
	authVerified := authProtected.Use(middleware.RequireVerification())
	authVerified.Put("/change-password", controllers.ChangePassword)
	authVerified.Put("/change-email", controllers.ChangeEmail)
	authVerified.Delete("/account", controllers.DeleteAccount)

	// TODO: Add routes for tokens
}
