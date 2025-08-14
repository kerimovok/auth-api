package routes

import (
	"auth-api/internal/handlers"
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
	auth.Post("/register", handlers.Register)
	auth.Post("/login", handlers.Login)
	auth.Post("/refresh-token", handlers.RefreshToken)
	auth.Post("/request-password-reset", handlers.RequestPasswordReset)
	auth.Post("/reset-password", handlers.ResetPassword)
	auth.Get("/confirm-email", handlers.ConfirmEmail)

	// Protected auth routes
	authProtected := auth.Use(middleware.RequireAuth())
	authProtected.Post("/logout", handlers.Logout)
	authProtected.Get("/userinfo", handlers.UserInfo)

	// Protected + Verified auth routes
	authVerified := authProtected.Use(middleware.RequireVerification())
	authVerified.Put("/change-password", handlers.ChangePassword)
	authVerified.Put("/change-email", handlers.ChangeEmail)
	authVerified.Delete("/account", handlers.DeleteAccount)

	// TODO: Add routes for tokens
}
