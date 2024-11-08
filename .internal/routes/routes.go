package routes

import (
	"auth-api/.internal/handlers"
	"auth-api/.internal/middleware"

	"github.com/gofiber/fiber/v2"
)

func SetupRoutes(app *fiber.App) {
	api := app.Group("/api/v1")

	// Public routes
	api.Post("/register", handlers.Register)
	api.Post("/login", handlers.Login)
	api.Post("/request-password-reset", handlers.RequestPasswordReset)
	api.Post("/reset-password", handlers.ResetPassword)
	api.Get("/confirm-email", handlers.ConfirmEmail)

	// Protected routes
	protected := api.Use(middleware.RequireAuth())
	protected.Get("/userinfo", handlers.UserInfo)

	// Protected + Verified routes
	verified := protected.Use(middleware.RequireVerification())
	verified.Put("/change-password", handlers.ChangePassword)
	verified.Post("/change-email", handlers.ChangeEmail)
}
