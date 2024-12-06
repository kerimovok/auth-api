package routes

import (
	"auth-api/internal/controllers"
	"auth-api/internal/middleware"

	"github.com/gofiber/fiber/v2"
)

func SetupRoutes(app *fiber.App) {
	// API routes group
	api := app.Group("/api")
	v1 := api.Group("/v1")

	// Public routes
	v1.Post("/register", controllers.Register)
	v1.Post("/login", controllers.Login)
	v1.Post("/request-password-reset", controllers.RequestPasswordReset)
	v1.Post("/reset-password", controllers.ResetPassword)
	v1.Get("/confirm-email", controllers.ConfirmEmail)

	// Protected routes
	protected := v1.Use(middleware.RequireAuth())
	protected.Post("/logout", controllers.Logout)
	protected.Get("/userinfo", controllers.UserInfo)

	// Protected + Verified routes
	verified := protected.Use(middleware.RequireVerification())
	verified.Put("/change-password", controllers.ChangePassword)
	verified.Put("/change-email", controllers.ChangeEmail)
	verified.Delete("/account", controllers.DeleteAccount)
}
