package routes

import (
	"auth-api/internal/controllers"
	"auth-api/internal/middleware"

	"github.com/gofiber/fiber/v2"
)

func SetupRoutes(app *fiber.App) {
	api := app.Group("/api/v1")

	// Public routes
	api.Post("/register", controllers.Register)
	api.Post("/login", controllers.Login)
	api.Post("/request-password-reset", controllers.RequestPasswordReset)
	api.Post("/reset-password", controllers.ResetPassword)
	api.Get("/confirm-email", controllers.ConfirmEmail)

	// Protected routes
	protected := api.Use(middleware.RequireAuth())
	protected.Post("/logout", controllers.Logout)
	protected.Get("/userinfo", controllers.UserInfo)

	// Protected + Verified routes
	verified := protected.Use(middleware.RequireVerification())
	verified.Put("/change-password", controllers.ChangePassword)
	verified.Put("/change-email", controllers.ChangeEmail)
	verified.Delete("/account", controllers.DeleteAccount)
}
