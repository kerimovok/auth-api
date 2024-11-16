package middleware

import (
	"auth-api/.internal/config"
	"auth-api/.internal/database"
	"auth-api/.internal/models"
	"auth-api/.internal/services"
	"auth-api/.internal/utils"

	"github.com/gofiber/fiber/v2"
)

// RequireAuth middleware for routes that require authentication
func RequireAuth() fiber.Handler {
	return func(c *fiber.Ctx) error {
		tokenString, err := utils.ExtractBearerToken(c.Get("Authorization"))
		if err != nil {
			return utils.ErrorResponse(c, fiber.StatusUnauthorized, config.Messages.Auth.Error.TokenRequired, nil)
		}

		tokenService := services.NewTokenService()
		token, err := tokenService.ValidateToken(tokenString, utils.AuthToken)
		if err != nil {
			return utils.ErrorResponse(c, fiber.StatusUnauthorized, config.Messages.Auth.Error.InvalidToken, nil)
		}

		// Get user
		var user models.User
		if err := database.DB.First(&user, token.UserID).Error; err != nil {
			return utils.ErrorResponse(c, fiber.StatusUnauthorized, config.Messages.Auth.Error.InvalidToken, nil)
		}

		// Check if user is blocked
		if user.IsBlocked {
			// Revoke all user tokens
			tokenService.RevokeAllUserTokens(user.ID, utils.AuthToken)
			return utils.ErrorResponse(c, fiber.StatusForbidden, config.Messages.Auth.Error.AccountBlocked, nil)
		}

		c.Locals("user", user)
		c.Locals("token", token)
		return c.Next()
	}
}

// RequireVerification middleware for routes that require email verification
func RequireVerification() fiber.Handler {
	return func(c *fiber.Ctx) error {
		if !config.Auth.Verification.Required {
			return c.Next()
		}

		user := c.Locals("user").(models.User)
		if !user.IsVerified {
			return utils.ErrorResponse(c, fiber.StatusForbidden, config.Messages.Auth.Error.EmailVerificationRequired, nil)
		}
		return c.Next()
	}
}

// RequireAdmin middleware for admin-only routes
func RequireAdmin() fiber.Handler {
	return func(c *fiber.Ctx) error {
		user := c.Locals("user").(models.User)
		if !user.IsAdmin {
			return utils.ErrorResponse(c, fiber.StatusForbidden, config.Messages.Auth.Error.AdminRequired, nil)
		}
		return c.Next()
	}
}
