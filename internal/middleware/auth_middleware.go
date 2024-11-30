package middleware

import (
	"auth-api/internal/models"
	"auth-api/internal/services"
	"auth-api/pkg/config"
	"auth-api/pkg/constants"
	"auth-api/pkg/database"
	"auth-api/pkg/utils"

	"fmt"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// RequireAuth middleware for routes that require authentication
func RequireAuth() fiber.Handler {
	return func(c *fiber.Ctx) error {
		tokenID, err := extractTokenID(c)
		if err != nil {
			return utils.ErrorResponse(c, fiber.StatusUnauthorized, config.Messages.Auth.Error.TokenRequired, nil)
		}

		tokenService := services.NewTokenService()
		token, err := tokenService.ValidateToken(tokenID, constants.AuthToken)
		if err != nil {
			return utils.ErrorResponse(c, fiber.StatusUnauthorized, config.Messages.Auth.Error.InvalidToken, nil)
		}

		var user models.User
		if err := database.DB.First(&user, "id = ?", token.UserID).Error; err != nil {
			return utils.ErrorResponse(c, fiber.StatusUnauthorized, config.Messages.Auth.Error.InvalidToken, nil)
		}

		if err := validateUser(user, tokenService); err != nil {
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
		if !config.Auth.Verification {
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

// Add helper for token extraction
func extractTokenID(c *fiber.Ctx) (uuid.UUID, error) {
	tokenHeader := c.Get("Authorization")
	if tokenHeader == "" || !strings.HasPrefix(tokenHeader, "Bearer ") {
		return uuid.Nil, fmt.Errorf("token required")
	}

	return uuid.Parse(strings.TrimPrefix(tokenHeader, "Bearer "))
}

// Add helper for user validation
func validateUser(user models.User, tokenService *services.TokenService) error {
	if user.IsBlocked {
		if err := tokenService.RevokeAllUserTokens(user.ID, constants.AuthToken); err != nil {
			return fmt.Errorf("failed to revoke tokens for blocked user: %w", err)
		}
		return fmt.Errorf("account blocked")
	}
	return nil
}
