package middleware

import (
	"auth-api/internal/config"
	"auth-api/internal/constants"
	"auth-api/internal/database"
	"auth-api/internal/models"
	"auth-api/internal/services"
	"fmt"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/kerimovok/go-pkg-utils/httpx"
)

// RequireAuth middleware for routes that require authentication
func RequireAuth() fiber.Handler {
	return func(c *fiber.Ctx) error {
		tokenString, err := extractTokenString(c)
		if err != nil {
			response := httpx.Unauthorized(config.Messages.Auth.Error.TokenRequired)
			return httpx.SendResponse(c, response)
		}

		jwtService := services.NewJWTService()
		claims, err := jwtService.ValidateAccessToken(tokenString)
		if err != nil {
			response := httpx.Unauthorized(config.Messages.Auth.Error.InvalidToken)
			return httpx.SendResponse(c, response)
		}

		// Create user from JWT claims (avoiding database query)
		user := models.User{
			Email:      claims.Email,
			IsAdmin:    claims.IsAdmin,
			IsVerified: claims.IsVerified,
		}
		user.ID = claims.UserID

		// Only check database for critical security status (blocking)
		var isBlocked bool
		err = database.DB.Model(&models.User{}).
			Select("is_blocked").
			Where("id = ?", claims.UserID).
			Scan(&isBlocked).Error

		if err != nil {
			response := httpx.Unauthorized(config.Messages.Auth.Error.InvalidToken)
			return httpx.SendResponse(c, response)
		}

		if isBlocked {
			// User is blocked, revoke refresh tokens and deny access
			tokenService := services.NewTokenService()
			tokenService.RevokeAllUserTokens(user.ID, constants.RefreshToken)
			response := httpx.Forbidden(config.Messages.Auth.Error.AccountBlocked)
			return httpx.SendResponse(c, response)
		}

		c.Locals("user", user)
		c.Locals("claims", claims)
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
			response := httpx.Forbidden(config.Messages.Auth.Error.EmailVerificationRequired)
			return httpx.SendResponse(c, response)
		}
		return c.Next()
	}
}

// RequireAdmin middleware for admin-only routes
func RequireAdmin() fiber.Handler {
	return func(c *fiber.Ctx) error {
		user := c.Locals("user").(models.User)
		if !user.IsAdmin {
			response := httpx.Forbidden(config.Messages.Auth.Error.AdminRequired)
			return httpx.SendResponse(c, response)
		}
		return c.Next()
	}
}

// Add helper for token extraction
func extractTokenString(c *fiber.Ctx) (string, error) {
	tokenHeader := c.Get("Authorization")
	if tokenHeader == "" || !strings.HasPrefix(tokenHeader, "Bearer ") {
		return "", fmt.Errorf("token required")
	}

	return strings.TrimPrefix(tokenHeader, "Bearer "), nil
}
