package handlers

import (
	"auth-api/internal/config"
	"auth-api/internal/constants"
	"auth-api/internal/database"
	"auth-api/internal/helpers"
	"auth-api/internal/models"
	"auth-api/internal/requests"
	"auth-api/internal/services"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/kerimovok/go-pkg-database/sql"
	"github.com/kerimovok/go-pkg-utils/crypto"
	"github.com/kerimovok/go-pkg-utils/httpx"
	"github.com/kerimovok/go-pkg-utils/validator"
	"gorm.io/gorm"
)

// UserInfo returns the current user's information
func UserInfo(c *fiber.Ctx) error {
	user := c.Locals("user").(models.User)
	response := httpx.OK("", user)
	return httpx.SendResponse(c, response)
}

// Register handles user registration
func Register(c *fiber.Ctx) error {
	var input requests.RegisterRequest
	if err := c.BodyParser(&input); err != nil {
		response := httpx.BadRequest(config.Messages.Validation.Error.InvalidRequest, err)
		return httpx.SendResponse(c, response)
	}

	if err := validator.ValidateStruct(&input); err != nil {
		response := httpx.BadRequest(config.Messages.Validation.Error.InvalidRequest, err)
		return httpx.SendResponse(c, response)
	}

	// Normalize email
	input.Email = strings.ToLower(strings.TrimSpace(input.Email))

	// Check if email exists - use case-insensitive comparison
	var existingUser models.User
	if result := database.DB.Where("LOWER(email) = LOWER(?)", input.Email).First(&existingUser); result.Error == nil {
		response := httpx.Conflict(config.Messages.Auth.Error.EmailExists, nil)
		return httpx.SendResponse(c, response)
	}

	// Validate password strength
	if err := helpers.ValidatePasswordStrength(input.Password); err != nil {
		response := httpx.BadRequest(config.Messages.Validation.Error.InvalidRequest, err)
		return httpx.SendResponse(c, response)
	}

	// Hash password
	hashedPassword, err := crypto.HashPassword(input.Password)
	if err != nil {
		response := httpx.InternalServerError(config.Messages.Server.Error.Internal, err)
		return httpx.SendResponse(c, response)
	}

	user := models.User{
		Email:    input.Email,
		Password: hashedPassword,
	}

	var token *models.Token
	err = sql.WithTransaction(database.DB, func(tx *gorm.DB) error {
		if err := tx.Create(&user).Error; err != nil {
			return fmt.Errorf("failed to create user: %w", err)
		}

		if config.Auth.Verification {
			tokenService := services.NewTokenService()
			token, err = tokenService.CreateEmailVerificationToken(user, c.Get("User-Agent"), c)
			if err != nil {
				return fmt.Errorf("failed to create verification token: %w", err)
			}
		}
		return nil
	})

	if err != nil {
		response := httpx.InternalServerError(config.Messages.Server.Error.Internal, err)
		return httpx.SendResponse(c, response)
	}

	if token != nil {
		mailer := services.NewMailerService()
		if err := mailer.SendVerificationEmail(user.Email, token); err != nil {
			response := httpx.InternalServerError(config.Messages.Server.Error.MailService, err)
			return httpx.SendResponse(c, response)
		}
	}

	response := httpx.OK(config.Messages.Auth.Success.Registration, nil)
	return httpx.SendResponse(c, response)
}

// Login handles user authentication
func Login(c *fiber.Ctx) error {
	var input requests.LoginRequest

	if err := c.BodyParser(&input); err != nil {
		response := httpx.BadRequest(config.Messages.Validation.Error.InvalidRequest, err)
		return httpx.SendResponse(c, response)
	}

	if err := validator.ValidateStruct(&input); err != nil {
		response := httpx.BadRequest(config.Messages.Validation.Error.InvalidRequest, err)
		return httpx.SendResponse(c, response)
	}

	// Normalize email
	input.Email = strings.ToLower(strings.TrimSpace(input.Email))

	// Find user by email - use case-insensitive comparison
	var user models.User
	result := database.DB.Where("LOWER(email) = LOWER(?)", input.Email).First(&user)
	if result.Error != nil {
		response := httpx.Unauthorized(config.Messages.Auth.Error.InvalidCredentials)
		return httpx.SendResponse(c, response)
	}

	// Check password
	if !crypto.CheckPassword(input.Password, user.Password) {
		response := httpx.Unauthorized(config.Messages.Auth.Error.InvalidCredentials)
		return httpx.SendResponse(c, response)
	}

	// Check if user is blocked
	if user.IsBlocked {
		response := httpx.Forbidden(config.Messages.Auth.Error.AccountBlocked)
		return httpx.SendResponse(c, response)
	}

	var token *models.Token
	err := sql.WithTransaction(database.DB, func(tx *gorm.DB) error {
		tokenService := services.NewTokenService()

		// Create new token
		var err error
		token, err = tokenService.CreateAuthTokenForUser(user, c.Get("User-Agent"), c)
		if err != nil {
			return fmt.Errorf("failed to create auth token: %w", err)
		}

		// Update last login time
		now := time.Now()
		if err := tx.Model(&user).Update("last_login_at", &now).Error; err != nil {
			return fmt.Errorf("failed to update last login time: %w", err)
		}

		return nil
	})

	if err != nil {
		response := httpx.InternalServerError(config.Messages.Server.Error.Internal, err)
		return httpx.SendResponse(c, response)
	}

	response := httpx.OK(config.Messages.Auth.Success.Login, fiber.Map{
		"token": token.ID,
	})
	return httpx.SendResponse(c, response)
}

// ConfirmEmail handles email verification
func ConfirmEmail(c *fiber.Ctx) error {
	tokenID, err := uuid.Parse(c.Query("token"))
	if err != nil {
		response := httpx.BadRequest(config.Messages.Auth.Error.InvalidToken, err)
		return httpx.SendResponse(c, response)
	}

	tokenService := services.NewTokenService()
	token, err := tokenService.ValidateToken(tokenID, constants.EmailVerificationToken)
	if err != nil {
		response := httpx.Unauthorized(config.Messages.Auth.Error.InvalidToken)
		return httpx.SendResponse(c, response)
	}

	err = sql.WithTransaction(database.DB, func(tx *gorm.DB) error {
		var user models.User
		if err := tx.First(&user, token.UserID).Error; err != nil {
			return fmt.Errorf("failed to find user: %w", err)
		}

		if user.IsVerified {
			if err := tx.Delete(token).Error; err != nil {
				return fmt.Errorf("failed to delete token: %w", err)
			}
			return nil
		}

		if err := tx.Model(&user).Update("is_verified", true).Error; err != nil {
			return fmt.Errorf("failed to update verification status: %w", err)
		}

		if err := tx.Delete(token).Error; err != nil {
			return fmt.Errorf("failed to delete token: %w", err)
		}

		return nil
	})

	if err != nil {
		response := httpx.InternalServerError(config.Messages.Server.Error.Internal, err)
		return httpx.SendResponse(c, response)
	}

	response := httpx.OK(config.Messages.Auth.Success.EmailVerified, nil)
	return httpx.SendResponse(c, response)
}

// RequestPasswordReset initiates the password reset process
func RequestPasswordReset(c *fiber.Ctx) error {
	var input requests.PasswordResetRequest

	if err := c.BodyParser(&input); err != nil {
		response := httpx.BadRequest(config.Messages.Validation.Error.InvalidRequest, err)
		return httpx.SendResponse(c, response)
	}

	if err := validator.ValidateStruct(&input); err != nil {
		response := httpx.BadRequest(config.Messages.Validation.Error.InvalidRequest, err)
		return httpx.SendResponse(c, response)
	}

	// Find user by email
	var user models.User
	result := database.DB.Where("LOWER(email) = LOWER(?)", strings.ToLower(strings.TrimSpace(input.Email))).First(&user)
	if result.Error != nil {
		// Don't reveal if user exists
		response := httpx.OK(config.Messages.Auth.Success.PasswordResetRequested, nil)
		return httpx.SendResponse(c, response)
	}

	var token *models.Token
	err := sql.WithTransaction(database.DB, func(tx *gorm.DB) error {
		// Generate new token
		tokenService := services.NewTokenService()
		var err error
		token, err = tokenService.CreatePasswordResetToken(user, c.Get("User-Agent"), c)
		if err != nil {
			return fmt.Errorf("failed to create password reset token: %w", err)
		}

		return nil
	})

	if err != nil {
		response := httpx.InternalServerError(config.Messages.Server.Error.Internal, err)
		return httpx.SendResponse(c, response)
	}

	// Send password reset email
	mailer := services.NewMailerService()
	if err := mailer.SendPasswordResetEmail(user.Email, token); err != nil {
		response := httpx.InternalServerError(config.Messages.Server.Error.MailService, err)
		return httpx.SendResponse(c, response)
	}

	response := httpx.OK(config.Messages.Auth.Success.PasswordResetRequested, nil)
	return httpx.SendResponse(c, response)
}

// ResetPassword handles password reset with token
func ResetPassword(c *fiber.Ctx) error {
	var input requests.ResetPasswordRequest

	if err := c.BodyParser(&input); err != nil {
		response := httpx.BadRequest(config.Messages.Validation.Error.InvalidRequest, err)
		return httpx.SendResponse(c, response)
	}

	if err := validator.ValidateStruct(&input); err != nil {
		response := httpx.BadRequest(config.Messages.Validation.Error.InvalidRequest, err)
		return httpx.SendResponse(c, response)
	}

	// Parse token ID
	tokenID, err := uuid.Parse(input.Token)
	if err != nil {
		response := httpx.BadRequest(config.Messages.Auth.Error.InvalidToken, err)
		return httpx.SendResponse(c, response)
	}

	// Validate token
	tokenService := services.NewTokenService()
	token, err := tokenService.ValidateToken(tokenID, constants.PasswordResetToken)
	if err != nil {
		response := httpx.Unauthorized(config.Messages.Auth.Error.InvalidToken)
		return httpx.SendResponse(c, response)
	}

	// Validate password strength
	if err := helpers.ValidatePasswordStrength(input.Password); err != nil {
		response := httpx.BadRequest(err.Error(), nil)
		return httpx.SendResponse(c, response)
	}

	// Hash new password
	hashedPassword, err := crypto.HashPassword(input.Password)
	if err != nil {
		log.Printf("failed to hash password: %v", err)
		response := httpx.InternalServerError(config.Messages.Server.Error.Internal, err)
		return httpx.SendResponse(c, response)
	}

	err = sql.WithTransaction(database.DB, func(tx *gorm.DB) error {
		// Check if user exists
		var user models.User
		if err := tx.First(&user, token.UserID).Error; err != nil {
			return fmt.Errorf("failed to find user: %w", err)
		}

		// Update password
		if err := tx.Model(&user).Update("password", hashedPassword).Error; err != nil {
			return fmt.Errorf("failed to update password: %w", err)
		}

		// Delete the used token
		if err := tx.Delete(token).Error; err != nil {
			return fmt.Errorf("failed to delete token: %w", err)
		}

		return nil
	})

	if err != nil {
		log.Printf("failed to reset password: %v", err)
		response := httpx.InternalServerError(config.Messages.Server.Error.Internal, err)
		return httpx.SendResponse(c, response)
	}

	response := httpx.OK(config.Messages.Auth.Success.PasswordReset, nil)
	return httpx.SendResponse(c, response)
}

// ChangePassword handles password change for authenticated users
func ChangePassword(c *fiber.Ctx) error {
	var input requests.ChangePasswordRequest

	if err := c.BodyParser(&input); err != nil {
		response := httpx.BadRequest(config.Messages.Validation.Error.InvalidRequest, err)
		return httpx.SendResponse(c, response)
	}

	if err := validator.ValidateStruct(&input); err != nil {
		response := httpx.BadRequest(config.Messages.Validation.Error.InvalidRequest, err)
		return httpx.SendResponse(c, response)
	}

	user := c.Locals("user").(models.User)

	// Verify old password
	if !crypto.CheckPassword(input.OldPassword, user.Password) {
		response := httpx.Unauthorized(config.Messages.Auth.Error.InvalidPassword)
		return httpx.SendResponse(c, response)
	}

	// Prevent using the same password
	if crypto.CheckPassword(input.NewPassword, user.Password) {
		response := httpx.BadRequest(config.Messages.Auth.Error.SamePassword, nil)
		return httpx.SendResponse(c, response)
	}

	// Validate new password strength
	if err := helpers.ValidatePasswordStrength(input.NewPassword); err != nil {
		response := httpx.BadRequest(err.Error(), nil)
		return httpx.SendResponse(c, response)
	}

	// Hash new password
	hashedPassword, err := crypto.HashPassword(input.NewPassword)
	if err != nil {
		log.Printf("failed to hash password: %v", err)
		response := httpx.InternalServerError(config.Messages.Server.Error.Internal, err)
		return httpx.SendResponse(c, response)
	}

	err = sql.WithTransaction(database.DB, func(tx *gorm.DB) error {
		// Update password
		if err := tx.Model(&user).Update("password", hashedPassword).Error; err != nil {
			return fmt.Errorf("failed to update password: %w", err)
		}

		if !config.Auth.Allow.ConcurrentLogins {
			currentToken := c.Locals("token").(*models.Token)
			tokenService := services.NewTokenService()
			if err := tokenService.RevokeAllUserTokensExcept(user.ID, constants.AuthToken, currentToken.ID); err != nil {
				return fmt.Errorf("failed to revoke tokens: %w", err)
			}
		}

		return nil
	})

	if err != nil {
		log.Printf("failed to change password: %v", err)
		response := httpx.InternalServerError(config.Messages.Server.Error.Internal, err)
		return httpx.SendResponse(c, response)
	}

	response := httpx.OK(config.Messages.Auth.Success.PasswordChanged, nil)
	return httpx.SendResponse(c, response)
}

// ChangeEmail initiates email change process
func ChangeEmail(c *fiber.Ctx) error {
	var input requests.ChangeEmailRequest

	if err := c.BodyParser(&input); err != nil {
		response := httpx.BadRequest(config.Messages.Validation.Error.InvalidRequest, err)
		return httpx.SendResponse(c, response)
	}

	if err := validator.ValidateStruct(&input); err != nil {
		response := httpx.BadRequest(config.Messages.Validation.Error.InvalidRequest, err)
		return httpx.SendResponse(c, response)
	}

	user := c.Locals("user").(models.User)

	// Verify password
	if !crypto.CheckPassword(input.Password, user.Password) {
		response := httpx.Unauthorized(config.Messages.Auth.Error.InvalidPassword)
		return httpx.SendResponse(c, response)
	}

	// Normalize new email
	input.NewEmail = strings.ToLower(strings.TrimSpace(input.NewEmail))

	// Check if new email is already registered - use case-insensitive comparison
	var existingUser models.User
	if result := database.DB.Where("LOWER(email) = LOWER(?)", input.NewEmail).First(&existingUser); result.Error == nil {
		response := httpx.Conflict(config.Messages.Auth.Error.EmailExists, nil)
		return httpx.SendResponse(c, response)
	}

	var token *models.Token
	err := sql.WithTransaction(database.DB, func(tx *gorm.DB) error {
		// First, create the verification token if required
		// This ensures we don't update the email if token creation fails
		if config.Auth.Verification {
			tokenService := services.NewTokenService()
			var err error
			token, err = tokenService.CreateEmailVerificationToken(user, c.Get("User-Agent"), c)
			if err != nil {
				return fmt.Errorf("failed to create verification token: %w", err)
			}

			// Store token in database within the transaction
			if err := tx.Create(token).Error; err != nil {
				return fmt.Errorf("failed to save verification token: %w", err)
			}
		}

		// Then update email if token was created successfully (or not required)
		if err := tx.Model(&user).Updates(map[string]interface{}{
			"email":       input.NewEmail,
			"is_verified": false,
		}).Error; err != nil {
			return fmt.Errorf("failed to update email: %w", err)
		}

		return nil
	})

	if err != nil {
		log.Printf("failed to change email: %v", err)
		response := httpx.InternalServerError(config.Messages.Server.Error.Internal, err)
		return httpx.SendResponse(c, response)
	}

	// Send verification email if token was created
	if token != nil {
		mailer := services.NewMailerService()
		if err := mailer.SendVerificationEmail(input.NewEmail, token); err != nil {
			log.Printf("failed to send verification email: %v", err)
			response := httpx.InternalServerError(config.Messages.Server.Error.MailService, err)
			return httpx.SendResponse(c, response)
		}
	}

	response := httpx.OK(config.Messages.Auth.Success.EmailChanged, nil)
	return httpx.SendResponse(c, response)
}

// DeleteAccount handles account deletion for authenticated users
func DeleteAccount(c *fiber.Ctx) error {
	var input requests.DeleteAccountRequest

	if err := c.BodyParser(&input); err != nil {
		response := httpx.BadRequest(config.Messages.Validation.Error.InvalidRequest, err)
		return httpx.SendResponse(c, response)
	}

	if err := validator.ValidateStruct(&input); err != nil {
		response := httpx.BadRequest(config.Messages.Validation.Error.InvalidRequest, err)
		return httpx.SendResponse(c, response)
	}

	user := c.Locals("user").(models.User)

	// Verify password
	if !crypto.CheckPassword(input.Password, user.Password) {
		response := httpx.Unauthorized(config.Messages.Auth.Error.InvalidPassword)
		return httpx.SendResponse(c, response)
	}

	err := sql.WithTransaction(database.DB, func(tx *gorm.DB) error {
		// Revoke all tokens first
		if err := tx.Model(&models.Token{}).
			Where("user_id = ? AND revoked_at IS NULL", user.ID).
			Update("revoked_at", time.Now()).Error; err != nil {
			return fmt.Errorf("failed to revoke tokens: %w", err)
		}

		// Delete user (using soft delete if configured)
		if err := tx.Delete(&user).Error; err != nil {
			return fmt.Errorf("failed to delete user: %w", err)
		}

		return nil
	})

	if err != nil {
		log.Printf("failed to delete account: %v", err)
		response := httpx.InternalServerError(config.Messages.Server.Error.Internal, err)
		return httpx.SendResponse(c, response)
	}

	response := httpx.OK(config.Messages.Auth.Success.AccountDeleted, nil)
	return httpx.SendResponse(c, response)
}

// Logout handles user logout by revoking the auth token
func Logout(c *fiber.Ctx) error {
	token := c.Locals("token").(*models.Token)

	err := sql.WithTransaction(database.DB, func(tx *gorm.DB) error {
		// Revoke the current token
		if err := tx.Model(token).Update("revoked_at", time.Now()).Error; err != nil {
			return fmt.Errorf("failed to revoke token: %w", err)
		}
		return nil
	})

	if err != nil {
		log.Printf("failed to logout user: %v", err)
		response := httpx.InternalServerError(config.Messages.Server.Error.Internal, err)
		return httpx.SendResponse(c, response)
	}

	response := httpx.OK(config.Messages.Auth.Success.Logout, nil)
	return httpx.SendResponse(c, response)
}
