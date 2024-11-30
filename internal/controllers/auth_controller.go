package controllers

import (
	"auth-api/internal/models"
	"auth-api/internal/services"
	"auth-api/pkg/config"
	"auth-api/pkg/constants"
	"auth-api/pkg/database"
	"auth-api/pkg/requests"
	"auth-api/pkg/utils"
	"fmt"
	"log"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// UserInfo returns the current user's information
func UserInfo(c *fiber.Ctx) error {
	user := c.Locals("user").(models.User)
	return utils.SuccessResponse(c, "", user)
}

// Register handles user registration
func Register(c *fiber.Ctx) error {
	var input requests.RegisterRequest
	if err := c.BodyParser(&input); err != nil {
		return utils.ErrorResponse(c, fiber.StatusBadRequest, config.Messages.Validation.Error.InvalidRequest, err)
	}

	if err := utils.ValidateRequest(&input); err != nil {
		return utils.ErrorResponse(c, fiber.StatusBadRequest, config.Messages.Validation.Error.InvalidRequest, err)
	}

	// Normalize email
	input.Email = utils.NormalizeEmail(input.Email)

	// Check if email exists - use case-insensitive comparison
	var existingUser models.User
	if result := database.DB.Where("LOWER(email) = LOWER(?)", input.Email).First(&existingUser); result.Error == nil {
		return utils.ErrorResponse(c, fiber.StatusConflict, config.Messages.Auth.Error.EmailExists, nil)
	}

	// Validate password strength
	if err := utils.ValidatePasswordStrength(input.Password); err != nil {
		return utils.ErrorResponse(c, fiber.StatusBadRequest, err.Error(), nil)
	}

	// Hash password
	hashedPassword, err := utils.HashPassword(input.Password)
	if err != nil {
		log.Printf("failed to hash password: %v", err)
		return utils.ErrorResponse(c, fiber.StatusInternalServerError, config.Messages.Server.Error.Internal, nil)
	}

	user := models.User{
		Email:    input.Email,
		Password: hashedPassword,
	}

	var token *models.Token
	err = withTransaction(func(tx *gorm.DB) error {
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
		return utils.ErrorResponse(c, fiber.StatusInternalServerError, config.Messages.Server.Error.Internal, nil)
	}

	if token != nil {
		mailer := services.NewMailerService()
		if err := mailer.SendVerificationEmail(user.Email, token); err != nil {
			log.Printf("failed to send verification email: %v", err)
			return utils.ErrorResponse(c, fiber.StatusInternalServerError, config.Messages.Server.Error.MailService, nil)
		}
	}

	return utils.SuccessResponse(c, config.Messages.Auth.Success.Registration, nil)
}

// Login handles user authentication
func Login(c *fiber.Ctx) error {
	var input requests.LoginRequest

	if err := c.BodyParser(&input); err != nil {
		return utils.ErrorResponse(c, fiber.StatusBadRequest, config.Messages.Validation.Error.InvalidRequest, err)
	}

	if err := utils.ValidateRequest(&input); err != nil {
		return utils.ErrorResponse(c, fiber.StatusBadRequest, config.Messages.Validation.Error.InvalidRequest, err)
	}

	// Normalize email
	input.Email = utils.NormalizeEmail(input.Email)

	// Find user by email - use case-insensitive comparison
	var user models.User
	result := database.DB.Where("LOWER(email) = LOWER(?)", input.Email).First(&user)
	if result.Error != nil {
		return utils.ErrorResponse(c, fiber.StatusUnauthorized, config.Messages.Auth.Error.InvalidCredentials, nil)
	}

	// Check password
	if !utils.CheckPassword(input.Password, user.Password) {
		return utils.ErrorResponse(c, fiber.StatusUnauthorized, config.Messages.Auth.Error.InvalidCredentials, nil)
	}

	// Check if user is blocked
	if user.IsBlocked {
		return utils.ErrorResponse(c, fiber.StatusForbidden, config.Messages.Auth.Error.AccountBlocked, nil)
	}

	var token *models.Token
	err := withTransaction(func(tx *gorm.DB) error {
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
		return utils.ErrorResponse(c, fiber.StatusInternalServerError, config.Messages.Server.Error.Internal, err)
	}

	return utils.SuccessResponse(c, config.Messages.Auth.Success.Login, fiber.Map{
		"token": token.ID,
	})
}

// ConfirmEmail handles email verification
func ConfirmEmail(c *fiber.Ctx) error {
	tokenID, err := uuid.Parse(c.Query("token"))
	if err != nil {
		return utils.ErrorResponse(c, fiber.StatusBadRequest, config.Messages.Auth.Error.InvalidToken, nil)
	}

	tokenService := services.NewTokenService()
	token, err := tokenService.ValidateToken(tokenID, constants.EmailVerificationToken)
	if err != nil {
		return utils.ErrorResponse(c, fiber.StatusUnauthorized, config.Messages.Auth.Error.InvalidToken, nil)
	}

	err = withTransaction(func(tx *gorm.DB) error {
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
		return utils.ErrorResponse(c, fiber.StatusInternalServerError, config.Messages.Server.Error.Internal, nil)
	}

	return utils.SuccessResponse(c, config.Messages.Auth.Success.EmailVerified, nil)
}

// RequestPasswordReset initiates the password reset process
func RequestPasswordReset(c *fiber.Ctx) error {
	var input requests.PasswordResetRequest

	if err := c.BodyParser(&input); err != nil {
		return utils.ErrorResponse(c, fiber.StatusBadRequest, config.Messages.Validation.Error.InvalidRequest, err)
	}

	if err := utils.ValidateRequest(&input); err != nil {
		return utils.ErrorResponse(c, fiber.StatusBadRequest, config.Messages.Validation.Error.InvalidRequest, err)
	}

	// Find user by email
	var user models.User
	result := database.DB.Where("LOWER(email) = LOWER(?)", utils.NormalizeEmail(input.Email)).First(&user)
	if result.Error != nil {
		// Don't reveal if user exists
		return utils.SuccessResponse(c, config.Messages.Auth.Success.PasswordResetRequested, nil)
	}

	var token *models.Token
	err := withTransaction(func(tx *gorm.DB) error {
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
		return utils.ErrorResponse(c, fiber.StatusInternalServerError, config.Messages.Server.Error.Internal, nil)
	}

	// Send password reset email
	mailer := services.NewMailerService()
	if err := mailer.SendPasswordResetEmail(user.Email, token); err != nil {
		log.Printf("failed to send password reset email: %v", err)
		return utils.ErrorResponse(c, fiber.StatusInternalServerError, config.Messages.Server.Error.MailService, nil)
	}

	return utils.SuccessResponse(c, config.Messages.Auth.Success.PasswordResetRequested, nil)
}

// ResetPassword handles password reset with token
func ResetPassword(c *fiber.Ctx) error {
	var input requests.ResetPasswordRequest

	if err := c.BodyParser(&input); err != nil {
		return utils.ErrorResponse(c, fiber.StatusBadRequest, config.Messages.Validation.Error.InvalidRequest, err)
	}

	if err := utils.ValidateRequest(&input); err != nil {
		return utils.ErrorResponse(c, fiber.StatusBadRequest, config.Messages.Validation.Error.InvalidRequest, err)
	}

	// Parse token ID
	tokenID, err := uuid.Parse(input.Token)
	if err != nil {
		return utils.ErrorResponse(c, fiber.StatusBadRequest, config.Messages.Auth.Error.InvalidToken, nil)
	}

	// Validate token
	tokenService := services.NewTokenService()
	token, err := tokenService.ValidateToken(tokenID, constants.PasswordResetToken)
	if err != nil {
		return utils.ErrorResponse(c, fiber.StatusUnauthorized, config.Messages.Auth.Error.InvalidToken, nil)
	}

	// Validate password strength
	if err := utils.ValidatePasswordStrength(input.Password); err != nil {
		return utils.ErrorResponse(c, fiber.StatusBadRequest, err.Error(), nil)
	}

	// Hash new password
	hashedPassword, err := utils.HashPassword(input.Password)
	if err != nil {
		return utils.ErrorResponse(c, fiber.StatusInternalServerError, config.Messages.Server.Error.Internal, nil)
	}

	err = withTransaction(func(tx *gorm.DB) error {
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
		return utils.ErrorResponse(c, fiber.StatusInternalServerError, config.Messages.Server.Error.Internal, nil)
	}

	return utils.SuccessResponse(c, config.Messages.Auth.Success.PasswordReset, nil)
}

// ChangePassword handles password change for authenticated users
func ChangePassword(c *fiber.Ctx) error {
	var input requests.ChangePasswordRequest

	if err := c.BodyParser(&input); err != nil {
		return utils.ErrorResponse(c, fiber.StatusBadRequest, config.Messages.Validation.Error.InvalidRequest, err)
	}

	if err := utils.ValidateRequest(&input); err != nil {
		return utils.ErrorResponse(c, fiber.StatusBadRequest, config.Messages.Validation.Error.InvalidRequest, err)
	}

	user := c.Locals("user").(models.User)

	// Verify old password
	if !utils.CheckPassword(input.OldPassword, user.Password) {
		return utils.ErrorResponse(c, fiber.StatusUnauthorized, config.Messages.Auth.Error.InvalidPassword, nil)
	}

	// Prevent using the same password
	if utils.CheckPassword(input.NewPassword, user.Password) {
		return utils.ErrorResponse(c, fiber.StatusBadRequest, config.Messages.Auth.Error.SamePassword, nil)
	}

	// Validate new password strength
	if err := utils.ValidatePasswordStrength(input.NewPassword); err != nil {
		return utils.ErrorResponse(c, fiber.StatusBadRequest, err.Error(), nil)
	}

	// Hash new password
	hashedPassword, err := utils.HashPassword(input.NewPassword)
	if err != nil {
		return utils.ErrorResponse(c, fiber.StatusInternalServerError, config.Messages.Server.Error.Internal, nil)
	}

	err = withTransaction(func(tx *gorm.DB) error {
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
		return utils.ErrorResponse(c, fiber.StatusInternalServerError, config.Messages.Server.Error.Internal, nil)
	}

	return utils.SuccessResponse(c, config.Messages.Auth.Success.PasswordChanged, nil)
}

// ChangeEmail initiates email change process
func ChangeEmail(c *fiber.Ctx) error {
	var input requests.ChangeEmailRequest

	if err := c.BodyParser(&input); err != nil {
		return utils.ErrorResponse(c, fiber.StatusBadRequest, config.Messages.Validation.Error.InvalidRequest, err)
	}

	if err := utils.ValidateRequest(&input); err != nil {
		return utils.ErrorResponse(c, fiber.StatusBadRequest, config.Messages.Validation.Error.InvalidRequest, err)
	}

	user := c.Locals("user").(models.User)

	// Verify password
	if !utils.CheckPassword(input.Password, user.Password) {
		return utils.ErrorResponse(c, fiber.StatusUnauthorized, config.Messages.Auth.Error.InvalidPassword, nil)
	}

	// Normalize new email
	input.NewEmail = utils.NormalizeEmail(input.NewEmail)

	// Check if new email is already registered - use case-insensitive comparison
	var existingUser models.User
	if result := database.DB.Where("LOWER(email) = LOWER(?)", input.NewEmail).First(&existingUser); result.Error == nil {
		return utils.ErrorResponse(c, fiber.StatusConflict, config.Messages.Auth.Error.EmailExists, nil)
	}

	var token *models.Token
	err := withTransaction(func(tx *gorm.DB) error {
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
		utils.LogError("change email", err)
		return utils.ErrorResponse(c, fiber.StatusInternalServerError, config.Messages.Server.Error.Internal, nil)
	}

	// Send verification email if token was created
	if token != nil {
		mailer := services.NewMailerService()
		if err := mailer.SendVerificationEmail(input.NewEmail, token); err != nil {
			utils.LogError("send verification email", err)
			return utils.ErrorResponse(c, fiber.StatusInternalServerError, config.Messages.Server.Error.MailService, nil)
		}
	}

	return utils.SuccessResponse(c, config.Messages.Auth.Success.EmailChanged, nil)
}

// DeleteAccount handles account deletion for authenticated users
func DeleteAccount(c *fiber.Ctx) error {
	var input requests.DeleteAccountRequest

	if err := c.BodyParser(&input); err != nil {
		return utils.ErrorResponse(c, fiber.StatusBadRequest, config.Messages.Validation.Error.InvalidRequest, err)
	}

	if err := utils.ValidateRequest(&input); err != nil {
		return utils.ErrorResponse(c, fiber.StatusBadRequest, config.Messages.Validation.Error.InvalidRequest, err)
	}

	user := c.Locals("user").(models.User)

	// Verify password
	if !utils.CheckPassword(input.Password, user.Password) {
		return utils.ErrorResponse(c, fiber.StatusUnauthorized, config.Messages.Auth.Error.InvalidPassword, nil)
	}

	err := withTransaction(func(tx *gorm.DB) error {
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
		return utils.ErrorResponse(c, fiber.StatusInternalServerError, config.Messages.Server.Error.Internal, nil)
	}

	return utils.SuccessResponse(c, config.Messages.Auth.Success.AccountDeleted, nil)
}

// Logout handles user logout by revoking the auth token
func Logout(c *fiber.Ctx) error {
	token := c.Locals("token").(*models.Token)

	err := withTransaction(func(tx *gorm.DB) error {
		// Revoke the current token
		if err := tx.Model(token).Update("revoked_at", time.Now()).Error; err != nil {
			return fmt.Errorf("failed to revoke token: %w", err)
		}
		return nil
	})

	if err != nil {
		return utils.ErrorResponse(c, fiber.StatusInternalServerError, config.Messages.Server.Error.Internal, nil)
	}

	return utils.SuccessResponse(c, config.Messages.Auth.Success.Logout, nil)
}

// Add a common transaction helper to reduce boilerplate
func withTransaction(fn func(*gorm.DB) error) error {
	tx := database.DB.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit().Error
}
