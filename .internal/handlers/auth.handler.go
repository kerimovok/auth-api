package handlers

import (
	"auth-api/.internal/config"
	"auth-api/.internal/database"
	"auth-api/.internal/models"
	"auth-api/.internal/services"
	"auth-api/.internal/utils"
	"time"

	"github.com/gofiber/fiber/v2"
)

type RegisterRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type PasswordResetRequest struct {
	Email string `json:"email" validate:"required,email"`
}

type ResetPasswordRequest struct {
	Token    string `json:"token" validate:"required"`
	Password string `json:"password" validate:"required"`
}

type ChangePasswordRequest struct {
	OldPassword string `json:"oldPassword" validate:"required"`
	NewPassword string `json:"newPassword" validate:"required"`
}

type ChangeEmailRequest struct {
	Password string `json:"password" validate:"required"`
	NewEmail string `json:"newEmail" validate:"required,email"`
}

// Register handles user registration
func Register(c *fiber.Ctx) error {
	var req RegisterRequest
	if err := utils.ValidateRequest(c, &req); err != nil {
		return utils.ErrorResponse(c, fiber.StatusBadRequest, config.AppMessages.Validation.Error.InvalidRequest, err)
	}

	// Validate password strength
	if err := utils.ValidatePasswordStrength(req.Password); err != nil {
		return utils.ErrorResponse(c, fiber.StatusBadRequest, err.Error(), nil)
	}

	// Check if email exists
	var existingUser models.User
	if result := database.DB.Where("email = ?", req.Email).First(&existingUser); result.Error == nil {
		return utils.ErrorResponse(c, fiber.StatusConflict, config.AppMessages.Auth.Error.EmailExists, nil)
	}

	// Hash password
	hashedPassword, err := utils.HashPassword(req.Password)
	if err != nil {
		return utils.ErrorResponse(c, fiber.StatusInternalServerError, config.AppMessages.Server.Error.Internal, nil)
	}

	// Create user
	user := models.User{
		Email:    req.Email,
		Password: hashedPassword,
	}

	if result := database.DB.Create(&user); result.Error != nil {
		return utils.ErrorResponse(c, fiber.StatusInternalServerError, config.AppMessages.Server.Error.Internal, nil)
	}

	// Generate verification token if required
	if config.AppConfig.Auth.RequireEmailVerification {
		tokenService := services.NewTokenService()
		token, err := tokenService.CreateEmailVerificationTokenForUser(user, c.Get("User-Agent"), c.IP())
		if err != nil {
			return utils.ErrorResponse(c, fiber.StatusInternalServerError, config.AppMessages.Server.Error.Internal, nil)
		}

		// Send verification email
		mailer := services.NewMailerService(&config.AppConfig)
		if err := mailer.SendVerificationEmail(user.Email, token.Token); err != nil {
			return utils.ErrorResponse(c, fiber.StatusInternalServerError, config.AppMessages.Server.Error.MailService, nil)
		}
	}

	return utils.SuccessResponse(c, config.AppMessages.Auth.Success.Registration, nil)
}

// Login handles user authentication
func Login(c *fiber.Ctx) error {
	var req LoginRequest
	if err := utils.ValidateRequest(c, &req); err != nil {
		return err
	}

	// Find user by email
	var user models.User
	result := database.DB.Where("email = ?", req.Email).First(&user)
	if result.Error != nil {
		return utils.ErrorResponse(c, fiber.StatusUnauthorized, config.AppMessages.Auth.Error.InvalidCredentials, nil)
	}

	// Check password
	if !utils.CheckPassword(req.Password, user.Password) {
		return utils.ErrorResponse(c, fiber.StatusUnauthorized, config.AppMessages.Auth.Error.InvalidCredentials, nil)
	}

	// Check if user is blocked
	if user.IsBlocked {
		return utils.ErrorResponse(c, fiber.StatusForbidden, config.AppMessages.Auth.Error.AccountBlocked, nil)
	}

	// Create new token
	tokenService := services.NewTokenService()
	token, err := tokenService.CreateAuthTokenForUser(
		user,
		c.Get("User-Agent"),
		c.IP(),
	)
	if err != nil {
		return utils.ErrorResponse(c, fiber.StatusInternalServerError, config.AppMessages.Server.Error.Internal, err)
	}

	// Update last login time
	now := time.Now()
	if err := database.DB.Model(&user).Update("last_login_at", &now).Error; err != nil {
		return utils.ErrorResponse(c, fiber.StatusInternalServerError, config.AppMessages.Server.Error.Internal, nil)
	}

	return utils.SuccessResponse(c, config.AppMessages.Auth.Success.Login, fiber.Map{
		"token": token.Token,
	})
}

// RequestPasswordReset initiates the password reset process
func RequestPasswordReset(c *fiber.Ctx) error {
	var req PasswordResetRequest
	if err := utils.ValidateRequest(c, &req); err != nil {
		return err
	}

	// Find user by email
	var user models.User
	result := database.DB.Where("email = ?", req.Email).First(&user)
	if result.Error != nil {
		// Don't reveal if user exists
		return utils.SuccessResponse(c, config.AppMessages.Auth.Success.PasswordResetRequested, nil)
	}

	// Generate password reset token
	tokenService := services.NewTokenService()
	token, err := tokenService.CreatePasswordResetTokenForUser(user, c.Get("User-Agent"), c.IP())
	if err != nil {
		return utils.ErrorResponse(c, fiber.StatusInternalServerError, config.AppMessages.Server.Error.Internal, nil)
	}

	// Send password reset email
	mailer := services.NewMailerService(&config.AppConfig)
	if err := mailer.SendPasswordResetEmail(user.Email, token.Token); err != nil {
		return utils.ErrorResponse(c, fiber.StatusInternalServerError, config.AppMessages.Server.Error.MailService, nil)
	}

	return utils.SuccessResponse(c, config.AppMessages.Auth.Success.PasswordResetRequested, nil)
}

// ResetPassword handles password reset with token
func ResetPassword(c *fiber.Ctx) error {
	var req ResetPasswordRequest
	if err := utils.ValidateRequest(c, &req); err != nil {
		return err
	}

	// Validate token
	claims, err := utils.ValidateToken(req.Token)
	if err != nil {
		return utils.ErrorResponse(c, fiber.StatusUnauthorized, config.AppMessages.Auth.Error.InvalidToken, nil)
	}

	// Verify token type
	if claims.TokenType != string(utils.PasswordResetToken) {
		return utils.ErrorResponse(c, fiber.StatusUnauthorized, config.AppMessages.Auth.Error.InvalidTokenType, nil)
	}

	// Validate password strength
	if err := utils.ValidatePasswordStrength(req.Password); err != nil {
		return utils.ErrorResponse(c, fiber.StatusBadRequest, err.Error(), nil)
	}

	// Hash new password
	hashedPassword, err := utils.HashPassword(req.Password)
	if err != nil {
		return utils.ErrorResponse(c, fiber.StatusInternalServerError, config.AppMessages.Server.Error.Internal, nil)
	}

	// Start a transaction
	tx := database.DB.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Update password
	if err := tx.Model(&models.User{}).Where("id = ?", claims.UserID).Update("password", hashedPassword).Error; err != nil {
		tx.Rollback()
		return utils.ErrorResponse(c, fiber.StatusInternalServerError, config.AppMessages.Server.Error.Internal, nil)
	}

	// Delete the used token
	if err := tx.Where("token = ?", req.Token).Delete(&models.Token{}).Error; err != nil {
		tx.Rollback()
		return utils.ErrorResponse(c, fiber.StatusInternalServerError, config.AppMessages.Server.Error.Internal, nil)
	}

	if err := tx.Commit().Error; err != nil {
		return utils.ErrorResponse(c, fiber.StatusInternalServerError, config.AppMessages.Server.Error.Internal, nil)
	}

	return utils.SuccessResponse(c, config.AppMessages.Auth.Success.PasswordReset, nil)
}

// ConfirmEmail handles email verification
func ConfirmEmail(c *fiber.Ctx) error {
	token := c.Query("token")
	if token == "" {
		return utils.ErrorResponse(c, fiber.StatusBadRequest, config.AppMessages.Auth.Error.TokenRequired, nil)
	}

	// Validate token
	claims, err := utils.ValidateToken(token)
	if err != nil {
		return utils.ErrorResponse(c, fiber.StatusUnauthorized, config.AppMessages.Auth.Error.InvalidToken, nil)
	}

	// Verify token type
	if claims.TokenType != string(utils.EmailVerificationToken) {
		return utils.ErrorResponse(c, fiber.StatusUnauthorized, config.AppMessages.Auth.Error.InvalidTokenType, nil)
	}

	// Start a transaction
	tx := database.DB.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Update user verification status
	if err := tx.Model(&models.User{}).Where("id = ?", claims.UserID).Update("is_verified", true).Error; err != nil {
		tx.Rollback()
		return utils.ErrorResponse(c, fiber.StatusInternalServerError, config.AppMessages.Server.Error.Internal, nil)
	}

	// Delete the used token
	if err := tx.Where("token = ?", token).Delete(&models.Token{}).Error; err != nil {
		tx.Rollback()
		return utils.ErrorResponse(c, fiber.StatusInternalServerError, config.AppMessages.Server.Error.Internal, nil)
	}

	if err := tx.Commit().Error; err != nil {
		return utils.SuccessResponse(c, config.AppMessages.Auth.Success.EmailVerified, nil)
	}

	return utils.SuccessResponse(c, config.AppMessages.Auth.Success.EmailVerified, nil)
}

// UserInfo returns the current user's information
func UserInfo(c *fiber.Ctx) error {
	user := c.Locals("user").(models.User)
	return utils.SuccessResponse(c, "", user)
}

// ChangePassword handles password change for authenticated users
func ChangePassword(c *fiber.Ctx) error {
	var req ChangePasswordRequest
	if err := utils.ValidateRequest(c, &req); err != nil {
		return err
	}

	user := c.Locals("user").(models.User)

	// Verify old password
	if !utils.CheckPassword(req.OldPassword, user.Password) {
		return utils.ErrorResponse(c, fiber.StatusUnauthorized, config.AppMessages.Auth.Error.InvalidPassword, nil)
	}

	// Validate new password strength
	if err := utils.ValidatePasswordStrength(req.NewPassword); err != nil {
		return utils.ErrorResponse(c, fiber.StatusBadRequest, err.Error(), nil)
	}

	// Hash new password
	hashedPassword, err := utils.HashPassword(req.NewPassword)
	if err != nil {
		return utils.ErrorResponse(c, fiber.StatusInternalServerError, config.AppMessages.Server.Error.Internal, nil)
	}

	// Update password
	result := database.DB.Model(&user).Update("password", hashedPassword)
	if result.Error != nil {
		return utils.ErrorResponse(c, fiber.StatusInternalServerError, config.AppMessages.Server.Error.Internal, nil)
	}

	return utils.SuccessResponse(c, config.AppMessages.Auth.Success.PasswordChanged, nil)
}

// ChangeEmail initiates email change process
func ChangeEmail(c *fiber.Ctx) error {
	var req ChangeEmailRequest
	if err := utils.ValidateRequest(c, &req); err != nil {
		return err
	}

	user := c.Locals("user").(models.User)

	// Verify password
	if !utils.CheckPassword(req.Password, user.Password) {
		return utils.ErrorResponse(c, fiber.StatusUnauthorized, config.AppMessages.Auth.Error.InvalidPassword, nil)
	}

	// Check if new email is already registered
	var existingUser models.User
	if result := database.DB.Where("email = ?", req.NewEmail).First(&existingUser); result.Error == nil {
		return utils.ErrorResponse(c, fiber.StatusConflict, config.AppMessages.Auth.Error.EmailExists, nil)
	}

	// Update email
	result := database.DB.Model(&user).Updates(map[string]interface{}{
		"email":       req.NewEmail,
		"is_verified": false,
	})
	if result.Error != nil {
		return utils.ErrorResponse(c, fiber.StatusInternalServerError, config.AppMessages.Server.Error.Internal, nil)
	}

	// Generate new verification token if required
	if config.AppConfig.Auth.RequireEmailVerification {
		tokenService := services.NewTokenService()
		token, err := tokenService.CreateEmailVerificationTokenForUser(user, c.Get("User-Agent"), c.IP())
		if err != nil {
			return utils.ErrorResponse(c, fiber.StatusInternalServerError, config.AppMessages.Server.Error.Internal, nil)
		}

		// Send verification email
		mailer := services.NewMailerService(&config.AppConfig)
		if err := mailer.SendVerificationEmail(req.NewEmail, token.Token); err != nil {
			return utils.ErrorResponse(c, fiber.StatusInternalServerError, config.AppMessages.Server.Error.MailService, nil)
		}
	}

	return utils.SuccessResponse(c, config.AppMessages.Auth.Success.EmailChanged, nil)
}