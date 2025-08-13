package services

import (
	"auth-api/internal/config"
	"auth-api/internal/constants"
	"auth-api/internal/models"
	"auth-api/pkg/database"
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	pkgNet "github.com/kerimovok/go-pkg-utils/net"

	"errors"

	"gorm.io/gorm"
)

type TokenService struct {
	db *gorm.DB
}

func NewTokenService() *TokenService {
	return &TokenService{
		db: database.DB,
	}
}

func (s *TokenService) ValidateToken(tokenID uuid.UUID, tokenType constants.TokenType) (*models.Token, error) {
	var token models.Token
	err := s.db.Where("id = ? AND type = ?", tokenID, string(tokenType)).First(&token).Error
	if err != nil {
		return nil, fmt.Errorf("failed to validate token: %w", fmt.Errorf("token not found: %w", err))
	}

	if !token.IsValid() {
		return nil, fmt.Errorf("failed to validate token: %w", fmt.Errorf("token is invalid or expired"))
	}

	return &token, nil
}

func (s *TokenService) RevokeToken(tokenID uuid.UUID) error {
	now := time.Now()
	return s.db.Model(&models.Token{}).
		Where("id = ? AND revoked_at IS NULL", tokenID).
		Update("revoked_at", &now).Error
}

func (s *TokenService) RevokeAllUserTokens(userID uuid.UUID, tokenType constants.TokenType) error {
	now := time.Now()
	result := s.db.Model(&models.Token{}).
		Where("user_id = ? AND type = ? AND revoked_at IS NULL", userID, string(tokenType)).
		Update("revoked_at", &now)

	// Ignore "record not found" errors
	if result.Error != nil && !errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return fmt.Errorf("failed to revoke tokens: %w", result.Error)
	}

	return nil
}

func (s *TokenService) RevokeAllUserTokensExcept(userID uuid.UUID, tokenType constants.TokenType, exceptTokenID uuid.UUID) error {
	now := time.Now()
	result := s.db.Model(&models.Token{}).
		Where("user_id = ? AND type = ? AND id != ? AND revoked_at IS NULL",
			userID, string(tokenType), exceptTokenID).
		Update("revoked_at", &now)

	if result.Error != nil && !errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return fmt.Errorf("failed to revoke tokens: %w", result.Error)
	}

	return nil
}

func (s *TokenService) createToken(user models.User, tokenType constants.TokenType, expiry time.Duration, userAgent string, c *fiber.Ctx) (*models.Token, error) {
	token := &models.Token{
		UserID:    user.ID,
		Type:      string(tokenType),
		ExpiresAt: time.Now().Add(expiry),
		UserAgent: userAgent,
		IP:        pkgNet.GetUserIP(c),
	}

	if err := s.db.Create(token).Error; err != nil {
		return nil, fmt.Errorf("failed to create token: %w", err)
	}

	return token, nil
}

func (s *TokenService) CreateAuthTokenForUser(user models.User, userAgent string, c *fiber.Ctx) (*models.Token, error) {
	expiry, err := time.ParseDuration(config.Auth.Token.Auth.Expiry)
	if err != nil {
		return nil, fmt.Errorf("failed to parse auth token expiry: %w", err)
	}

	if config.Auth.Token.Auth.RevokeExisting {
		if err := s.RevokeAllUserTokens(user.ID, constants.AuthToken); err != nil {
			return nil, fmt.Errorf("failed to revoke existing auth tokens: %w", err)
		}
	}

	return s.createToken(user, constants.AuthToken, expiry, userAgent, c)
}

func (s *TokenService) CreateEmailVerificationToken(user models.User, userAgent string, c *fiber.Ctx) (*models.Token, error) {
	expiry, err := time.ParseDuration(config.Auth.Token.Verification.Expiry)
	if err != nil {
		return nil, fmt.Errorf("failed to parse verification token expiry: %w", err)
	}

	if config.Auth.Token.Verification.RevokeExisting {
		if err := s.RevokeAllUserTokens(user.ID, constants.EmailVerificationToken); err != nil {
			return nil, fmt.Errorf("failed to revoke existing verification tokens: %w", err)
		}
	}

	return s.createToken(user, constants.EmailVerificationToken, expiry, userAgent, c)
}

func (s *TokenService) CreatePasswordResetToken(user models.User, userAgent string, c *fiber.Ctx) (*models.Token, error) {
	expiry, err := time.ParseDuration(config.Auth.Token.PasswordReset.Expiry)
	if err != nil {
		return nil, fmt.Errorf("failed to parse password reset token expiry: %w", err)
	}

	if config.Auth.Token.PasswordReset.RevokeExisting {
		if err := s.RevokeAllUserTokens(user.ID, constants.PasswordResetToken); err != nil {
			return nil, fmt.Errorf("failed to revoke existing password reset tokens: %w", err)
		}
	}

	return s.createToken(user, constants.PasswordResetToken, expiry, userAgent, c)
}

// CleanupExpiredTokens removes expired and revoked tokens
func (s *TokenService) CleanupExpiredTokens() error {
	return s.db.Where("expires_at < ? OR revoked_at IS NOT NULL", time.Now()).
		Delete(&models.Token{}).Error
}
