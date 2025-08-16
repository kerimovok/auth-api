package services

import (
	"auth-api/internal/config"
	"auth-api/internal/constants"
	"auth-api/internal/database"
	"auth-api/internal/models"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"

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

// ValidateTokenByValue validates a token by its actual value instead of UUID
func (s *TokenService) ValidateTokenByValue(tokenValue string, tokenType constants.TokenType) (*models.Token, error) {
	var token models.Token
	err := s.db.Where("value = ? AND type = ?", tokenValue, string(tokenType)).First(&token).Error
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

// GetTokenConfig returns the configuration for a specific token type
func (s *TokenService) GetTokenConfig(tokenType constants.TokenType) (*config.TokenConfig, error) {
	if !constants.IsValidTokenType(tokenType) {
		return nil, fmt.Errorf("invalid token type: %s", tokenType)
	}

	switch tokenType {
	case constants.RefreshToken:
		return &config.Auth.Tokens.RefreshToken, nil
	case constants.EmailVerificationToken:
		return &config.Auth.Tokens.EmailVerification, nil
	case constants.PasswordResetToken:
		return &config.Auth.Tokens.PasswordReset, nil
	default:
		return nil, fmt.Errorf("token type %s not configured", tokenType)
	}
}

// CreateToken creates a token of any type using unified configuration
func (s *TokenService) CreateToken(user models.User, tokenType constants.TokenType, userAgent string, ip string) (*models.Token, error) {
	tokenConfig, err := s.GetTokenConfig(tokenType)
	if err != nil {
		return nil, err
	}

	expiry, err := time.ParseDuration(tokenConfig.Expiry)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s token expiry: %w", tokenType, err)
	}

	if tokenConfig.RevokeExisting {
		if err := s.RevokeAllUserTokens(user.ID, tokenType); err != nil {
			return nil, fmt.Errorf("failed to revoke existing %s tokens: %w", tokenType, err)
		}
	}

	return s.createToken(user, tokenType, expiry, userAgent, ip)
}

func (s *TokenService) createToken(user models.User, tokenType constants.TokenType, expiry time.Duration, userAgent string, ip string) (*models.Token, error) {
	tokenValue, err := s.generateTokenValue()
	if err != nil {
		return nil, fmt.Errorf("failed to generate token value: %w", err)
	}

	token := &models.Token{
		UserID:    user.ID,
		Type:      string(tokenType),
		ExpiresAt: time.Now().Add(expiry),
		UserAgent: userAgent,
		IP:        ip,
		Value:     tokenValue, // Store the actual token value
	}

	if err := s.db.Create(token).Error; err != nil {
		return nil, fmt.Errorf("failed to create token: %w", err)
	}

	return token, nil
}

func (s *TokenService) CreateRefreshToken(user models.User, userAgent string, ip string) (*models.Token, error) {
	// Use unified token creation but add family tracking for refresh tokens
	token, err := s.CreateToken(user, constants.RefreshToken, userAgent, ip)
	if err != nil {
		return nil, err
	}

	// Add family tracking for refresh tokens (rotation security)
	familyID := uuid.New()
	token.Family = &familyID
	token.ParentID = nil // Initial token has no parent

	if err := s.db.Save(token).Error; err != nil {
		return nil, fmt.Errorf("failed to update refresh token family: %w", err)
	}

	return token, nil
}

// RotateRefreshToken creates a new refresh token from an existing one with family tracking
func (s *TokenService) RotateRefreshToken(oldToken *models.Token, userAgent string, ip string) (*models.Token, error) {
	expiry, err := time.ParseDuration(config.Auth.Tokens.RefreshToken.Expiry)
	if err != nil {
		return nil, fmt.Errorf("failed to parse refresh token expiry: %w", err)
	}

	// Create new token in the same family
	newToken := &models.Token{
		UserID:    oldToken.UserID,
		Type:      string(constants.RefreshToken),
		ExpiresAt: time.Now().Add(expiry),
		UserAgent: userAgent,
		IP:        ip,
		Family:    oldToken.Family, // Same family as parent
		ParentID:  &oldToken.ID,    // Link to parent token
	}

	if err := s.db.Create(newToken).Error; err != nil {
		return nil, fmt.Errorf("failed to create rotated refresh token: %w", err)
	}

	return newToken, nil
}

// RevokeTokenFamily revokes all tokens in a family (security breach detection)
func (s *TokenService) RevokeTokenFamily(familyID uuid.UUID) error {
	now := time.Now()
	result := s.db.Model(&models.Token{}).
		Where("family = ? AND revoked_at IS NULL", familyID).
		Update("revoked_at", &now)

	if result.Error != nil && !errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return fmt.Errorf("failed to revoke token family: %w", result.Error)
	}

	return nil
}

func (s *TokenService) CreateEmailVerificationToken(user models.User, userAgent string, ip string) (*models.Token, error) {
	return s.CreateToken(user, constants.EmailVerificationToken, userAgent, ip)
}

func (s *TokenService) CreatePasswordResetToken(user models.User, userAgent string, ip string) (*models.Token, error) {
	return s.CreateToken(user, constants.PasswordResetToken, userAgent, ip)
}

// CleanupExpiredTokens removes expired and revoked tokens
func (s *TokenService) CleanupExpiredTokens() error {
	return s.db.Where("expires_at < ? OR revoked_at IS NOT NULL", time.Now()).
		Delete(&models.Token{}).Error
}

// generateTokenValue creates a cryptographically secure random token value
func (s *TokenService) generateTokenValue() (string, error) {
	bytes := make([]byte, 32) // 256 bits
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
