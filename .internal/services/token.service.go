package services

import (
	"auth-api/.internal/config"
	"auth-api/.internal/database"
	"auth-api/.internal/models"
	"auth-api/.internal/utils"
	"fmt"
	"time"

	"github.com/google/uuid"

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

func (s *TokenService) CreateToken(userID uuid.UUID, tokenType utils.TokenType, expiresAt time.Time, userAgent, ip string) (*models.Token, error) {
	// Generate JWT token
	claims := utils.Claims{
		UserID:    userID,
		TokenType: string(tokenType),
	}

	tokenString, err := utils.GenerateToken(claims, time.Until(expiresAt))
	if err != nil {
		return nil, err
	}

	// Store token in database
	token := &models.Token{
		UserID:    userID,
		Token:     tokenString,
		Type:      string(tokenType),
		ExpiresAt: expiresAt,
		UserAgent: userAgent,
		IP:        ip,
	}

	if err := s.db.Create(token).Error; err != nil {
		return nil, err
	}

	return token, nil
}

func (s *TokenService) ValidateToken(tokenString string, tokenType utils.TokenType) (*models.Token, error) {
	// First validate JWT
	claims, err := utils.ValidateToken(tokenString)
	if err != nil {
		return nil, err
	}

	// Check token type
	if claims.TokenType != string(tokenType) {
		return nil, fmt.Errorf("invalid token type")
	}

	// Find token in database
	var token models.Token
	err = s.db.Where("token = ? AND type = ?", tokenString, string(tokenType)).First(&token).Error
	if err != nil {
		return nil, err
	}

	// Check if token is valid
	if !token.IsValid() {
		return nil, fmt.Errorf("token is invalid or expired")
	}

	return &token, nil
}

func (s *TokenService) RevokeToken(tokenID uint) error {
	now := time.Now()
	return s.db.Model(&models.Token{}).Where("id = ?", tokenID).Update("revoked_at", &now).Error
}

func (s *TokenService) RevokeAllUserTokens(userID uint, tokenType utils.TokenType) error {
	now := time.Now()
	return s.db.Model(&models.Token{}).
		Where("user_id = ? AND type = ? AND revoked_at IS NULL", userID, string(tokenType)).
		Update("revoked_at", &now).Error
}

// CreateAuthTokenForUser creates a new auth token with config-based expiry
func (s *TokenService) CreateAuthTokenForUser(user models.User, userAgent, ip string) (*models.Token, error) {
	// Parse duration from config
	expiry, err := time.ParseDuration(config.AppConfig.Auth.JWT.TokenExpiry.Auth)
	if err != nil {
		return nil, fmt.Errorf("invalid auth token expiry configuration: %w", err)
	}

	return s.CreateToken(
		user.ID,
		utils.AuthToken,
		time.Now().Add(expiry),
		userAgent,
		ip,
	)
}

func (s *TokenService) CreateEmailVerificationTokenForUser(user models.User, userAgent, ip string) (*models.Token, error) {
	expiry, err := time.ParseDuration(config.AppConfig.Auth.JWT.TokenExpiry.EmailVerification)
	if err != nil {
		return nil, fmt.Errorf("invalid email verification token expiry configuration: %w", err)
	}

	return s.CreateToken(
		user.ID,
		utils.EmailVerificationToken,
		time.Now().Add(expiry),
		userAgent,
		ip,
	)
}

func (s *TokenService) CreatePasswordResetTokenForUser(user models.User, userAgent, ip string) (*models.Token, error) {
	expiry, err := time.ParseDuration(config.AppConfig.Auth.JWT.TokenExpiry.PasswordReset)
	if err != nil {
		return nil, fmt.Errorf("invalid password reset token expiry configuration: %w", err)
	}

	return s.CreateToken(
		user.ID,
		utils.PasswordResetToken,
		time.Now().Add(expiry),
		userAgent,
		ip,
	)
}
