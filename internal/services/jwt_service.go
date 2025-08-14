package services

import (
	"auth-api/internal/config"
	"auth-api/internal/models"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	pkgConfig "github.com/kerimovok/go-pkg-utils/config"
)

type JWTClaims struct {
	UserID     uuid.UUID `json:"user_id"`
	Email      string    `json:"email"`
	IsAdmin    bool      `json:"is_admin"`
	IsVerified bool      `json:"is_verified"`
	jwt.RegisteredClaims
}

type JWTService struct {
	accessTokenExpiry time.Duration
	secretKey         []byte
}

func NewJWTService() *JWTService {
	// Parse expiry once during service creation
	expiry, err := time.ParseDuration(config.Auth.Tokens.AccessToken.Expiry)
	if err != nil {
		// Use default if parsing fails
		expiry = 15 * time.Minute
	}

	return &JWTService{
		accessTokenExpiry: expiry,
		secretKey:         []byte(pkgConfig.GetEnv("JWT_SECRET")),
	}
}

// GenerateAccessToken creates a short-lived JWT access token
func (s *JWTService) GenerateAccessToken(user models.User) (string, error) {
	now := time.Now()
	claims := JWTClaims{
		UserID:     user.ID,
		Email:      user.Email,
		IsAdmin:    user.IsAdmin,
		IsVerified: user.IsVerified,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(s.accessTokenExpiry)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    "auth-api",
			Subject:   user.ID.String(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(s.secretKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign access token: %w", err)
	}

	return tokenString, nil
}

// ValidateAccessToken parses and validates a JWT access token
func (s *JWTService) ValidateAccessToken(tokenString string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.secretKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if claims, ok := token.Claims.(*JWTClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token claims")
}

// TokenResponse represents the response structure for token operations
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

// GenerateTokenPair creates both access and refresh tokens
func (s *JWTService) GenerateTokenPair(user models.User, userAgent string, ip string) (*TokenResponse, *models.Token, error) {
	// Generate access token
	accessToken, err := s.GenerateAccessToken(user)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Create refresh token in database
	tokenService := NewTokenService()
	refreshToken, err := tokenService.CreateRefreshToken(user, userAgent, ip)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create refresh token: %w", err)
	}

	response := &TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken.ID.String(),
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.accessTokenExpiry.Seconds()),
	}

	return response, refreshToken, nil
}

// RefreshTokenPair rotates the refresh token and generates a new access token
func (s *JWTService) RefreshTokenPair(oldRefreshToken *models.Token, userAgent string, ip string) (*TokenResponse, error) {
	// Get user for new access token
	var user models.User
	if err := NewTokenService().db.First(&user, "id = ?", oldRefreshToken.UserID).Error; err != nil {
		return nil, fmt.Errorf("failed to find user: %w", err)
	}

	// Generate new access token
	accessToken, err := s.GenerateAccessToken(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Rotate refresh token
	tokenService := NewTokenService()
	newRefreshToken, err := tokenService.RotateRefreshToken(oldRefreshToken, userAgent, ip)
	if err != nil {
		return nil, fmt.Errorf("failed to rotate refresh token: %w", err)
	}

	response := &TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken.ID.String(),
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.accessTokenExpiry.Seconds()),
	}

	return response, nil
}
