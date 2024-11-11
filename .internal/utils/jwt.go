package utils

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type TokenType string

const (
	AuthToken              TokenType = "auth"
	EmailVerificationToken TokenType = "email_verification"
	PasswordResetToken     TokenType = "password_reset"
)

// TODO: Define claims based on config
type Claims struct {
	UserID    uuid.UUID `json:"userId"`
	TokenType string    `json:"tokenType"`
	jwt.RegisteredClaims
}

// GenerateToken creates a new JWT token
func GenerateToken(claims Claims, expiry time.Duration) (string, error) {
	key := []byte(os.Getenv("JWT_SECRET"))
	claims.RegisteredClaims = jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiry)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(key)
}

// ValidateToken validates and returns claims from a JWT token
func ValidateToken(tokenString string) (*Claims, error) {
	key := []byte(os.Getenv("JWT_SECRET"))
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return key, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

// ExtractBearerToken extracts the token from the Authorization header
func ExtractBearerToken(header string) (string, error) {
	if header == "" {
		return "", fmt.Errorf("authorization header is required")
	}

	parts := strings.Split(header, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return "", fmt.Errorf("invalid authorization header format")
	}

	return parts[1], nil
}
