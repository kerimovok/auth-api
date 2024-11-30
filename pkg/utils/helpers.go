package utils

import (
	"fmt"
	"github.com/gofiber/fiber/v2/log"
	"strings"
)

// NormalizeEmail standardizes email format
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// LogError provides consistent error logging
func LogError(operation string, err error) {
	log.Errorf("failed to %s: %v", operation, err)
}

// WrapError provides consistent error wrapping
func WrapError(operation string, err error) error {
	return fmt.Errorf("failed to %s: %w", operation, err)
}
