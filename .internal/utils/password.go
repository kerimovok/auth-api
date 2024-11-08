package utils

import (
	"fmt"
	"strings"
	"unicode"

	"auth-api/.internal/config"
)

func ValidatePasswordStrength(password string) error {
	if len(password) < config.AppConfig.Auth.PasswordStrength.MinLength {
		return fmt.Errorf(config.AppMessages.Validation.Error.PasswordStrength.MinLength, config.AppConfig.Auth.PasswordStrength.MinLength)
	}

	if len(password) > config.AppConfig.Auth.PasswordStrength.MaxLength {
		return fmt.Errorf(config.AppMessages.Validation.Error.PasswordStrength.MaxLength, config.AppConfig.Auth.PasswordStrength.MaxLength)
	}

	var (
		hasUpper   bool
		hasLower   bool
		hasNumber  bool
		hasSpecial bool
	)

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case strings.ContainsRune("!@#$%^&*()_+-=[]{}|;:,.<>?", char):
			hasSpecial = true
		}
	}

	if config.AppConfig.Auth.PasswordStrength.RequireUppercase && !hasUpper {
		return fmt.Errorf(config.AppMessages.Validation.Error.PasswordStrength.RequireUppercase)
	}

	if config.AppConfig.Auth.PasswordStrength.RequireLowercase && !hasLower {
		return fmt.Errorf(config.AppMessages.Validation.Error.PasswordStrength.RequireLowercase)
	}

	if config.AppConfig.Auth.PasswordStrength.RequireNumbers && !hasNumber {
		return fmt.Errorf(config.AppMessages.Validation.Error.PasswordStrength.RequireNumbers)
	}

	if config.AppConfig.Auth.PasswordStrength.RequireSpecial && !hasSpecial {
		return fmt.Errorf(config.AppMessages.Validation.Error.PasswordStrength.RequireSpecial)
	}

	return nil
}
