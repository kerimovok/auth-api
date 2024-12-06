package helpers

import (
	"auth-api/internal/config"
	"fmt"
	"strings"
	"unicode"
)

func ValidatePasswordStrength(password string) error {
	if len(password) < config.Auth.PasswordStrength.MinLength {
		return fmt.Errorf(config.Messages.Validation.Error.PasswordStrength.MinLength, config.Auth.PasswordStrength.MinLength)
	}

	if len(password) > config.Auth.PasswordStrength.MaxLength {
		return fmt.Errorf(config.Messages.Validation.Error.PasswordStrength.MaxLength, config.Auth.PasswordStrength.MaxLength)
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

	if config.Auth.PasswordStrength.RequireUppercase && !hasUpper {
		return fmt.Errorf(config.Messages.Validation.Error.PasswordStrength.RequireUppercase)
	}

	if config.Auth.PasswordStrength.RequireLowercase && !hasLower {
		return fmt.Errorf(config.Messages.Validation.Error.PasswordStrength.RequireLowercase)
	}

	if config.Auth.PasswordStrength.RequireNumbers && !hasNumber {
		return fmt.Errorf(config.Messages.Validation.Error.PasswordStrength.RequireNumbers)
	}

	if config.Auth.PasswordStrength.RequireSpecial && !hasSpecial {
		return fmt.Errorf(config.Messages.Validation.Error.PasswordStrength.RequireSpecial)
	}

	return nil
}
