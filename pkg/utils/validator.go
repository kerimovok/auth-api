package utils

import (
	"fmt"
	"strings"
)

// ValidationRule defines a validation function that returns an error if validation fails
type ValidationRule struct {
	Variable string
	Default  string
	Rule     func(value string) bool
	Message  string
}

// ValidateConfig checks all required configuration values
func ValidateConfig(rules []ValidationRule) error {
	var errors []string
	for _, rule := range rules {
		value := GetEnvOrDefault(rule.Variable, rule.Default)
		if !rule.Rule(value) {
			errors = append(errors, rule.Message)
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("validation failed: %s", strings.Join(errors, "; "))
	}

	return nil
}
