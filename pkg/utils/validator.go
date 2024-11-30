package utils

import (
	"auth-api/pkg/validator"
	"errors"
	"fmt"

	validatorv10 "github.com/go-playground/validator"
)

// ValidateRequest validates a struct using validator tags
func ValidateRequest(req interface{}) error {
	// Validate struct
	if err := validator.Validate.Struct(req); err != nil {
		// Check if it's a validation error
		var validationErrors validatorv10.ValidationErrors
		if errors.As(err, &validationErrors) {
			for _, validationErr := range validationErrors {
				return fmt.Errorf("field '%s' failed validation on the '%s' tag", validationErr.Field(), validationErr.Tag())
			}
		}
	}

	return nil
}
