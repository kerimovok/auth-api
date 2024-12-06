package validator

import (
	"errors"
	"fmt"

	"github.com/go-playground/validator"
)

var Validate *validator.Validate

func InitValidator() {
	Validate = validator.New()
}

// ValidateStruct validates a struct using validator tags
func ValidateStruct(s interface{}) error {
	// Validate struct
	if err := Validate.Struct(s); err != nil {
		// Check if it's a validation error
		var validationErrors validator.ValidationErrors
		if errors.As(err, &validationErrors) {
			for _, validationErr := range validationErrors {
				return fmt.Errorf("field '%s' failed validation on the '%s' tag", validationErr.Field(), validationErr.Tag())
			}
		}
	}

	return nil
}
