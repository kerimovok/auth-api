package validator

import (
	"github.com/go-playground/validator"
)

var Validate *validator.Validate

func InitValidator() {
	Validate = validator.New()

	// Optional: Register custom validation tags if needed
	// Validate.RegisterValidation("custom_tag", customValidationFunc)
}
