package utils

import (
	"auth-api/.internal/validator"
	"fmt"

	validatorv10 "github.com/go-playground/validator"
	"github.com/gofiber/fiber/v2"
)

// ValidateRequest validates a struct using validator tags
func ValidateRequest(c *fiber.Ctx, req interface{}) error {
	// Parse request body
	if err := c.BodyParser(req); err != nil {
		return err
	}

	// Validate struct
	if err := validator.Validate.Struct(req); err != nil {
		// Check if it's a validation error
		if validationErrors, ok := err.(validatorv10.ValidationErrors); ok {
			for _, validationErr := range validationErrors {
				return fmt.Errorf("field '%s' failed validation on the '%s' tag", validationErr.Field(), validationErr.Tag())
			}
		} else {
			// Handle other types of errors
			return err
		}
	}

	return nil
}
