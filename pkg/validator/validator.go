package validator

import (
	"github.com/go-playground/validator"
)

var Validate *validator.Validate

func InitValidator() {
	Validate = validator.New()
}
