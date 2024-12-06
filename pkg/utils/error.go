package utils

import (
	"fmt"
)

// WrapError provides consistent error wrapping
func WrapError(operation string, err error) error {
	return fmt.Errorf("failed to %s: %w", operation, err)
}
