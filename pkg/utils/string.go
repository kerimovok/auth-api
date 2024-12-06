package utils

import "strings"

// NormalizeString standardizes a string
func NormalizeString(input string) string {
	return strings.ToLower(strings.TrimSpace(input))
}
