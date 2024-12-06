package utils

import (
	"net/mail"
	"net/url"
	"os"
	"strconv"
)

// Custom validation helper functions
func IsValidPort(port string) bool {
	if port == "" {
		return false
	}
	portNum, err := strconv.Atoi(port)
	return err == nil && portNum > 0 && portNum <= 65535
}

func IsValidEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

func IsValidURL(urlStr string) bool {
	_, err := url.ParseRequestURI(urlStr)
	return err == nil
}

func GetEnvOrDefault(key, defaultValue string) string {
	if value := GetEnv(key); value != "" {
		return value
	}
	return defaultValue
}

func GetEnv(key string) string {
	return os.Getenv(key)
}
