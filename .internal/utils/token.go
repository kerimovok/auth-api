package utils

type TokenType string

const (
	AuthToken              TokenType = "auth"
	EmailVerificationToken TokenType = "email_verification"
	PasswordResetToken     TokenType = "password_reset"
)
