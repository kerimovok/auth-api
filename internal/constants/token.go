package constants

type TokenType string

const (
	RefreshToken           TokenType = "refresh_token"
	EmailVerificationToken TokenType = "email_verification"
	PasswordResetToken     TokenType = "password_reset"
)

// GetAllTokenTypes returns all available token types
func GetAllTokenTypes() []TokenType {
	return []TokenType{
		RefreshToken,
		EmailVerificationToken,
		PasswordResetToken,
	}
}

// IsValidTokenType checks if a token type is valid
func IsValidTokenType(tokenType TokenType) bool {
	for _, t := range GetAllTokenTypes() {
		if t == tokenType {
			return true
		}
	}
	return false
}
