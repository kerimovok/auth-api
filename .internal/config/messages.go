package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Messages struct {
	Auth struct {
		Success struct {
			Registration           string `yaml:"registration"`
			Login                  string `yaml:"login"`
			Logout                 string `yaml:"logout"`
			PasswordChanged        string `yaml:"password_changed"`
			EmailChanged           string `yaml:"email_changed"`
			EmailVerified          string `yaml:"email_verified"`
			PasswordReset          string `yaml:"password_reset"`
			PasswordResetRequested string `yaml:"password_reset_requested"`
			AccountDeleted         string `yaml:"account_deleted"`
		} `yaml:"success"`
		Error struct {
			InvalidCredentials        string `yaml:"invalid_credentials"`
			InvalidToken              string `yaml:"invalid_token"`
			InvalidTokenType          string `yaml:"invalid_token_type"`
			AccountBlocked            string `yaml:"account_blocked"`
			EmailExists               string `yaml:"email_exists"`
			EmailVerificationRequired string `yaml:"email_verification_required"`
			AdminRequired             string `yaml:"admin_required"`
			InvalidPassword           string `yaml:"invalid_password"`
			TokenRequired             string `yaml:"token_required"`
		} `yaml:"error"`
	} `yaml:"auth"`
	Validation struct {
		Error struct {
			InvalidRequest   string `yaml:"invalid_request"`
			PasswordStrength struct {
				MinLength        string `yaml:"min_length"`
				MaxLength        string `yaml:"max_length"`
				RequireUppercase string `yaml:"require_uppercase"`
				RequireLowercase string `yaml:"require_lowercase"`
				RequireNumbers   string `yaml:"require_numbers"`
				RequireSpecial   string `yaml:"require_special"`
			} `yaml:"password_strength"`
		} `yaml:"error"`
	} `yaml:"validation"`
	Server struct {
		Error struct {
			Internal    string `yaml:"internal"`
			Database    string `yaml:"database"`
			MailService string `yaml:"mail_service"`
		} `yaml:"error"`
	} `yaml:"server"`
}

var AppMessages Messages

func LoadMessages() error {
	file, err := os.ReadFile("config/messages.yaml")
	if err != nil {
		return err
	}

	return yaml.Unmarshal(file, &AppMessages)
}
