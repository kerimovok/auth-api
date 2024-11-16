package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type AuthConfig struct {
	Verification struct {
		Required    bool   `yaml:"required"`
		Expiry      string `yaml:"expiry"`
		RedirectURL string `yaml:"redirect_url"`
	} `yaml:"verification"`
	PasswordReset struct {
		Expiry string `yaml:"expiry"`
	} `yaml:"password_reset"`
	Allow struct {
		PasswordReset    bool `yaml:"password_reset"`
		ConcurrentLogins bool `yaml:"concurrent_logins"`
	} `yaml:"allow"`
	PasswordStrength struct {
		MinLength        int  `yaml:"min_length"`
		MaxLength        int  `yaml:"max_length"`
		RequireUppercase bool `yaml:"require_uppercase"`
		RequireLowercase bool `yaml:"require_lowercase"`
		RequireNumbers   bool `yaml:"require_numbers"`
		RequireSpecial   bool `yaml:"require_special"`
	} `yaml:"password_strength"`
	JWT struct {
		Expiry string `yaml:"expiry"`
	} `yaml:"jwt"`
}

type MailerConfig struct {
	Auth struct {
		Enabled bool `yaml:"enabled"`
		Header  struct {
			Key   string `yaml:"key"`
			Value string `yaml:"value"`
		} `yaml:"header"`
	} `yaml:"auth"`
	From     string `yaml:"from"`
	Subjects struct {
		Verification string `yaml:"verification"`
		Reset        string `yaml:"reset"`
	} `yaml:"subjects"`
}

type MessagesConfig struct {
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

var (
	Auth     AuthConfig
	Mailer   MailerConfig
	Messages MessagesConfig
)

// LoadConfig loads all configuration files
func LoadConfig() error {
	// Load auth config
	authFile, err := os.ReadFile("config/auth.yaml")
	if err != nil {
		return err
	}
	if err := yaml.Unmarshal(authFile, &Auth); err != nil {
		return err
	}

	// Load mailer config
	mailerFile, err := os.ReadFile("config/mailer.yaml")
	if err != nil {
		return err
	}
	if err := yaml.Unmarshal(mailerFile, &Mailer); err != nil {
		return err
	}

	// Load messages config
	messagesFile, err := os.ReadFile("config/messages.yaml")
	if err != nil {
		return err
	}
	if err := yaml.Unmarshal(messagesFile, &Messages); err != nil {
		return err
	}

	return nil
}
