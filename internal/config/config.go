package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
	"github.com/kerimovok/go-pkg-utils/config"
	"gopkg.in/yaml.v3"
)

type TokenConfig struct {
	Expiry         string `yaml:"expiry"`
	RevokeExisting bool   `yaml:"revoke_existing"`
}

type AuthConfig struct {
	Token struct {
		Auth          TokenConfig `yaml:"auth"`
		Verification  TokenConfig `yaml:"verification"`
		PasswordReset TokenConfig `yaml:"password_reset"`
	} `yaml:"token"`
	Verification bool `yaml:"verification"`
	RedirectURLs struct {
		Verification  string `yaml:"verification"`
		PasswordReset string `yaml:"password_reset"`
	} `yaml:"redirect_urls"`
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
}

type MailerConfig struct {
	Auth struct {
		Enabled bool `yaml:"enabled"`
		Header  struct {
			Key   string `yaml:"key"`
			Value string `yaml:"value"`
		} `yaml:"header"`
	} `yaml:"auth"`
	From      string `yaml:"from"`
	Templates struct {
		Verification string `yaml:"verification"`
		Reset        string `yaml:"reset"`
	} `yaml:"templates"`
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
			UserNotFound              string `yaml:"user_not_found"`
			InvalidCredentials        string `yaml:"invalid_credentials"`
			InvalidToken              string `yaml:"invalid_token"`
			InvalidTokenType          string `yaml:"invalid_token_type"`
			AccountBlocked            string `yaml:"account_blocked"`
			EmailExists               string `yaml:"email_exists"`
			EmailVerificationRequired string `yaml:"email_verification_required"`
			AdminRequired             string `yaml:"admin_required"`
			InvalidPassword           string `yaml:"invalid_password"`
			TokenRequired             string `yaml:"token_required"`
			SamePassword              string `yaml:"same_password"`
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
	if err := godotenv.Load(); err != nil {
		if config.GetEnv("GO_ENV") != "production" {
			log.Println("Warning: Failed to load .env file")
		}
	}

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
