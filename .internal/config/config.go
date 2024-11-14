package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Auth struct {
		// Identifier struct {
		// 	Email    bool `yaml:"email"`
		// 	Username bool `yaml:"username"`
		// } `yaml:"identifier"`
		RequireEmailVerification bool `yaml:"require_email_verification"`
		SendWelcomeEmail         bool `yaml:"send_welcome_email"`
		// UsernameFormat   struct {
		// 	MinLength    int  `yaml:"min_length"`
		// 	MaxLength    int  `yaml:"max_length"`
		// 	AllowSpecial bool `yaml:"allow_special"`
		// 	AllowNumbers bool `yaml:"allow_numbers"`
		// } `yaml:"username_format"`
		PasswordStrength struct {
			MinLength        int  `yaml:"min_length"`
			MaxLength        int  `yaml:"max_length"`
			RequireUppercase bool `yaml:"require_uppercase"`
			RequireLowercase bool `yaml:"require_lowercase"`
			RequireNumbers   bool `yaml:"require_numbers"`
			RequireSpecial   bool `yaml:"require_special"`
		} `yaml:"password_strength"`
		JWT struct {
			// Claims      []string `yaml:"claims"`
			TokenExpiry struct {
				Auth              string `yaml:"auth"`
				EmailVerification string `yaml:"email_verification"`
				PasswordReset     string `yaml:"password_reset"`
			} `yaml:"token_expiry"`
		} `yaml:"jwt"`
		AllowConcurrentLogins bool `yaml:"allow_concurrent_logins"`
	} `yaml:"auth"`
	Mailer struct {
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
	} `yaml:"mailer"`
}

var AppConfig Config

func LoadConfig() error {
	file, err := os.ReadFile("config/config.yaml")
	if err != nil {
		return err
	}

	return yaml.Unmarshal(file, &AppConfig)
}
