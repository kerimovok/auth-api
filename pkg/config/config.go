package config

import (
	"fmt"
	"log"
	"net/mail"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
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

type EnvConfig struct {
	Server struct {
		Port        string
		Environment string
	}
	DB struct {
		Host string
		Port string
		User string
		Pass string
		Name string
	}
	Mailer struct {
		URI string
	}
}

var (
	Auth     AuthConfig
	Mailer   MailerConfig
	Messages MessagesConfig
	Env      *EnvConfig
)

// ValidationRule defines a validation function that returns an error if validation fails
type ValidationRule struct {
	Field   string
	Rule    func(value string) bool
	Message string
}

// LoadConfig loads all configuration files
func LoadConfig() error {
	if err := godotenv.Load(); err != nil {
		if GetEnv("GO_ENV") != "production" {
			log.Printf("Warning: .env file not found")
		}
	}

	Env = &EnvConfig{
		Server: struct {
			Port        string
			Environment string
		}{
			Port:        GetEnvOrDefault("PORT", "3001"),
			Environment: GetEnvOrDefault("GO_ENV", "development"),
		},
		DB: struct {
			Host string
			Port string
			User string
			Pass string
			Name string
		}{
			Host: GetEnvOrDefault("DB_HOST", ""),
			Port: GetEnvOrDefault("DB_PORT", ""),
			User: GetEnvOrDefault("DB_USER", ""),
			Pass: GetEnvOrDefault("DB_PASS", ""),
			Name: GetEnvOrDefault("DB_NAME", ""),
		},
		Mailer: struct {
			URI string
		}{
			URI: GetEnvOrDefault("MAILER_URI", ""),
		},
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

	return validateConfig()
}

// validateConfig checks all required configuration values
func validateConfig() error {
	rules := []ValidationRule{
		// Server validation
		{
			Field:   "Server.Port",
			Rule:    func(v string) bool { return v != "" },
			Message: "server port is required",
		},

		// Database validation
		{
			Field:   "DB.Host",
			Rule:    func(v string) bool { return v != "" },
			Message: "database host is required",
		},
		{
			Field:   "DB.Port",
			Rule:    func(v string) bool { return v != "" },
			Message: "database port is required",
		},
		{
			Field:   "DB.User",
			Rule:    func(v string) bool { return v != "" },
			Message: "database user is required",
		},
		{
			Field:   "DB.Name",
			Rule:    func(v string) bool { return v != "" },
			Message: "database name is required",
		},

		// Mailer validation
		{
			Field:   "Mailer.URI",
			Rule:    func(v string) bool { return v != "" },
			Message: "mailer URI is required",
		},
	}

	var errors []string
	for _, rule := range rules {
		value := getConfigValue(rule.Field)
		if !rule.Rule(value) {
			errors = append(errors, rule.Message)
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("configuration validation failed: %s", strings.Join(errors, "; "))
	}

	return nil
}

// getConfigValue retrieves a configuration value using reflection based on the field path
func getConfigValue(fieldPath string) string {
	parts := strings.Split(fieldPath, ".")
	value := reflect.ValueOf(Env).Elem()

	for _, part := range parts {
		value = value.FieldByName(part)
	}

	return value.String()
}

// AddValidationRule allows adding custom validation rules
func AddValidationRule(field string, rule func(string) bool, message string) {
	customRules = append(customRules, ValidationRule{
		Field:   field,
		Rule:    rule,
		Message: message,
	})
}

// Custom validation rules that can be added by the application
var customRules []ValidationRule

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
