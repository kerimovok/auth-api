package constants

import "auth-api/pkg/utils"

var EnvValidationRules = []utils.ValidationRule{
	// Server validation
	{
		Variable: "PORT",
		Default:  "3001",
		Rule:     utils.IsValidPort,
		Message:  "server port is required and must be a valid port number",
	},
	{
		Variable: "GO_ENV",
		Default:  "development",
		Rule:     func(v string) bool { return v == "development" || v == "production" },
		Message:  "GO_ENV must be either 'development' or 'production'",
	},

	// Database validation
	{
		Variable: "DB_HOST",
		Rule:     func(v string) bool { return v != "" },
		Message:  "database host is required",
	},
	{
		Variable: "DB_PORT",
		Default:  "5432",
		Rule:     utils.IsValidPort,
		Message:  "database port is required and must be a valid port number",
	},
	{
		Variable: "DB_USER",
		Rule:     func(v string) bool { return v != "" },
		Message:  "database user is required",
	},
	{
		Variable: "DB_NAME",
		Default:  "auth",
		Rule:     func(v string) bool { return v != "" },
		Message:  "database name is required",
	},

	// Mailer validation
	{
		Variable: "MAILER_URI",
		Rule:     utils.IsValidURL,
		Message:  "mailer URI is required and must be a valid URL",
	},
}
