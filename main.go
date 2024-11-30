package main

import (
	"log"
	"os"

	"auth-api/internal/routes"
	"auth-api/pkg/config"
	"auth-api/pkg/database"
	"auth-api/pkg/validator"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/compress"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/healthcheck"
	"github.com/gofiber/fiber/v2/middleware/helmet"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/requestid"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
)

func init() {
	// Load .env file
	if err := godotenv.Load(); err != nil {
		log.Fatal("Error loading .env file")
	}

	// Load all configs
	if err := config.LoadConfig(); err != nil {
		log.Fatal("Error loading configs:", err)
	}

	// Initialize validator
	validator.InitValidator()

	// Connect to database
	if err := database.ConnectDB(); err != nil {
		log.Fatal("Error connecting to database:", err)
	}
}

func setupApp() *fiber.App {
	app := fiber.New(fiber.Config{})

	// Middleware
	app.Use(helmet.New())
	app.Use(cors.New())
	app.Use(compress.New())
	app.Use(healthcheck.New())
	app.Use(requestid.New(requestid.Config{
		Generator: func() string {
			return uuid.New().String()
		},
	}))
	app.Use(logger.New())

	return app
}

func main() {
	app := setupApp()

	routes.SetupRoutes(app)

	port := os.Getenv("PORT")
	if port == "" {
		port = "3001"
	}

	log.Fatal(app.Listen(":" + port))
}
