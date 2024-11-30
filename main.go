package main

import (
	"auth-api/pkg/config"
	"auth-api/pkg/database"
	"auth-api/pkg/validator"
	"log"
	"os"

	"auth-api/internal/routes"
	"github.com/gofiber/fiber/v2"
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

func main() {
	app := fiber.New(fiber.Config{})

	routes.SetupRoutes(app)

	port := os.Getenv("PORT")
	if port == "" {
		port = "3001"
	}

	log.Fatal(app.Listen(":" + port))
}
