package database

import (
	"fmt"

	"auth-api/internal/models"
	"auth-api/pkg/config"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

func ConnectDB() error {
	// Construct DSN (Data Source Name)
	dsn := fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%s sslmode=disable TimeZone=UTC",
		config.Env.DB.Host,
		config.Env.DB.User,
		config.Env.DB.Pass,
		config.Env.DB.Name,
		config.Env.DB.Port,
	)

	// Open connection
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	// Get underlying SQL DB
	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("failed to get database instance: %w", err)
	}

	// Set connection pool settings
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetMaxOpenConns(100)

	// Auto migrate models
	err = db.AutoMigrate(
		&models.User{},
		&models.Token{},
	)
	if err != nil {
		return fmt.Errorf("failed to migrate database: %w", err)
	}

	DB = db
	return nil
}
