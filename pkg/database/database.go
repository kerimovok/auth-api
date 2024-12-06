package database

import (
	"fmt"

	"auth-api/internal/models"
	"auth-api/pkg/utils"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

func ConnectDB() error {
	// Construct DSN (Data Source Name)
	dsn := fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%s sslmode=disable TimeZone=UTC",
		utils.GetEnv("DB_HOST"),
		utils.GetEnv("DB_USER"),
		utils.GetEnv("DB_PASS"),
		utils.GetEnv("DB_NAME"),
		utils.GetEnv("DB_PORT"),
	)

	// Open connection
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return err
	}

	// Get underlying SQL DB
	sqlDB, err := db.DB()
	if err != nil {
		return err
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
		return err
	}

	DB = db
	return nil
}
