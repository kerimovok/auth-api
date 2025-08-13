package database

import (
	"auth-api/internal/models"
	"time"

	"github.com/kerimovok/go-pkg-database/sql"
	"github.com/kerimovok/go-pkg-utils/config"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var DB *gorm.DB

func ConnectDB() error {
	gormConfig := sql.GormConfig{
		Host:                      config.GetEnv("DB_HOST"),
		User:                      config.GetEnv("DB_USER"),
		Password:                  config.GetEnv("DB_PASS"),
		Name:                      config.GetEnv("DB_NAME"),
		Port:                      config.GetEnv("DB_PORT"),
		SSLMode:                   "disable",
		Timezone:                  "UTC",
		MaxIdleConns:              10,
		MaxOpenConns:              100,
		ConnMaxLifetime:           30 * time.Minute,
		ConnMaxIdleTime:           10 * time.Minute,
		TranslateErrors:           true,
		LogLevel:                  logger.Info,
		SlowThreshold:             200 * time.Millisecond,
		IgnoreRecordNotFoundError: false,
	}

	// Use go-pkg-database to open connection and auto-migrate
	db, err := sql.OpenGorm(gormConfig, &models.User{}, &models.Token{})
	if err != nil {
		return err
	}

	DB = db.DB
	return nil
}
