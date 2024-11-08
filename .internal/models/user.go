package models

import (
	"time"

	"gorm.io/gorm"
)

type User struct {
	Email       string     `gorm:"uniqueIndex;not null"`
	Password    string     `gorm:"not null"`
	IsAdmin     bool       `gorm:"default:false"`
	IsVerified  bool       `gorm:"default:false"`
	IsBlocked   bool       `gorm:"default:false"`
	LastLoginAt *time.Time `gorm:"default:null"`
	gorm.Model
}
