package models

import (
	"time"

	"github.com/kerimovok/go-pkg-database/sql"
)

type User struct {
	sql.BaseModel
	Email       string     `gorm:"uniqueIndex;not null" json:"email"`
	Password    string     `gorm:"not null" json:"-"`
	IsAdmin     bool       `gorm:"default:false" json:"isAdmin"`
	IsVerified  bool       `gorm:"default:false" json:"isVerified"`
	IsBlocked   bool       `gorm:"default:false" json:"isBlocked"`
	LastLoginAt *time.Time `gorm:"default:null" json:"lastLoginAt,omitempty"`
}
