package models

import (
	"time"
)

type User struct {
	ID          uint       `json:"id"`
	Email       string     `gorm:"uniqueIndex;not null" json:"email"`
	Password    string     `gorm:"not null" json:"-"`
	IsAdmin     bool       `gorm:"default:false" json:"is_admin"`
	IsVerified  bool       `gorm:"default:false" json:"is_verified"`
	IsBlocked   bool       `gorm:"default:false" json:"is_blocked"`
	LastLoginAt *time.Time `gorm:"default:null" json:"last_login_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	DeletedAt   *time.Time `json:"deleted_at,omitempty"`
}
