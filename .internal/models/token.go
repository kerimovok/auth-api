package models

import (
	"time"

	"gorm.io/gorm"
)

type Token struct {
	UserID    uint       `gorm:"not null;index"`
	Token     string     `gorm:"not null;uniqueIndex"`
	Type      string     `gorm:"not null"` // auth, email_verification, password_reset
	ExpiresAt time.Time  `gorm:"not null;index"`
	RevokedAt *time.Time `gorm:"default:null"`
	UserAgent string     `gorm:"type:text"`
	IP        string     `gorm:"type:varchar(45)"`
	gorm.Model
}

// IsValid checks if the token is valid
func (t *Token) IsValid() bool {
	return t.RevokedAt == nil && t.ExpiresAt.After(time.Now())
}
