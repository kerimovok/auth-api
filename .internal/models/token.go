package models

import (
	"time"

	"gorm.io/gorm"
)

type Token struct {
	UserID    uint       `gorm:"not null;index" json:"user_id"`
	Token     string     `gorm:"not null;uniqueIndex" json:"token"`
	Type      string     `gorm:"not null" json:"type"` // auth, email_verification, password_reset
	ExpiresAt time.Time  `gorm:"not null;index" json:"expires_at"`
	RevokedAt *time.Time `gorm:"default:null" json:"revoked_at,omitempty"`
	UserAgent string     `gorm:"type:text" json:"user_agent"`
	IP        string     `gorm:"type:varchar(45)" json:"ip"`
	gorm.Model
	ID        uint       `json:"id"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	DeletedAt *time.Time `json:"deleted_at,omitempty"`
}

// IsValid checks if the token is valid
func (t *Token) IsValid() bool {
	return t.RevokedAt == nil && t.ExpiresAt.After(time.Now())
}
