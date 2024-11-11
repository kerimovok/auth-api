package models

import (
	"time"
)

type Token struct {
	ID        uint       `json:"id"`
	UserID    uint       `gorm:"not null;index" json:"userId"`
	Token     string     `gorm:"not null;uniqueIndex" json:"token"`
	Type      string     `gorm:"not null" json:"type"` // auth, email_verification, password_reset
	ExpiresAt time.Time  `gorm:"not null;index" json:"expiresAt"`
	RevokedAt *time.Time `gorm:"default:null" json:"revokedAt,omitempty"`
	UserAgent string     `gorm:"type:text" json:"userAgent"`
	IP        string     `gorm:"type:varchar(45)" json:"ip"`
	CreatedAt time.Time  `json:"createdAt"`
	UpdatedAt time.Time  `json:"updatedAt"`
	DeletedAt *time.Time `json:"deletedAt,omitempty"`
}

// IsValid checks if the token is valid
func (t *Token) IsValid() bool {
	return t.RevokedAt == nil && t.ExpiresAt.After(time.Now())
}
