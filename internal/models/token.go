package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/kerimovok/go-pkg-database/sql"
)

type Token struct {
	sql.BaseModel
	UserID    uuid.UUID  `gorm:"type:uuid;not null;index" json:"userId"`
	Type      string     `gorm:"not null" json:"type"` // refresh, email_verification, password_reset
	ExpiresAt time.Time  `gorm:"not null;index" json:"expiresAt"`
	RevokedAt *time.Time `gorm:"default:null" json:"revokedAt,omitempty"`
	UserAgent string     `gorm:"type:text" json:"userAgent"`
	IP        string     `gorm:"type:varchar(45)" json:"ip"`
	// Token family tracking for rotation security
	Family   *uuid.UUID `gorm:"type:uuid;index" json:"family,omitempty"`   // Token family ID for rotation tracking
	ParentID *uuid.UUID `gorm:"type:uuid;index" json:"parentId,omitempty"` // Parent token in the rotation chain
}

// IsValid checks if the token is valid
func (t *Token) IsValid() bool {
	return t.RevokedAt == nil && t.ExpiresAt.After(time.Now())
}
