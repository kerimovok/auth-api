package models

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID          uuid.UUID  `gorm:"type:uuid;default:gen_random_uuid()" json:"id"`
	Email       string     `gorm:"uniqueIndex;not null" json:"email"`
	Password    string     `gorm:"not null" json:"-"`
	IsAdmin     bool       `gorm:"default:false" json:"isAdmin"`
	IsVerified  bool       `gorm:"default:false" json:"isVerified"`
	IsBlocked   bool       `gorm:"default:false" json:"isBlocked"`
	LastLoginAt *time.Time `gorm:"default:null" json:"lastLoginAt,omitempty"`
	CreatedAt   time.Time  `json:"createdAt"`
	UpdatedAt   time.Time  `json:"updatedAt"`
	DeletedAt   *time.Time `json:"deletedAt,omitempty"`
}
