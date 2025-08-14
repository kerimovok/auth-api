package services

import (
	"auth-api/internal/config"
	"auth-api/internal/models"
	"fmt"
	"time"
)

type MailerService struct {
	queueService *QueueService
}

func NewMailerService() *MailerService {
	return &MailerService{
		queueService: NewQueueService(),
	}
}

// Helper methods for specific email types
func (m *MailerService) SendVerificationEmail(email string, token *models.Token) error {
	verifyURL := fmt.Sprintf("%s?token=%s",
		config.Auth.RedirectURLs.Verification,
		token.ID.String(),
	)

	emailTask := &EmailTask{
		To:       email,
		Subject:  config.Mailer.Subjects.Verification,
		Template: config.Mailer.Templates.Verification,
		Type:     "verification",
		Data: map[string]interface{}{
			"subject":   config.Mailer.Subjects.Verification,
			"email":     email,
			"url":       verifyURL,
			"expiry":    config.Auth.Tokens.EmailVerification.Expiry,
			"expiresAt": token.ExpiresAt.Format(time.Stamp),
		},
	}

	return m.queueService.PublishEmailTask(emailTask)
}

func (m *MailerService) SendPasswordResetEmail(email string, token *models.Token) error {
	resetURL := fmt.Sprintf("%s?token=%s",
		config.Auth.RedirectURLs.PasswordReset,
		token.ID.String(),
	)

	emailTask := &EmailTask{
		To:       email,
		Subject:  config.Mailer.Subjects.Reset,
		Template: config.Mailer.Templates.Reset,
		Type:     "password_reset",
		Data: map[string]interface{}{
			"subject":   config.Mailer.Subjects.Reset,
			"email":     email,
			"url":       resetURL,
			"expiry":    config.Auth.Tokens.PasswordReset.Expiry,
			"expiresAt": token.ExpiresAt.Format(time.Stamp),
		},
	}

	return m.queueService.PublishEmailTask(emailTask)
}

func (m *MailerService) Close() error {
	return m.queueService.Close()
}
