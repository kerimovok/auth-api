package services

import (
	"auth-api/internal/config"
	"auth-api/internal/models"
	"auth-api/internal/queue"
	"fmt"
	"time"
)

type MailerService struct {
	queueProducer *queue.Producer
}

func NewMailerService() *MailerService {
	return &MailerService{
		queueProducer: queue.NewProducer(),
	}
}

// Helper methods for specific email types
func (m *MailerService) SendVerificationEmail(email string, token *models.Token) error {
	verifyURL := fmt.Sprintf("%s?token=%s",
		config.Auth.RedirectURLs.Verification,
		token.ID.String(),
	)

	emailTask := &queue.EmailTask{
		To:       email,
		Subject:  config.Mailer.Templates.Verification.Subject,
		Template: config.Mailer.Templates.Verification.Name,
		Type:     "verification",
		Data: map[string]interface{}{
			"subject":   config.Mailer.Templates.Verification.Subject,
			"email":     email,
			"url":       verifyURL,
			"expiry":    config.Auth.Tokens.EmailVerification.Expiry,
			"expiresAt": token.ExpiresAt.Format(time.Stamp),
		},
	}

	return m.queueProducer.PublishEmailTask(emailTask)
}

func (m *MailerService) SendPasswordResetEmail(email string, token *models.Token) error {
	resetURL := fmt.Sprintf("%s?token=%s",
		config.Auth.RedirectURLs.PasswordReset,
		token.ID.String(),
	)

	emailTask := &queue.EmailTask{
		To:       email,
		Subject:  config.Mailer.Templates.Reset.Subject,
		Template: config.Mailer.Templates.Reset.Name,
		Type:     "password_reset",
		Data: map[string]interface{}{
			"subject":   config.Mailer.Templates.Reset.Subject,
			"email":     email,
			"url":       resetURL,
			"expiry":    config.Auth.Tokens.PasswordReset.Expiry,
			"expiresAt": token.ExpiresAt.Format(time.Stamp),
		},
	}

	return m.queueProducer.PublishEmailTask(emailTask)
}

func (m *MailerService) Close() error {
	return m.queueProducer.Close()
}
