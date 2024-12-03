package services

import (
	"auth-api/pkg/config"
	"auth-api/pkg/utils"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"auth-api/internal/models"
)

type MailRequest struct {
	From     string                 `json:"from"`
	To       string                 `json:"to"`
	Subject  string                 `json:"subject"`
	Template string                 `json:"template"`
	Data     map[string]interface{} `json:"data"`
}

type MailerService struct {
	client  *http.Client
	baseURL string
}

func NewMailerService() *MailerService {
	return &MailerService{
		client:  &http.Client{},
		baseURL: os.Getenv("MAILER_URI"),
	}
}

func (m *MailerService) SendMail(req MailRequest) error {
	// Prepare request body
	body := new(bytes.Buffer)
	if err := json.NewEncoder(body).Encode(req); err != nil {
		return utils.WrapError("encode mail request", err)
	}

	// Create HTTP request
	httpReq, err := http.NewRequest(http.MethodPost, m.baseURL, body)
	if err != nil {
		return utils.WrapError("create mail request", err)
	}

	// Set headers
	httpReq.Header.Set("Content-Type", "application/json")
	if config.Mailer.Auth.Enabled {
		httpReq.Header.Set(
			config.Mailer.Auth.Header.Key,
			config.Mailer.Auth.Header.Value,
		)
	}

	// Send request
	resp, err := m.client.Do(httpReq)
	if err != nil {
		return utils.WrapError("send mail request", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("mail service returned status %d: %s", resp.StatusCode, body)
	}

	return nil
}

// Helper methods for specific email types
func (m *MailerService) SendVerificationEmail(email string, token *models.Token) error {
	verifyURL := fmt.Sprintf("%s?token=%s",
		config.Auth.RedirectURLs.Verification,
		token.ID.String(),
	)

	return m.SendMail(MailRequest{
		From:     config.Mailer.From,
		To:       email,
		Subject:  config.Mailer.Subjects.Verification,
		Template: config.Mailer.Templates.Verification,
		Data: map[string]interface{}{
			"subject":   config.Mailer.Subjects.Verification,
			"email":     email,
			"url":       verifyURL,
			"expiry":    config.Auth.Token.Verification.Expiry,
			"expiresAt": token.ExpiresAt.Format(time.Stamp),
		},
	})
}

func (m *MailerService) SendPasswordResetEmail(email string, token *models.Token) error {
	resetURL := fmt.Sprintf("%s?token=%s",
		config.Auth.RedirectURLs.PasswordReset,
		token.ID.String(),
	)

	return m.SendMail(MailRequest{
		From:     config.Mailer.From,
		To:       email,
		Subject:  config.Mailer.Subjects.Reset,
		Template: config.Mailer.Templates.Reset,
		Data: map[string]interface{}{
			"subject":   config.Mailer.Subjects.Reset,
			"email":     email,
			"url":       resetURL,
			"expiry":    config.Auth.Token.Verification.Expiry,
			"expiresAt": token.ExpiresAt.Format(time.Stamp),
		},
	})
}
