package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"

	"auth-api/.internal/config"
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
	config  *config.Config
}

func NewMailerService(cfg *config.Config) *MailerService {
	return &MailerService{
		client:  &http.Client{},
		baseURL: os.Getenv("MAILER_URI"),
		config:  cfg,
	}
}

func (m *MailerService) SendMail(req MailRequest) error {
	// Set from address if not provided
	if req.From == "" {
		req.From = m.config.Mailer.From
	}

	// Convert request to JSON
	jsonData, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal mail request: %w", err)
	}

	// Create HTTP request
	httpReq, err := http.NewRequest(
		"POST",
		m.baseURL,
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		return fmt.Errorf("failed to create mail request: %w", err)
	}

	// Set headers
	httpReq.Header.Set("Content-Type", "application/json")
	if m.config.Mailer.Auth.Enabled {
		httpReq.Header.Set(
			m.config.Mailer.Auth.Header.Key,
			m.config.Mailer.Auth.Header.Value,
		)
	}

	// Send request
	resp, err := m.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed to send mail request: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("mail service returned non-200 status: %d", resp.StatusCode)
	}

	return nil
}

// Helper methods for specific email types
func (m *MailerService) SendVerificationEmail(email, token string) error {
	// Construct verification URL
	verifyURL, err := url.Parse(os.Getenv("BASE_URL"))
	if err != nil {
		return fmt.Errorf("failed to parse base URL: %w", err)
	}
	verifyURL.Path = path.Join(verifyURL.Path, "confirm-email")
	q := verifyURL.Query()
	q.Set("token", token)
	verifyURL.RawQuery = q.Encode()

	return m.SendMail(MailRequest{
		From:     m.config.Mailer.From,
		To:       email,
		Subject:  m.config.Mailer.Subjects.Verification,
		Template: "confirm-email",
		Data: map[string]interface{}{
			"subject": m.config.Mailer.Subjects.Verification,
			"email":   email,
			"url":     verifyURL.String(),
		},
	})
}

func (m *MailerService) SendPasswordResetEmail(email, token string) error {
	// Construct reset URL
	resetURL, err := url.Parse(os.Getenv("BASE_URL"))
	if err != nil {
		return fmt.Errorf("failed to parse base URL: %w", err)
	}
	resetURL.Path = path.Join(resetURL.Path, "reset-password")
	q := resetURL.Query()
	q.Set("token", token)
	resetURL.RawQuery = q.Encode()

	return m.SendMail(MailRequest{
		From:     m.config.Mailer.From,
		To:       email,
		Subject:  m.config.Mailer.Subjects.Reset,
		Template: "reset-password",
		Data: map[string]interface{}{
			"subject": m.config.Mailer.Subjects.Reset,
			"email":   email,
			"url":     resetURL.String(),
		},
	})
}
