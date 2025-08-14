package services

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
)

type QueueService struct {
	conn    *amqp.Connection
	channel *amqp.Channel
}

func NewQueueService() *QueueService {
	// Get RabbitMQ connection details from environment variables
	host := getEnvOrDefault("RABBITMQ_HOST", "localhost")
	port := getEnvOrDefault("RABBITMQ_PORT", "5672")
	username := getEnvOrDefault("RABBITMQ_USERNAME", "guest")
	password := getEnvOrDefault("RABBITMQ_PASSWORD", "guest")
	vhost := getEnvOrDefault("RABBITMQ_VHOST", "/")

	// Connect to RabbitMQ
	url := fmt.Sprintf("amqp://%s:%s@%s:%s/%s",
		username,
		password,
		host,
		port,
		vhost,
	)

	conn, err := amqp.Dial(url)
	if err != nil {
		log.Fatalf("Failed to connect to RabbitMQ: %v", err)
	}

	ch, err := conn.Channel()
	if err != nil {
		log.Fatalf("Failed to open channel: %v", err)
	}

	// Declare exchange
	err = ch.ExchangeDeclare(
		"mailer", // name
		"direct", // type
		true,     // durable
		false,    // auto-deleted
		false,    // internal
		false,    // no-wait
		nil,      // arguments
	)
	if err != nil {
		log.Fatalf("Failed to declare exchange: %v", err)
	}

	// Declare queue
	_, err = ch.QueueDeclare(
		"email_queue", // name
		true,          // durable
		false,         // delete when unused
		false,         // exclusive
		false,         // no-wait
		nil,           // arguments
	)
	if err != nil {
		log.Fatalf("Failed to declare queue: %v", err)
	}

	// Bind queue to exchange
	err = ch.QueueBind(
		"email_queue", // queue name
		"email",       // routing key
		"mailer",      // exchange
		false,
		nil,
	)
	if err != nil {
		log.Fatalf("Failed to bind queue: %v", err)
	}

	service := &QueueService{
		conn:    conn,
		channel: ch,
	}

	// Setup connection recovery
	service.setupConnectionRecovery()

	return service
}

func (q *QueueService) PublishEmailTask(emailTask *EmailTask) error {
	payload, err := json.Marshal(emailTask)
	if err != nil {
		return fmt.Errorf("failed to marshal email task: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = q.channel.PublishWithContext(ctx,
		"mailer", // exchange
		"email",  // routing key
		false,    // mandatory
		false,    // immediate
		amqp.Publishing{
			ContentType:  "application/json",
			Body:         payload,
			DeliveryMode: amqp.Persistent, // Make messages persistent
		})
	if err != nil {
		return fmt.Errorf("failed to publish email task: %w", err)
	}

	log.Printf("Email task published for user: %s", emailTask.To)
	return nil
}

func (q *QueueService) Close() error {
	if err := q.channel.Close(); err != nil {
		return err
	}
	return q.conn.Close()
}

// EmailTask represents the structure of an email task to be sent to the queue
type EmailTask struct {
	To       string                 `json:"to"`
	Subject  string                 `json:"subject"`
	Template string                 `json:"template"`
	Data     map[string]interface{} `json:"data"`
	Type     string                 `json:"type"` // "verification", "password_reset", etc.
}

// getEnvOrDefault gets an environment variable or returns a default value
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// setupConnectionRecovery sets up automatic reconnection for RabbitMQ
func (q *QueueService) setupConnectionRecovery() {
	// Monitor connection for errors
	go func() {
		for err := range q.conn.NotifyClose(make(chan *amqp.Error)) {
			if err != nil {
				log.Printf("RabbitMQ connection lost: %v, attempting to reconnect...", err)
				q.reconnect()
			}
		}
	}()

	// Monitor channel for errors
	go func() {
		for err := range q.channel.NotifyClose(make(chan *amqp.Error)) {
			if err != nil {
				log.Printf("RabbitMQ channel lost: %v, attempting to reconnect...", err)
				q.reconnect()
			}
		}
	}()
}

// reconnect attempts to reconnect to RabbitMQ
func (q *QueueService) reconnect() {
	for {
		log.Println("Attempting to reconnect to RabbitMQ...")

		// Close existing connections
		if q.channel != nil {
			q.channel.Close()
		}
		if q.conn != nil {
			q.conn.Close()
		}

		// Wait before retry
		time.Sleep(5 * time.Second)

		// Attempt to reconnect
		host := getEnvOrDefault("RABBITMQ_HOST", "localhost")
		port := getEnvOrDefault("RABBITMQ_PORT", "5672")
		username := getEnvOrDefault("RABBITMQ_USERNAME", "guest")
		password := getEnvOrDefault("RABBITMQ_PASSWORD", "guest")
		vhost := getEnvOrDefault("RABBITMQ_VHOST", "/")

		url := fmt.Sprintf("amqp://%s:%s@%s:%s/%s",
			username, password, host, port, vhost,
		)

		conn, err := amqp.Dial(url)
		if err != nil {
			log.Printf("Failed to reconnect: %v, retrying in 5 seconds...", err)
			continue
		}

		ch, err := conn.Channel()
		if err != nil {
			log.Printf("Failed to create channel: %v, retrying in 5 seconds...", err)
			conn.Close()
			continue
		}

		// Re-declare exchange and queue
		if err := ch.ExchangeDeclare("mailer", "direct", true, false, false, false, nil); err != nil {
			log.Printf("Failed to declare exchange: %v, retrying in 5 seconds...", err)
			ch.Close()
			conn.Close()
			continue
		}

		if _, err := ch.QueueDeclare("email_queue", true, false, false, false, nil); err != nil {
			log.Printf("Failed to declare queue: %v, retrying in 5 seconds...", err)
			ch.Close()
			conn.Close()
			continue
		}

		if err := ch.QueueBind("email_queue", "email", "mailer", false, nil); err != nil {
			log.Printf("Failed to bind queue: %v, retrying in 5 seconds...", err)
			ch.Close()
			conn.Close()
			continue
		}

		// Update service with new connections
		q.conn = conn
		q.channel = ch
		log.Println("Successfully reconnected to RabbitMQ")
		break
	}
}
