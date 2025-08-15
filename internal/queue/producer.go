package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/kerimovok/go-pkg-utils/config"
	amqp "github.com/rabbitmq/amqp091-go"
)

type Producer struct {
	conn    *amqp.Connection
	channel *amqp.Channel
}

func NewProducer() *Producer {
	// Get RabbitMQ connection details from environment variables
	host := config.GetEnvOrDefault("RABBITMQ_HOST", "localhost")
	port := config.GetEnvOrDefault("RABBITMQ_PORT", "5672")
	username := config.GetEnvOrDefault("RABBITMQ_USERNAME", "guest")
	password := config.GetEnvOrDefault("RABBITMQ_PASSWORD", "guest")
	vhost := config.GetEnvOrDefault("RABBITMQ_VHOST", "/")

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

	producer := &Producer{
		conn:    conn,
		channel: ch,
	}

	// Setup connection recovery
	producer.setupConnectionRecovery()

	return producer
}

func (p *Producer) PublishEmailTask(emailTask *EmailTask) error {
	payload, err := json.Marshal(emailTask)
	if err != nil {
		return fmt.Errorf("failed to marshal email task: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = p.channel.PublishWithContext(ctx,
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

func (p *Producer) Close() error {
	if err := p.channel.Close(); err != nil {
		return err
	}
	return p.conn.Close()
}

// EmailTask represents the structure of an email task to be sent to the queue
type EmailTask struct {
	To       string                 `json:"to"`
	Subject  string                 `json:"subject"`
	Template string                 `json:"template"`
	Data     map[string]interface{} `json:"data"`
	Type     string                 `json:"type"` // "verification", "password_reset", etc.
}

// setupConnectionRecovery sets up automatic reconnection for RabbitMQ
func (p *Producer) setupConnectionRecovery() {
	// Monitor connection for errors
	go func() {
		for err := range p.conn.NotifyClose(make(chan *amqp.Error)) {
			if err != nil {
				log.Printf("RabbitMQ connection lost: %v, attempting to reconnect...", err)
				p.reconnect()
			}
		}
	}()

	// Monitor channel for errors
	go func() {
		for err := range p.channel.NotifyClose(make(chan *amqp.Error)) {
			if err != nil {
				log.Printf("RabbitMQ channel lost: %v, attempting to reconnect...", err)
				p.reconnect()
			}
		}
	}()
}

// reconnect attempts to reconnect to RabbitMQ
func (p *Producer) reconnect() {
	for {
		log.Println("Attempting to reconnect to RabbitMQ...")

		// Close existing connections
		if p.channel != nil {
			p.channel.Close()
		}
		if p.conn != nil {
			p.conn.Close()
		}

		// Wait before retry
		time.Sleep(5 * time.Second)

		// Attempt to reconnect
		host := config.GetEnvOrDefault("RABBITMQ_HOST", "localhost")
		port := config.GetEnvOrDefault("RABBITMQ_PORT", "5672")
		username := config.GetEnvOrDefault("RABBITMQ_USERNAME", "guest")
		password := config.GetEnvOrDefault("RABBITMQ_PASSWORD", "guest")
		vhost := config.GetEnvOrDefault("RABBITMQ_VHOST", "/")

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

		// Update producer with new connections
		p.conn = conn
		p.channel = ch
		log.Println("Successfully reconnected to RabbitMQ")
		break
	}
}
