package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/kerimovok/go-pkg-utils/config"
	amqp "github.com/rabbitmq/amqp091-go"
)

type Producer struct {
	conn    *amqp.Connection
	channel *amqp.Channel
	mu      sync.RWMutex // Protect connection updates
	config  *QueueConfig
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

	// Get queue configuration
	queueConfig := DefaultQueueConfig()

	// Setup all queues and exchanges using shared configuration
	if err := queueConfig.SetupAllQueues(ch); err != nil {
		log.Fatalf("Failed to setup queues: %v", err)
	}

	producer := &Producer{
		conn:    conn,
		channel: ch,
		config:  queueConfig,
	}

	// Setup connection recovery
	producer.setupConnectionRecovery()

	return producer
}

func (p *Producer) PublishEmailTask(emailTask *EmailTask) error {
	// Check connection health before publishing
	p.mu.RLock()
	if p.conn == nil || p.conn.IsClosed() || p.channel == nil || p.channel.IsClosed() {
		p.mu.RUnlock()
		return fmt.Errorf("RabbitMQ connection is not available")
	}
	p.mu.RUnlock()

	payload, err := json.Marshal(emailTask)
	if err != nil {
		return fmt.Errorf("failed to marshal email task: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	p.mu.RLock()
	err = p.channel.PublishWithContext(ctx,
		p.config.ExchangeName, // exchange
		p.config.RoutingKey,   // routing key
		false,                 // mandatory
		false,                 // immediate
		amqp.Publishing{
			ContentType:  "application/json",
			Body:         payload,
			DeliveryMode: amqp.Persistent, // Make messages persistent
		})
	p.mu.RUnlock()

	if err != nil {
		return fmt.Errorf("failed to publish email task: %w", err)
	}

	log.Printf("Email task published for user: %s", emailTask.To)
	return nil
}

func (p *Producer) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

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
		p.mu.Lock()
		if p.channel != nil {
			p.channel.Close()
		}
		if p.conn != nil {
			p.conn.Close()
		}
		p.mu.Unlock()

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

		// Re-setup all queues and exchanges using shared configuration
		if err := p.config.SetupAllQueues(ch); err != nil {
			log.Printf("Failed to setup queues: %v, retrying in 5 seconds...", err)
			ch.Close()
			conn.Close()
			continue
		}

		// Update producer with new connections
		p.mu.Lock()
		p.conn = conn
		p.channel = ch
		p.mu.Unlock()
		log.Println("Successfully reconnected to RabbitMQ")
		break
	}
}
