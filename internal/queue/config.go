package queue

import (
	amqp "github.com/rabbitmq/amqp091-go"
)

// QueueConfig holds the configuration for RabbitMQ queues and exchanges
type QueueConfig struct {
	ExchangeName    string
	QueueName       string
	RoutingKey      string
	DLXExchangeName string
	DLQName         string
	DLQRoutingKey   string
}

// DefaultQueueConfig returns the default queue configuration
func DefaultQueueConfig() *QueueConfig {
	return &QueueConfig{
		ExchangeName:    "mailer",
		QueueName:       "email_queue",
		RoutingKey:      "email",
		DLXExchangeName: "mailer.dlx",
		DLQName:         "email_dlq",
		DLQRoutingKey:   "email.failed",
	}
}

// GetQueueArguments returns the queue arguments for both main queue and DLQ
func (qc *QueueConfig) GetQueueArguments() amqp.Table {
	return amqp.Table{
		"x-message-ttl":             int32(24 * 60 * 60 * 1000), // 24 hours TTL
		"x-max-priority":            int32(10),                  // Priority support
		"x-overflow":                "drop-head",                // Drop oldest when full
		"x-dead-letter-exchange":    qc.DLXExchangeName,         // Dead letter exchange
		"x-dead-letter-routing-key": qc.DLQRoutingKey,           // Routing key for DLQ
	}
}

// SetupExchange declares the main exchange
func (qc *QueueConfig) SetupExchange(ch *amqp.Channel) error {
	return ch.ExchangeDeclare(
		qc.ExchangeName, // name
		"direct",        // type
		true,            // durable
		false,           // auto-deleted
		false,           // internal
		false,           // no-wait
		nil,             // arguments
	)
}

// SetupDeadLetterExchange declares the dead letter exchange
func (qc *QueueConfig) SetupDeadLetterExchange(ch *amqp.Channel) error {
	return ch.ExchangeDeclare(
		qc.DLXExchangeName, // dead letter exchange name
		"direct",           // exchange type
		true,               // durable
		false,              // auto-deleted
		false,              // internal
		false,              // no-wait
		nil,                // arguments
	)
}

// SetupDeadLetterQueue declares the dead letter queue
func (qc *QueueConfig) SetupDeadLetterQueue(ch *amqp.Channel) error {
	dlq, err := ch.QueueDeclare(
		qc.DLQName, // dead letter queue name
		true,       // durable
		false,      // delete when unused
		false,      // exclusive
		false,      // no-wait
		nil,        // arguments
	)
	if err != nil {
		return err
	}

	// Bind dead letter queue to exchange
	return ch.QueueBind(
		dlq.Name,           // queue name
		qc.DLQRoutingKey,   // routing key
		qc.DLXExchangeName, // exchange
		false,              // no-wait
		nil,                // arguments
	)
}

// SetupMainQueue declares the main queue with DLQ configuration
func (qc *QueueConfig) SetupMainQueue(ch *amqp.Channel) error {
	_, err := ch.QueueDeclare(
		qc.QueueName, // name
		true,         // durable
		false,        // delete when unused
		false,        // exclusive
		false,        // no-wait
		qc.GetQueueArguments(),
	)
	if err != nil {
		return err
	}

	// Bind queue to exchange
	return ch.QueueBind(
		qc.QueueName,    // queue name
		qc.RoutingKey,   // routing key
		qc.ExchangeName, // exchange
		false,
		nil,
	)
}

// SetupAllQueues sets up all exchanges and queues
func (qc *QueueConfig) SetupAllQueues(ch *amqp.Channel) error {
	// Setup dead letter queue first
	if err := qc.SetupDeadLetterExchange(ch); err != nil {
		return err
	}

	if err := qc.SetupDeadLetterQueue(ch); err != nil {
		return err
	}

	// Setup main exchange
	if err := qc.SetupExchange(ch); err != nil {
		return err
	}

	// Setup main queue
	return qc.SetupMainQueue(ch)
}
