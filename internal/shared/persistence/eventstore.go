package persistence

import "context"

type EventHandler func(ctx context.Context, event interface{}) error

// EventStore enforces Publisher -> Store -> Subscriber architecture
type EventStore interface {
	Publish(ctx context.Context, topic string, payload interface{}) error
	Subscribe(topic string, handler EventHandler) error
	Close() error
}
