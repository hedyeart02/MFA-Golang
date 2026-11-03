package shared

import (
	"context"
	"errors"
)

var (
	ErrNotFound = errors.New("record not found")
)

// User represents a basic user model
type User struct {
	ID    string
	Email string
}

// Session represents an active user session
type Session struct {
	ID        string
	UserID    string
	ExpiresAt int64
}

// UserRepository defines the interface for user persistence
type UserRepository interface {
	GetUserByID(ctx context.Context, id string) (*User, error)
	CreateUser(ctx context.Context, user *User) error
}

// SessionRepository defines the interface for session persistence
type SessionRepository interface {
	GetSession(ctx context.Context, id string) (*Session, error)
	SaveSession(ctx context.Context, session *Session) error
	DeleteSession(ctx context.Context, id string) error
}
