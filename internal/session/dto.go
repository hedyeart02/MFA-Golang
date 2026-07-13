package session

import "time"

// CreateSessionRequest is the request to create a new session.
type CreateSessionRequest struct {
	UserID    string `json:"user_id" binding:"required"`
	IPAddress string `json:"ip_address"`
	UserAgent string `json:"user_agent"`
}

// CreateSessionResponse contains the created session tokens.
type CreateSessionResponse struct {
	SessionID    string    `json:"session_id"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// SessionInfoResponse contains session details for validation.
type SessionInfoResponse struct {
	SessionID      string    `json:"session_id"`
	UserID         string    `json:"user_id"`
	IPAddress      string    `json:"ip_address"`
	UserAgent      string    `json:"user_agent"`
	CreatedAt      time.Time `json:"created_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	LastActivityAt time.Time `json:"last_activity_at"`
	Revoked        bool      `json:"revoked"`
}

// ValidateSessionRequest is the request to validate a session.
type ValidateSessionRequest struct {
	TokenHash string `json:"token_hash" binding:"required"`
}

// RefreshSessionRequest is the request to refresh a session.
type RefreshSessionRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
	IPAddress    string `json:"ip_address"`
	UserAgent    string `json:"user_agent"`
}

// RevokeSessionRequest is the request to revoke/delete a session.
type RevokeSessionRequest struct {
	SessionID string `json:"session_id" binding:"required"`
}
