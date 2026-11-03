package session

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/hidayat-SE/samlguard/pkg/config"
	"github.com/hidayat-SE/samlguard/pkg/database"
	"github.com/hidayat-SE/samlguard/pkg/utils"
)

// Service contains the business logic for session management.
type Service struct {
	repo            *Repository
	sessionCfg      config.SessionConfig
	logger          *zap.Logger
}

// NewService creates a new session service.
func NewService(repo *Repository, cfg config.SessionConfig, log *zap.Logger) *Service {
	return &Service{
		repo:       repo,
		sessionCfg: cfg,
		logger:     log,
	}
}

// CreateSession creates a new session for the authenticated user.
// Returns the session ID and token hashes for cookie storage.
func (s *Service) CreateSession(ctx context.Context, req CreateSessionRequest) (*database.Session, error) {
	if err := s.repo.EnsureUserExists(ctx, req.UserID); err != nil {
		return nil, fmt.Errorf("ensuring user exists: %w", err)
	}

	sessionID := uuid.New().String()
	now := time.Now()

	tokenData := fmt.Sprintf("%s:%s:%d", sessionID, req.UserID, now.UnixNano())
	tokenHash := utils.SHA256Hash(tokenData)

	refreshData := fmt.Sprintf("refresh:%s:%s:%d", sessionID, req.UserID, now.UnixNano())
	refreshTokenHash := utils.SHA256Hash(refreshData)

	sess := &database.Session{
		BaseModel: database.BaseModel{
			ID:        sessionID,
			CreatedAt: now,
			UpdatedAt: now,
		},
		UserID:           req.UserID,
		TokenHash:        tokenHash,
		RefreshTokenHash: refreshTokenHash,
		IPAddress:        req.IPAddress,
		UserAgent:        req.UserAgent,
		ExpiresAt:        now.Add(s.sessionCfg.AbsoluteTimeout),
		IdleExpiresAt:    now.Add(s.sessionCfg.IdleTimeout),
		LastActivityAt:   now,
		Revoked:          false,
	}

	if err := s.repo.Create(ctx, sess); err != nil {
		return nil, fmt.Errorf("creating session: %w", err)
	}

	s.logger.Info("session created",
		zap.String("session_id", sessionID),
		zap.String("user_id", req.UserID),
		zap.Time("expires_at", sess.ExpiresAt),
	)

	return sess, nil
}

// ValidateSession checks if a session is valid (not expired, not revoked).
func (s *Service) ValidateSession(ctx context.Context, sessionID string) (*database.Session, error) {
	sess, err := s.repo.FindByID(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("finding session: %w", err)
	}

	if sess == nil {
		return nil, utils.ErrSessionNotFound
	}

	if sess.Revoked {
		return nil, utils.ErrSessionRevoked
	}

	if sess.IsExpired() {
		return nil, utils.ErrSessionExpired
	}

	newIdleExpiry := time.Now().Add(s.sessionCfg.IdleTimeout)
	if err := s.repo.UpdateActivity(ctx, sessionID, newIdleExpiry); err != nil {
		s.logger.Warn("failed to update session activity",
			zap.String("session_id", sessionID),
			zap.Error(err),
		)
	}

	return sess, nil
}

// RevokeSession marks a session as revoked (logout).
func (s *Service) RevokeSession(ctx context.Context, sessionID string) error {
	sess, err := s.repo.FindByID(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("finding session: %w", err)
	}

	if sess == nil {
		return utils.ErrSessionNotFound
	}

	if err := s.repo.Revoke(ctx, sessionID); err != nil {
		return fmt.Errorf("revoking session: %w", err)
	}

	s.logger.Info("session revoked",
		zap.String("session_id", sessionID),
		zap.String("user_id", sess.UserID),
	)

	return nil
}

// RevokeAllUserSessions revokes all sessions for a user.
func (s *Service) RevokeAllUserSessions(ctx context.Context, userID string) error {
	if err := s.repo.RevokeAllForUser(ctx, userID); err != nil {
		return fmt.Errorf("revoking all sessions for user %s: %w", userID, err)
	}

	s.logger.Info("all sessions revoked for user", zap.String("user_id", userID))
	return nil
}

// GetSessionInfo returns session details.
func (s *Service) GetSessionInfo(ctx context.Context, sessionID string) (*SessionInfoResponse, error) {
	sess, err := s.ValidateSession(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	return &SessionInfoResponse{
		SessionID:      sess.ID,
		UserID:         sess.UserID,
		IPAddress:      sess.IPAddress,
		UserAgent:      sess.UserAgent,
		CreatedAt:      sess.CreatedAt,
		ExpiresAt:      sess.ExpiresAt,
		LastActivityAt: sess.LastActivityAt,
		Revoked:        sess.Revoked,
	}, nil
}
