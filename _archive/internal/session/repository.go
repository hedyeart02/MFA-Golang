package session

import (
	"context"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/hidayat-SE/samlguard/pkg/database"
)

// Repository provides data access for session records.
type Repository struct {
	db *gorm.DB
}

// NewRepository creates a new session repository.
func NewRepository(db *gorm.DB) *Repository {
	return &Repository{db: db}
}

// Create inserts a new session record.
func (r *Repository) Create(ctx context.Context, session *database.Session) error {
	result := r.db.WithContext(ctx).Create(session)
	if result.Error != nil {
		return fmt.Errorf("creating session: %w", result.Error)
	}
	return nil
}

// FindByID retrieves a session by its ID.
func (r *Repository) FindByID(ctx context.Context, id string) (*database.Session, error) {
	var session database.Session
	result := r.db.WithContext(ctx).Where("id = ?", id).First(&session)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("finding session: %w", result.Error)
	}
	return &session, nil
}

// FindByTokenHash retrieves a session by its token hash.
func (r *Repository) FindByTokenHash(ctx context.Context, tokenHash string) (*database.Session, error) {
	var session database.Session
	result := r.db.WithContext(ctx).Where("token_hash = ?", tokenHash).First(&session)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("finding session by token: %w", result.Error)
	}
	return &session, nil
}

// FindByUserID retrieves all active sessions for a user.
func (r *Repository) FindByUserID(ctx context.Context, userID string) ([]database.Session, error) {
	var sessions []database.Session
	result := r.db.WithContext(ctx).
		Where("user_id = ? AND revoked = ?", userID, false).
		Order("created_at DESC").
		Find(&sessions)
	if result.Error != nil {
		return nil, fmt.Errorf("finding sessions for user: %w", result.Error)
	}
	return sessions, nil
}

// UpdateActivity updates the last activity timestamp.
func (r *Repository) UpdateActivity(ctx context.Context, id string, idleExpiresAt time.Time) error {
	result := r.db.WithContext(ctx).
		Model(&database.Session{}).
		Where("id = ?", id).
		Updates(map[string]interface{}{
			"last_activity_at": time.Now(),
			"idle_expires_at":  idleExpiresAt,
		})
	if result.Error != nil {
		return fmt.Errorf("updating session activity: %w", result.Error)
	}
	return nil
}

// Revoke marks a session as revoked.
func (r *Repository) Revoke(ctx context.Context, id string) error {
	result := r.db.WithContext(ctx).
		Model(&database.Session{}).
		Where("id = ?", id).
		Update("revoked", true)
	if result.Error != nil {
		return fmt.Errorf("revoking session: %w", result.Error)
	}
	return nil
}

// RevokeAllForUser revokes all sessions for a user.
func (r *Repository) RevokeAllForUser(ctx context.Context, userID string) error {
	result := r.db.WithContext(ctx).
		Model(&database.Session{}).
		Where("user_id = ? AND revoked = ?", userID, false).
		Update("revoked", true)
	if result.Error != nil {
		return fmt.Errorf("revoking all sessions for user: %w", result.Error)
	}
	return nil
}

// DeleteExpired removes expired and revoked sessions.
func (r *Repository) DeleteExpired(ctx context.Context) (int64, error) {
	now := time.Now()
	result := r.db.WithContext(ctx).
		Where("expires_at < ? OR (revoked = ? AND updated_at < ?)", now, true, now.Add(-24*time.Hour)).
		Delete(&database.Session{})
	if result.Error != nil {
		return 0, fmt.Errorf("deleting expired sessions: %w", result.Error)
	}
	return result.RowsAffected, nil
}

// EnsureUserExists checks if a user exists in the session database. If not, it creates a placeholder.
func (r *Repository) EnsureUserExists(ctx context.Context, userID string) error {
	var user database.User
	err := r.db.WithContext(ctx).First(&user, "id = ?", userID).Error
	if err == nil {
		return nil
	}
	// GORM ErrRecordNotFound
	placeholder := &database.User{
		BaseModel: database.BaseModel{ID: userID},
		Email:       userID + "@example.com",
		NameID:      userID,
		DisplayName: userID,
	}
	if err := r.db.WithContext(ctx).Create(placeholder).Error; err != nil {
		return fmt.Errorf("creating placeholder user: %w", err)
	}
	return nil
}
