package auth

import (
	"context"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/hidayat-SE/samlguard/pkg/database"
)

// Repository provides data access for user records.
type Repository struct {
	db *gorm.DB
}

// NewRepository creates a new auth repository.
func NewRepository(db *gorm.DB) *Repository {
	return &Repository{db: db}
}

// FindByEmail retrieves a user by email address.
func (r *Repository) FindByEmail(ctx context.Context, email string) (*database.User, error) {
	var user database.User
	result := r.db.WithContext(ctx).Where("email = ?", email).First(&user)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("finding user by email: %w", result.Error)
	}
	return &user, nil
}

// FindByID retrieves a user by ID.
func (r *Repository) FindByID(ctx context.Context, id string) (*database.User, error) {
	var user database.User
	result := r.db.WithContext(ctx).Where("id = ?", id).First(&user)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("finding user by ID: %w", result.Error)
	}
	return &user, nil
}

// CreateOrUpdate creates a new user or updates an existing one based on email.
// This handles the case where a user authenticates via SAML for the first time
// or returns with updated attributes.
func (r *Repository) CreateOrUpdate(ctx context.Context, user *database.User) (*database.User, error) {
	existing, err := r.FindByEmail(ctx, user.Email)
	if err != nil {
		return nil, err
	}

	if existing != nil {
		existing.NameID = user.NameID
		existing.DisplayName = user.DisplayName
		existing.IdPEntityID = user.IdPEntityID
		existing.UpdatedAt = time.Now()

		if result := r.db.WithContext(ctx).Save(existing); result.Error != nil {
			return nil, fmt.Errorf("updating user: %w", result.Error)
		}
		return existing, nil
	}

	if result := r.db.WithContext(ctx).Create(user); result.Error != nil {
		return nil, fmt.Errorf("creating user: %w", result.Error)
	}
	return user, nil
}

// UpdateMFAStatus updates the MFA enabled state and method for a user.
func (r *Repository) UpdateMFAStatus(ctx context.Context, userID string, enabled bool, method string) error {
	result := r.db.WithContext(ctx).
		Model(&database.User{}).
		Where("id = ?", userID).
		Updates(map[string]interface{}{
			"mfa_enabled": enabled,
			"mfa_method":  method,
		})
	if result.Error != nil {
		return fmt.Errorf("updating MFA status: %w", result.Error)
	}
	return nil
}
