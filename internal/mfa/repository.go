package mfa

import (
	"context"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/hidayat-SE/samlguard/pkg/database"
)

// Repository provides data access for MFA secrets and trusted devices.
type Repository struct {
	db *gorm.DB
}

// NewRepository creates a new MFA repository.
func NewRepository(db *gorm.DB) *Repository {
	return &Repository{db: db}
}

// FindSecretByUserAndMethod retrieves the MFA secret for a user and method.
func (r *Repository) FindSecretByUserAndMethod(ctx context.Context, userID, method string) (*database.MFASecret, error) {
	var secret database.MFASecret
	result := r.db.WithContext(ctx).
		Where("user_id = ? AND method = ?", userID, method).
		First(&secret)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("finding MFA secret: %w", result.Error)
	}
	return &secret, nil
}

// FindSecretsByUser retrieves all MFA secrets for a user.
func (r *Repository) FindSecretsByUser(ctx context.Context, userID string) ([]database.MFASecret, error) {
	var secrets []database.MFASecret
	result := r.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Find(&secrets)
	if result.Error != nil {
		return nil, fmt.Errorf("finding MFA secrets: %w", result.Error)
	}
	return secrets, nil
}

// CreateSecret creates a new MFA secret record.
func (r *Repository) CreateSecret(ctx context.Context, secret *database.MFASecret) error {
	result := r.db.WithContext(ctx).Create(secret)
	if result.Error != nil {
		return fmt.Errorf("creating MFA secret: %w", result.Error)
	}
	return nil
}

// UpdateSecret updates an existing MFA secret.
func (r *Repository) UpdateSecret(ctx context.Context, secret *database.MFASecret) error {
	result := r.db.WithContext(ctx).Save(secret)
	if result.Error != nil {
		return fmt.Errorf("updating MFA secret: %w", result.Error)
	}
	return nil
}

// DeleteSecretsByUser deletes all MFA secrets for a user.
func (r *Repository) DeleteSecretsByUser(ctx context.Context, userID string) error {
	result := r.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Delete(&database.MFASecret{})
	if result.Error != nil {
		return fmt.Errorf("deleting MFA secrets: %w", result.Error)
	}
	return nil
}

// IncrementRetryCount increments the retry counter for a user's MFA secret.
func (r *Repository) IncrementRetryCount(ctx context.Context, secretID string) error {
	result := r.db.WithContext(ctx).
		Model(&database.MFASecret{}).
		Where("id = ?", secretID).
		Updates(map[string]interface{}{
			"retry_count":  gorm.Expr("retry_count + 1"),
			"last_retry_at": time.Now(),
		})
	if result.Error != nil {
		return fmt.Errorf("incrementing retry count: %w", result.Error)
	}
	return nil
}

// ResetRetryCount resets the retry counter.
func (r *Repository) ResetRetryCount(ctx context.Context, secretID string) error {
	result := r.db.WithContext(ctx).
		Model(&database.MFASecret{}).
		Where("id = ?", secretID).
		Updates(map[string]interface{}{
			"retry_count": 0,
		})
	if result.Error != nil {
		return fmt.Errorf("resetting retry count: %w", result.Error)
	}
	return nil
}

// FindTrustedDevice retrieves a trusted device by user and fingerprint.
func (r *Repository) FindTrustedDevice(ctx context.Context, userID, fingerprint string) (*database.TrustedDevice, error) {
	var device database.TrustedDevice
	result := r.db.WithContext(ctx).
		Where("user_id = ? AND device_fingerprint = ?", userID, fingerprint).
		First(&device)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("finding trusted device: %w", result.Error)
	}
	return &device, nil
}

// CreateTrustedDevice creates a new trusted device record.
func (r *Repository) CreateTrustedDevice(ctx context.Context, device *database.TrustedDevice) error {
	result := r.db.WithContext(ctx).Create(device)
	if result.Error != nil {
		return fmt.Errorf("creating trusted device: %w", result.Error)
	}
	return nil
}

// UpdateTrustedDeviceLastUsed updates the last used timestamp.
func (r *Repository) UpdateTrustedDeviceLastUsed(ctx context.Context, deviceID string) error {
	result := r.db.WithContext(ctx).
		Model(&database.TrustedDevice{}).
		Where("id = ?", deviceID).
		Update("last_used_at", time.Now())
	if result.Error != nil {
		return fmt.Errorf("updating trusted device: %w", result.Error)
	}
	return nil
}
