package audit

import (
	"context"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/hidayat-SE/samlguard/pkg/database"
)

// Repository provides data access for audit log entries.
type Repository struct {
	db *gorm.DB
}

// NewRepository creates a new audit repository.
func NewRepository(db *gorm.DB) *Repository {
	return &Repository{db: db}
}

// Create inserts a new audit log entry.
func (r *Repository) Create(ctx context.Context, log *database.AuditLog) error {
	result := r.db.WithContext(ctx).Create(log)
	if result.Error != nil {
		return fmt.Errorf("creating audit log: %w", result.Error)
	}
	return nil
}

// FindAll returns paginated audit logs matching the given filters.
func (r *Repository) FindAll(ctx context.Context, params LogQueryParams) ([]database.AuditLog, int64, error) {
	var logs []database.AuditLog
	var total int64

	query := r.db.WithContext(ctx).Model(&database.AuditLog{})

	if params.UserID != "" {
		query = query.Where("user_id = ?", params.UserID)
	}
	if params.EventType != "" {
		query = query.Where("event_type = ?", params.EventType)
	}
	if params.Severity != "" {
		query = query.Where("severity = ?", params.Severity)
	}
	if !params.StartDate.IsZero() {
		query = query.Where("created_at >= ?", params.StartDate)
	}
	if !params.EndDate.IsZero() {
		query = query.Where("created_at <= ?", params.EndDate)
	}

	if err := query.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("counting audit logs: %w", err)
	}

	offset := (params.Page - 1) * params.PageSize
	result := query.Order("created_at DESC").
		Offset(offset).
		Limit(params.PageSize).
		Find(&logs)

	if result.Error != nil {
		return nil, 0, fmt.Errorf("querying audit logs: %w", result.Error)
	}

	return logs, total, nil
}

// GetEventTypes returns all distinct event types in the audit log.
func (r *Repository) GetEventTypes(ctx context.Context) ([]string, error) {
	var types []string
	result := r.db.WithContext(ctx).
		Model(&database.AuditLog{}).
		Distinct("event_type").
		Pluck("event_type", &types)

	if result.Error != nil {
		return nil, fmt.Errorf("querying event types: %w", result.Error)
	}

	return types, nil
}

// DeleteOlderThan removes audit logs older than the given duration.
func (r *Repository) DeleteOlderThan(ctx context.Context, age time.Duration) (int64, error) {
	cutoff := time.Now().Add(-age)
	result := r.db.WithContext(ctx).
		Where("created_at < ?", cutoff).
		Delete(&database.AuditLog{})

	if result.Error != nil {
		return 0, fmt.Errorf("deleting old audit logs: %w", result.Error)
	}

	return result.RowsAffected, nil
}
