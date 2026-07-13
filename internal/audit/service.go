package audit

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/hidayat-SE/samlguard/pkg/database"
)

// Service contains the business logic for audit logging.
type Service struct {
	repo   *Repository
	logger *zap.Logger
}

// NewService creates a new audit service.
func NewService(repo *Repository, log *zap.Logger) *Service {
	return &Service{
		repo:   repo,
		logger: log,
	}
}

// LogEvent creates a new audit log entry from the request.
func (s *Service) LogEvent(ctx context.Context, req LogEventRequest) (*LogEventResponse, error) {
	severity := req.Severity
	if severity == "" {
		severity = "info"
	}

	entry := &database.AuditLog{
		ID:            uuid.New().String(),
		UserID:        req.UserID,
		EventType:     req.EventType,
		Action:        req.Action,
		IPAddress:     req.IPAddress,
		UserAgent:     req.UserAgent,
		CorrelationID: req.CorrelationID,
		Details:       req.Details,
		Severity:      severity,
		CreatedAt:     time.Now(),
	}

	if err := s.repo.Create(ctx, entry); err != nil {
		return nil, fmt.Errorf("logging audit event: %w", err)
	}

	s.logger.Info("audit event logged",
		zap.String("event_id", entry.ID),
		zap.String("event_type", entry.EventType),
		zap.String("action", entry.Action),
		zap.String("user_id", entry.UserID),
		zap.String("severity", severity),
	)

	return &LogEventResponse{
		ID:        entry.ID,
		CreatedAt: entry.CreatedAt,
	}, nil
}

// QueryLogs retrieves paginated audit logs matching filters.
func (s *Service) QueryLogs(ctx context.Context, params LogQueryParams) ([]database.AuditLog, int64, error) {
	if params.Page < 1 {
		params.Page = 1
	}
	if params.PageSize < 1 || params.PageSize > 100 {
		params.PageSize = 20
	}

	logs, total, err := s.repo.FindAll(ctx, params)
	if err != nil {
		return nil, 0, fmt.Errorf("querying audit logs: %w", err)
	}

	return logs, total, nil
}

// GetEventTypes returns all distinct event types.
func (s *Service) GetEventTypes(ctx context.Context) ([]string, error) {
	types, err := s.repo.GetEventTypes(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting event types: %w", err)
	}
	return types, nil
}
