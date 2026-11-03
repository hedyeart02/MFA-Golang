package persistence

import "context"

// Generic Repository for simple CRUD operations
type Repository[T any] interface {
	FindByID(ctx context.Context, id string) (*T, error)
	FindAll(ctx context.Context, limit, offset int) ([]T, error)
	Create(ctx context.Context, entity *T) error
	Update(ctx context.Context, entity *T) error
	Delete(ctx context.Context, id string) error
}

// AuditRepository enforces append-only semantics
type AuditRepository interface {
	LogEvent(ctx context.Context, event interface{}) error
	QueryEvents(ctx context.Context, filter map[string]interface{}) ([]interface{}, error)
}

// MetadataRepository handles metadata lifecycle and versioning
type MetadataRepository interface {
	GetLatest(ctx context.Context, entityID string) (interface{}, error)
	SaveVersion(ctx context.Context, metadata interface{}) error
}

// CertificateRepository handles certificate states
type CertificateRepository interface {
	GetActive(ctx context.Context, certType string) (interface{}, error)
	Save(ctx context.Context, cert interface{}) error
	UpdateState(ctx context.Context, id string, state string) error
}

// UnitOfWork defines the transactional boundary
type UnitOfWork interface {
	Begin(ctx context.Context) (context.Context, error)
	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
}
