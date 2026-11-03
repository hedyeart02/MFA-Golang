package model

import (
	"time"
	"github.com/google/uuid"
)

type CertState string

const (
	CertStateImported CertState = "IMPORTED"
	CertStateActive   CertState = "ACTIVE"
	CertStateExpiring CertState = "EXPIRING"
	CertStateExpired  CertState = "EXPIRED"
	CertStateArchived CertState = "ARCHIVED"
)

// GenerateUUID prefer UUIDv7, fallback to UUIDv4
func GenerateUUID() uuid.UUID {
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.New()
	}
	return id
}

type User struct {
	ID        uuid.UUID
	Email     string
	CreatedAt time.Time
	UpdatedAt time.Time
}

type Session struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	ExpiresAt time.Time
}

// AuditEvent must be append-only
type AuditEvent struct {
	ID        uuid.UUID `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Event     string    `json:"event"`
	Actor     string    `json:"actor"`
	Target    string    `json:"target"`
	Status    string    `json:"status"`
	IPAddress string    `json:"ip_address"`
	Details   string    `json:"details"`
}

// IdPMetadata supports versioning and refresh timestamps
type IdPMetadata struct {
	ID            uuid.UUID
	EntityID      string
	SSOEndpoint   string
	SLOEndpoint   string
	Version       int
	LastRefreshed time.Time
	RawXML        []byte
}

type Certificate struct {
	ID          uuid.UUID
	Type        string // e.g., "signing", "tls"
	State       CertState
	PublicKey   []byte
	PrivateKeyRef string // Pointer to KeyStore or SecretProvider
	ExpiresAt   time.Time
}

// Secret represents an encrypted sensitive value
type Secret struct {
	ID         uuid.UUID
	KeyVersion int
	Name       string
	Ciphertext []byte
}

type Event struct {
	ID        uuid.UUID
	Topic     string
	Payload   []byte
	CreatedAt time.Time
}
