package database

import (
	"time"

	"gorm.io/gorm"
)

// BaseModel provides common fields for all database models.
type BaseModel struct {
	ID        string         `gorm:"type:text;primaryKey" json:"id"`
	CreatedAt time.Time      `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt time.Time      `gorm:"autoUpdateTime" json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`
}

// User represents an authenticated user from a SAML identity provider.
type User struct {
	BaseModel
	Email       string `gorm:"type:text;uniqueIndex;not null" json:"email"`
	NameID      string `gorm:"type:text" json:"name_id"`
	DisplayName string `gorm:"type:text" json:"display_name"`
	IdPEntityID string `gorm:"type:text" json:"idp_entity_id"`
	MFAEnabled  bool   `gorm:"default:false" json:"mfa_enabled"`
	MFAMethod   string `gorm:"type:text" json:"mfa_method"`

	MFASecrets     []MFASecret     `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE" json:"mfa_secrets,omitempty"`
	Sessions       []Session       `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE" json:"sessions,omitempty"`
	TrustedDevices []TrustedDevice `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE" json:"trusted_devices,omitempty"`
}

// TableName returns the table name for User.
func (User) TableName() string {
	return "users"
}

// MFASecret stores encrypted MFA secrets for a user.
type MFASecret struct {
	BaseModel
	UserID          string    `gorm:"type:text;index;not null" json:"user_id"`
	Method          string    `gorm:"type:text;not null" json:"method"`
	SecretEncrypted []byte    `gorm:"type:blob" json:"-"`
	BackupCodesHash string    `gorm:"type:text" json:"-"`
	RetryCount      int       `gorm:"default:0" json:"retry_count"`
	LastRetryAt     time.Time `json:"last_retry_at"`
	Verified        bool      `gorm:"default:false" json:"verified"`
}

// TableName returns the table name for MFASecret.
func (MFASecret) TableName() string {
	return "mfa_secrets"
}

// Session represents an active user session.
type Session struct {
	BaseModel
	UserID           string    `gorm:"type:text;index;not null" json:"user_id"`
	TokenHash        string    `gorm:"type:text;not null" json:"-"`
	RefreshTokenHash string    `gorm:"type:text" json:"-"`
	IPAddress        string    `gorm:"type:text" json:"ip_address"`
	UserAgent        string    `gorm:"type:text" json:"user_agent"`
	ExpiresAt        time.Time `gorm:"not null" json:"expires_at"`
	IdleExpiresAt    time.Time `gorm:"not null" json:"idle_expires_at"`
	LastActivityAt   time.Time `json:"last_activity_at"`
	Revoked          bool      `gorm:"default:false" json:"revoked"`
}

// TableName returns the table name for Session.
func (Session) TableName() string {
	return "sessions"
}

// IsExpired checks whether the session has exceeded its absolute or idle timeout.
func (s Session) IsExpired() bool {
	now := time.Now()
	return now.After(s.ExpiresAt) || now.After(s.IdleExpiresAt)
}

// AuditLog records security-relevant events.
type AuditLog struct {
	ID            string    `gorm:"type:text;primaryKey" json:"id"`
	UserID        string    `gorm:"type:text;index" json:"user_id,omitempty"`
	EventType     string    `gorm:"type:text;index;not null" json:"event_type"`
	Action        string    `gorm:"type:text;not null" json:"action"`
	IPAddress     string    `gorm:"type:text" json:"ip_address"`
	UserAgent     string    `gorm:"type:text" json:"user_agent"`
	CorrelationID string    `gorm:"type:text;index" json:"correlation_id"`
	Details       string    `gorm:"type:text" json:"details"`
	Severity      string    `gorm:"type:text;default:'info'" json:"severity"`
	CreatedAt     time.Time `gorm:"autoCreateTime;index" json:"created_at"`
}

// TableName returns the table name for AuditLog.
func (AuditLog) TableName() string {
	return "audit_logs"
}

// Configuration stores runtime configuration key-value pairs.
type Configuration struct {
	BaseModel
	Key         string `gorm:"type:text;uniqueIndex;not null" json:"key"`
	Value       string `gorm:"type:text;not null" json:"value"`
	Description string `gorm:"type:text" json:"description"`
}

// TableName returns the table name for Configuration.
func (Configuration) TableName() string {
	return "configuration"
}

// TrustedDevice represents a device trusted for MFA bypass.
type TrustedDevice struct {
	BaseModel
	UserID            string    `gorm:"type:text;index;not null" json:"user_id"`
	DeviceFingerprint string    `gorm:"type:text;not null" json:"device_fingerprint"`
	DeviceName        string    `gorm:"type:text" json:"device_name"`
	TrustedUntil      time.Time `gorm:"not null" json:"trusted_until"`
	LastUsedAt        time.Time `json:"last_used_at"`
}

// TableName returns the table name for TrustedDevice.
func (TrustedDevice) TableName() string {
	return "trusted_devices"
}

// IsTrusted checks whether the device is still within its trust period.
func (td TrustedDevice) IsTrusted() bool {
	return time.Now().Before(td.TrustedUntil)
}
