package mfa

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/hidayat-SE/samlguard/internal/config"
	pkgcrypto "github.com/hidayat-SE/samlguard/pkg/crypto"
	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

var (
	ErrNotFound            = errors.New("record not found")
	ErrOTPAlreadyUsed      = errors.New("OTP has already been used")
	ErrOTPExpired          = errors.New("OTP has expired")
	ErrMaxAttemptsExceeded = errors.New("maximum verification attempts exceeded")
	ErrInvalidCode         = errors.New("invalid verification code")
	ErrCooldownActive      = errors.New("resend cooldown active")
	ErrTimestepReplayed    = errors.New("TOTP code has already been used in this time window")
	ErrAccountLocked       = errors.New("account temporarily locked due to multiple failed verification attempts")
)

type MFASecret struct {
	ID                   string
	UserKey              string
	Method               string
	Status               string // "active", "pending"
	SecretEncrypted      []byte
	LastAcceptedTimestep int64
	FailedAttempts       int
	LockedUntil          *time.Time
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

// AuthorizedUser represents an authorized user in the system (from ITA or manual whitelist).
type AuthorizedUser struct {
	ID        int64     `json:"id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	Phone     string    `json:"phone"`
	FullName  string    `json:"full_name"`
	Source    string    `json:"source"` // "ita_sync" or "manual"
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// AdminUser represents an administrator account for accessing the SAMLGuard Admin Console.
type AdminUser struct {
	ID                 int64      `json:"id"`
	Username           string     `json:"username"`
	PasswordHash       string     `json:"-"`
	MustChangePassword bool       `json:"must_change_password"`
	FailedAttempts     int        `json:"failed_attempts"`
	LockedUntil        *time.Time `json:"locked_until"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

type Storage interface {
	Init(ctx context.Context) error
	Close() error

	// TOTP methods
	GetActiveTOTPSecret(ctx context.Context, userKey string) (*MFASecret, error)
	GetPendingTOTPSecret(ctx context.Context, userKey string) (*MFASecret, error)
	SavePendingTOTPSecret(ctx context.Context, secret *MFASecret) error
	ActivateTOTPSecret(ctx context.Context, userKey string, timestep int64) error
	RecordTOTPTimestep(ctx context.Context, userKey string, timestep int64) error
	IncrementTOTPFailure(ctx context.Context, userKey string, maxAttempts int, lockDuration time.Duration) (bool, error)
	ResetTOTPFailure(ctx context.Context, userKey string) error
	DeleteUserTOTPSecrets(ctx context.Context, identifier string) (int64, error)

	// Email OTP methods
	SaveEmailOTP(ctx context.Context, userKey string, hmacDigest []byte, expiresAt, resendAfter time.Time) error
	VerifyAndConsumeEmailOTP(ctx context.Context, userKey string, code string, pepper string, maxAttempts int) (bool, error)
	CheckEmailOTPResend(ctx context.Context, userKey string) (time.Duration, error)

	// SMS OTP methods
	SaveSMSOTP(ctx context.Context, userKey string, hmacDigest []byte, expiresAt, resendAfter time.Time) error
	VerifyAndConsumeSMSOTP(ctx context.Context, userKey string, code string, pepper string, maxAttempts int) (bool, error)
	CheckSMSOTPResend(ctx context.Context, userKey string) (time.Duration, error)

	// User Whitelist / Authorization methods
	IsUserAuthorized(ctx context.Context, identifier string) (bool, error)
	SaveAuthorizedUsers(ctx context.Context, users []AuthorizedUser) error
	ListAuthorizedUsers(ctx context.Context) ([]AuthorizedUser, error)
	AddAuthorizedUser(ctx context.Context, user AuthorizedUser) error
	DeleteAuthorizedUser(ctx context.Context, username string) error
	LookupAuthorizedUserPhone(ctx context.Context, identifiers ...string) (string, error)
	UpdateAuthorizedUserPhone(ctx context.Context, username, phone string) error

	// Admin Authentication methods
	GetAdminUser(ctx context.Context, username string) (*AdminUser, error)
	AuthenticateAdmin(ctx context.Context, username, password string) (*AdminUser, error)
	UpdateAdminPassword(ctx context.Context, username, newPassword string) error

	// Admin Gateway Settings persistence
	SaveAdminSettings(ctx context.Context, settings *config.AdminSettingsPayload) error
	GetAdminSettings(ctx context.Context) (*config.AdminSettingsPayload, error)
}

type SQLiteStorage struct {
	db            *sql.DB
	mu            sync.Mutex // Mutex to serialize SQLite transaction writes safely
	encryptionKey []byte     // Optional 32-byte AES key for encrypting admin settings secrets
}

// SetEncryptionKey configures the 32-byte key used to encrypt/decrypt persisted admin secrets.
func (s *SQLiteStorage) SetEncryptionKey(key []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(key) == 32 {
		s.encryptionKey = append([]byte(nil), key...)
	} else {
		s.encryptionKey = nil
	}
}

// SetEncryptionKeyFromHex configures the encryption key from a 64-character hex string.
func (s *SQLiteStorage) SetEncryptionKeyFromHex(hexKey string) error {
	trimmed := strings.TrimSpace(hexKey)
	if trimmed == "" {
		return nil
	}
	b, err := hex.DecodeString(trimmed)
	if err != nil || len(b) != 32 {
		return errors.New("invalid 32-byte hex encryption key")
	}
	s.SetEncryptionKey(b)
	return nil
}

func NewSQLiteStorage(dbPath string) (*SQLiteStorage, error) {
	connStr := dbPath
	if connStr == "" {
		connStr = "./data/samlguard.db"
	}

	// Auto-create parent directory if storing database on filesystem
	if connStr != ":memory:" && !strings.HasPrefix(connStr, "file::memory:") {
		cleanPath := connStr
		if strings.HasPrefix(cleanPath, "file:") {
			cleanPath = strings.TrimPrefix(cleanPath, "file:")
			if idx := strings.Index(cleanPath, "?"); idx != -1 {
				cleanPath = cleanPath[:idx]
			}
		}
		dir := filepath.Dir(cleanPath)
		if dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0700); err != nil {
				return nil, fmt.Errorf("creating database directory %q: %w", dir, err)
			}
		}
	}

	db, err := sql.Open("sqlite", connStr)
	if err != nil {
		return nil, fmt.Errorf("opening sqlite database: %w", err)
	}

	db.SetMaxOpenConns(1) // SQLite write serialization
	db.SetMaxIdleConns(1)

	s := &SQLiteStorage{db: db}
	if err := s.Init(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("initializing database schema: %w", err)
	}

	// On Unix-like systems, ensure database file permissions are restricted to owner (0600)
	if connStr != ":memory:" && !strings.HasPrefix(connStr, "file::memory:") {
		cleanPath := connStr
		if strings.HasPrefix(cleanPath, "file:") {
			cleanPath = strings.TrimPrefix(cleanPath, "file:")
			if idx := strings.Index(cleanPath, "?"); idx != -1 {
				cleanPath = cleanPath[:idx]
			}
		}
		if fileInfo, err := os.Stat(cleanPath); err == nil && !fileInfo.IsDir() {
			_ = os.Chmod(cleanPath, 0600)
		}
	}

	return s, nil
}

func (s *SQLiteStorage) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

func (s *SQLiteStorage) Init(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Enable WAL mode
	_, _ = s.db.ExecContext(ctx, "PRAGMA journal_mode=WAL;")
	_, _ = s.db.ExecContext(ctx, "PRAGMA busy_timeout=5000;")

	// Check if legacy schema exists in mfa_secrets (database schema migration)
	if rows, err := s.db.QueryContext(ctx, "PRAGMA table_info(mfa_secrets);"); err == nil {
		var hasUserKey, hasUserID, hasStatus, hasLastAccepted bool
		for rows.Next() {
			var cid int
			var name, ctype string
			var notnull, pk int
			var dfltValue interface{}
			if err := rows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk); err == nil {
				switch name {
				case "user_key":
					hasUserKey = true
				case "user_id":
					hasUserID = true
				case "status":
					hasStatus = true
				case "last_accepted_timestep":
					hasLastAccepted = true
				}
			}
		}
		rows.Close()

		if hasUserID && !hasUserKey {
			_, _ = s.db.ExecContext(ctx, "ALTER TABLE mfa_secrets RENAME COLUMN user_id TO user_key;")
		}
		if !hasStatus && (hasUserID || hasUserKey) {
			_, _ = s.db.ExecContext(ctx, "ALTER TABLE mfa_secrets ADD COLUMN status TEXT NOT NULL DEFAULT 'active';")
		}
		if !hasLastAccepted && (hasUserID || hasUserKey) {
			_, _ = s.db.ExecContext(ctx, "ALTER TABLE mfa_secrets ADD COLUMN last_accepted_timestep INTEGER DEFAULT 0;")
		}
	}

	schema := `
	CREATE TABLE IF NOT EXISTS mfa_secrets (
		id TEXT PRIMARY KEY,
		user_key TEXT NOT NULL,
		method TEXT NOT NULL,
		status TEXT NOT NULL,
		secret_encrypted BLOB NOT NULL,
		last_accepted_timestep INTEGER DEFAULT 0,
		failed_attempts INTEGER DEFAULT 0,
		locked_until DATETIME,
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL,
		UNIQUE(user_key, status)
	);
	CREATE UNIQUE INDEX IF NOT EXISTS idx_mfa_secrets_user_status ON mfa_secrets(user_key, status);

	CREATE TABLE IF NOT EXISTS email_otps (
		user_key TEXT PRIMARY KEY,
		hmac_digest BLOB NOT NULL,
		expires_at DATETIME NOT NULL,
		resend_after DATETIME NOT NULL,
		attempts INTEGER DEFAULT 0,
		consumed INTEGER DEFAULT 0,
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_email_otps_expiry ON email_otps(expires_at);

	CREATE TABLE IF NOT EXISTS sms_otps (
		user_key TEXT PRIMARY KEY,
		hmac_digest BLOB NOT NULL,
		expires_at DATETIME NOT NULL,
		resend_after DATETIME NOT NULL,
		attempts INTEGER DEFAULT 0,
		consumed INTEGER DEFAULT 0,
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_sms_otps_expiry ON sms_otps(expires_at);

	CREATE TABLE IF NOT EXISTS authorized_users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL COLLATE NOCASE,
		email TEXT COLLATE NOCASE,
		phone TEXT DEFAULT '',
		full_name TEXT,
		source TEXT NOT NULL DEFAULT 'ita_sync',
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL,
		UNIQUE(username)
	);
	CREATE UNIQUE INDEX IF NOT EXISTS idx_authorized_users_username ON authorized_users(username);
	CREATE INDEX IF NOT EXISTS idx_authorized_users_email ON authorized_users(email);

	CREATE TABLE IF NOT EXISTS admin_users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL COLLATE NOCASE UNIQUE,
		password_hash TEXT NOT NULL,
		must_change_password BOOLEAN NOT NULL DEFAULT 1,
		failed_attempts INTEGER NOT NULL DEFAULT 0,
		locked_until DATETIME,
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL
	);
	CREATE UNIQUE INDEX IF NOT EXISTS idx_admin_users_username ON admin_users(username);

	CREATE TABLE IF NOT EXISTS gateway_settings (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		settings_json TEXT NOT NULL,
		updated_at DATETIME NOT NULL
	);
	`

	if _, err := s.db.ExecContext(ctx, schema); err != nil {
		return err
	}

	// Schema migrations for existing databases
	_, _ = s.db.ExecContext(ctx, "ALTER TABLE mfa_secrets ADD COLUMN failed_attempts INTEGER DEFAULT 0;")
	_, _ = s.db.ExecContext(ctx, "ALTER TABLE mfa_secrets ADD COLUMN locked_until DATETIME;")
	_, _ = s.db.ExecContext(ctx, "ALTER TABLE authorized_users ADD COLUMN phone TEXT DEFAULT '';")
	_, _ = s.db.ExecContext(ctx, "DROP INDEX IF EXISTS idx_mfa_secrets_user_status;")
	_, _ = s.db.ExecContext(ctx, "CREATE UNIQUE INDEX IF NOT EXISTS idx_mfa_secrets_user_status ON mfa_secrets(user_key, status);")

	// Seed default ITA administrator accounts if table is empty
	var userCount int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(1) FROM authorized_users;").Scan(&userCount); err == nil && userCount == 0 {
		now := time.Now()
		_, _ = s.db.ExecContext(ctx, `
			INSERT OR IGNORE INTO authorized_users (username, email, full_name, source, created_at, updated_at) VALUES 
			('apc', 'apc@samlguard.local', 'Default APC Administrator', 'system_default', ?, ?),
			('itaadmin', 'itaadmin@samlguard.local', 'ITA Administrator', 'system_default', ?, ?)
		`, now, now, now, now)
	}

	// Seed default admin account (username: admin, password: admin, must_change_password: 1) if table is empty
	var adminCount int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(1) FROM admin_users;").Scan(&adminCount); err == nil && adminCount == 0 {
		defaultHash, err := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
		if err == nil {
			now := time.Now()
			_, _ = s.db.ExecContext(ctx, `
				INSERT OR IGNORE INTO admin_users (username, password_hash, must_change_password, created_at, updated_at)
				VALUES ('admin', ?, 1, ?, ?)
			`, string(defaultHash), now, now)
		}
	}

	return nil
}

func (s *SQLiteStorage) GetActiveTOTPSecret(ctx context.Context, userKey string) (*MFASecret, error) {
	query := `SELECT id, user_key, method, status, secret_encrypted, last_accepted_timestep, failed_attempts, locked_until, created_at, updated_at
	          FROM mfa_secrets WHERE user_key = ? AND status = 'active' LIMIT 1`

	var sec MFASecret
	var lockedUntil sql.NullTime
	err := s.db.QueryRowContext(ctx, query, userKey).Scan(
		&sec.ID, &sec.UserKey, &sec.Method, &sec.Status, &sec.SecretEncrypted,
		&sec.LastAcceptedTimestep, &sec.FailedAttempts, &lockedUntil, &sec.CreatedAt, &sec.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying active totp secret: %w", err)
	}
	if lockedUntil.Valid {
		sec.LockedUntil = &lockedUntil.Time
	}
	return &sec, nil
}

func (s *SQLiteStorage) GetPendingTOTPSecret(ctx context.Context, userKey string) (*MFASecret, error) {
	query := `SELECT id, user_key, method, status, secret_encrypted, last_accepted_timestep, failed_attempts, locked_until, created_at, updated_at
	          FROM mfa_secrets WHERE user_key = ? AND status = 'pending' LIMIT 1`

	var sec MFASecret
	var lockedUntil sql.NullTime
	err := s.db.QueryRowContext(ctx, query, userKey).Scan(
		&sec.ID, &sec.UserKey, &sec.Method, &sec.Status, &sec.SecretEncrypted,
		&sec.LastAcceptedTimestep, &sec.FailedAttempts, &lockedUntil, &sec.CreatedAt, &sec.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying pending totp secret: %w", err)
	}
	if lockedUntil.Valid {
		sec.LockedUntil = &lockedUntil.Time
	}
	return &sec, nil
}

func (s *SQLiteStorage) SavePendingTOTPSecret(ctx context.Context, sec *MFASecret) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := `INSERT INTO mfa_secrets (id, user_key, method, status, secret_encrypted, last_accepted_timestep, failed_attempts, locked_until, created_at, updated_at)
	          VALUES (?, ?, ?, 'pending', ?, 0, 0, NULL, ?, ?)
	          ON CONFLICT(user_key, status) DO UPDATE SET
	              id = excluded.id,
	              secret_encrypted = excluded.secret_encrypted,
	              last_accepted_timestep = 0,
	              failed_attempts = 0,
	              locked_until = NULL,
	              updated_at = excluded.updated_at`

	now := time.Now().UTC()
	sec.CreatedAt = now
	sec.UpdatedAt = now
	sec.Status = "pending"

	_, err := s.db.ExecContext(ctx, query, sec.ID, sec.UserKey, sec.Method, sec.SecretEncrypted, sec.CreatedAt, sec.UpdatedAt)
	return err
}

func (s *SQLiteStorage) ActivateTOTPSecret(ctx context.Context, userKey string, timestep int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin activate tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// 1. Delete old active secret if any
	_, err = tx.ExecContext(ctx, "DELETE FROM mfa_secrets WHERE user_key = ? AND status = 'active'", userKey)
	if err != nil {
		return fmt.Errorf("deleting previous active secret: %w", err)
	}

	// 2. Promote pending secret to active with initial accepted timestep and reset counters
	now := time.Now().UTC()
	res, err := tx.ExecContext(ctx, `UPDATE mfa_secrets 
	                                  SET status = 'active', last_accepted_timestep = ?, failed_attempts = 0, locked_until = NULL, updated_at = ? 
	                                  WHERE user_key = ? AND status = 'pending'`,
		timestep, now, userKey)
	if err != nil {
		return fmt.Errorf("promoting pending secret: %w", err)
	}

	rows, err := res.RowsAffected()
	if err != nil || rows == 0 {
		return fmt.Errorf("no pending secret found to activate for user: %s", userKey)
	}

	return tx.Commit()
}

func (s *SQLiteStorage) RecordTOTPTimestep(ctx context.Context, userKey string, timestep int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	query := `UPDATE mfa_secrets 
	          SET last_accepted_timestep = ?, failed_attempts = 0, locked_until = NULL, updated_at = ? 
	          WHERE user_key = ? AND status = 'active' 
	            AND (last_accepted_timestep IS NULL OR last_accepted_timestep < ?)`

	res, err := s.db.ExecContext(ctx, query, timestep, now, userKey, timestep)
	if err != nil {
		return fmt.Errorf("updating totp timestep: %w", err)
	}

	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("checking affected rows: %w", err)
	}
	if rows == 0 {
		return ErrTimestepReplayed
	}

	return nil
}

func (s *SQLiteStorage) IncrementTOTPFailure(ctx context.Context, userKey string, maxAttempts int, lockDuration time.Duration) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	lockTime := now.Add(lockDuration)
	query := `UPDATE mfa_secrets 
	          SET failed_attempts = failed_attempts + 1,
	              locked_until = CASE WHEN failed_attempts + 1 >= ? THEN ? ELSE locked_until END,
	              updated_at = ?
	          WHERE user_key = ?`

	_, err := s.db.ExecContext(ctx, query, maxAttempts, lockTime, now, userKey)
	if err != nil {
		return false, err
	}

	var attempts int
	_ = s.db.QueryRowContext(ctx, `SELECT failed_attempts FROM mfa_secrets WHERE user_key = ?`, userKey).Scan(&attempts)
	return attempts >= maxAttempts, nil
}

func (s *SQLiteStorage) ResetTOTPFailure(ctx context.Context, userKey string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	query := `UPDATE mfa_secrets 
	          SET failed_attempts = 0, locked_until = NULL, updated_at = ?
	          WHERE user_key = ?`

	_, err := s.db.ExecContext(ctx, query, now, userKey)
	return err
}

// DeleteUserTOTPSecrets removes all TOTP enrollments (active and pending) matching a userKey or username/email suffix.
func (s *SQLiteStorage) DeleteUserTOTPSecrets(ctx context.Context, identifier string) (int64, error) {
	trimmed := strings.TrimSpace(identifier)
	if trimmed == "" {
		return 0, errors.New("user identifier cannot be empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	res, err := s.db.ExecContext(ctx, `
		DELETE FROM mfa_secrets
		WHERE LOWER(user_key) = LOWER(?)
		   OR LOWER(substr(user_key, instr(user_key, '|') + 1)) = LOWER(?)
	`, trimmed, trimmed)
	if err != nil {
		return 0, fmt.Errorf("deleting user totp secrets: %w", err)
	}
	rows, _ := res.RowsAffected()
	return rows, nil
}

func (s *SQLiteStorage) SaveEmailOTP(ctx context.Context, userKey string, hmacDigest []byte, expiresAt, resendAfter time.Time) error {
	return s.saveChallengeOTP(ctx, "email_otps", userKey, hmacDigest, expiresAt, resendAfter)
}

func (s *SQLiteStorage) CheckEmailOTPResend(ctx context.Context, userKey string) (time.Duration, error) {
	return s.checkChallengeOTPResend(ctx, "email_otps", userKey)
}

func (s *SQLiteStorage) VerifyAndConsumeEmailOTP(ctx context.Context, userKey string, code string, pepper string, maxAttempts int) (bool, error) {
	return s.verifyAndConsumeChallengeOTP(ctx, "email_otps", userKey, code, pepper, maxAttempts)
}

func (s *SQLiteStorage) SaveSMSOTP(ctx context.Context, userKey string, hmacDigest []byte, expiresAt, resendAfter time.Time) error {
	return s.saveChallengeOTP(ctx, "sms_otps", userKey, hmacDigest, expiresAt, resendAfter)
}

func (s *SQLiteStorage) CheckSMSOTPResend(ctx context.Context, userKey string) (time.Duration, error) {
	return s.checkChallengeOTPResend(ctx, "sms_otps", userKey)
}

func (s *SQLiteStorage) VerifyAndConsumeSMSOTP(ctx context.Context, userKey string, code string, pepper string, maxAttempts int) (bool, error) {
	return s.verifyAndConsumeChallengeOTP(ctx, "sms_otps", userKey, code, pepper, maxAttempts)
}

func (s *SQLiteStorage) saveChallengeOTP(ctx context.Context, table, userKey string, hmacDigest []byte, expiresAt, resendAfter time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	query := fmt.Sprintf(`INSERT INTO %s (user_key, hmac_digest, expires_at, resend_after, attempts, consumed, created_at, updated_at)
	          VALUES (?, ?, ?, ?, 0, 0, ?, ?)
	          ON CONFLICT(user_key) DO UPDATE SET
	              hmac_digest = excluded.hmac_digest,
	              expires_at = excluded.expires_at,
	              resend_after = excluded.resend_after,
	              attempts = 0,
	              consumed = 0,
	              updated_at = excluded.updated_at`, table)

	_, err := s.db.ExecContext(ctx, query, userKey, hmacDigest, expiresAt, resendAfter, now, now)
	return err
}

func (s *SQLiteStorage) checkChallengeOTPResend(ctx context.Context, table, userKey string) (time.Duration, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := fmt.Sprintf(`SELECT resend_after FROM %s WHERE user_key = ? LIMIT 1`, table)
	var resendAfter time.Time
	err := s.db.QueryRowContext(ctx, query, userKey).Scan(&resendAfter)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, nil // No existing OTP, resend permitted
		}
		return 0, fmt.Errorf("checking resend cooldown: %w", err)
	}

	now := time.Now().UTC()
	if now.Before(resendAfter) {
		return resendAfter.Sub(now), ErrCooldownActive
	}
	return 0, nil
}

func (s *SQLiteStorage) verifyAndConsumeChallengeOTP(ctx context.Context, table, userKey string, code string, pepper string, maxAttempts int) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return false, fmt.Errorf("begin verify tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	query := fmt.Sprintf(`SELECT hmac_digest, expires_at, attempts, consumed FROM %s WHERE user_key = ? LIMIT 1`, table)
	var storedDigest []byte
	var expiresAt time.Time
	var attempts int
	var consumed int

	err = tx.QueryRowContext(ctx, query, userKey).Scan(&storedDigest, &expiresAt, &attempts, &consumed)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, ErrNotFound
		}
		return false, fmt.Errorf("querying otp from %s: %w", table, err)
	}

	now := time.Now().UTC()

	// 1. Check if already consumed
	if consumed != 0 {
		return false, ErrOTPAlreadyUsed
	}

	// 2. Check if expired
	if now.After(expiresAt) {
		return false, ErrOTPExpired
	}

	// 3. Check attempt limit
	if attempts >= maxAttempts {
		return false, ErrMaxAttemptsExceeded
	}

	// 4. Calculate expected HMAC-SHA256
	mac := hmac.New(sha256.New, []byte(pepper))
	mac.Write([]byte(code))
	expectedDigest := mac.Sum(nil)

	// Constant-time comparison
	if subtle.ConstantTimeCompare(storedDigest, expectedDigest) != 1 {
		// Increment attempts
		_, _ = tx.ExecContext(ctx, fmt.Sprintf(`UPDATE %s SET attempts = attempts + 1, updated_at = ? WHERE user_key = ?`, table), now, userKey)
		_ = tx.Commit()
		return false, ErrInvalidCode
	}

	// 5. Successful match: Atomically mark consumed
	_, err = tx.ExecContext(ctx, fmt.Sprintf(`UPDATE %s SET consumed = 1, updated_at = ? WHERE user_key = ?`, table), now, userKey)
	if err != nil {
		return false, fmt.Errorf("marking otp consumed: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("committing otp verification: %w", err)
	}

	return true, nil
}

// IsUserAuthorized checks if a username, email, or prefix exists in the authorized_users table.
func (s *SQLiteStorage) IsUserAuthorized(ctx context.Context, identifier string) (bool, error) {
	trimmed := strings.ToLower(strings.TrimSpace(identifier))
	if trimmed == "" {
		return false, nil
	}

	// 1. Direct match on username or email
	query := `SELECT COUNT(1) FROM authorized_users WHERE LOWER(username) = ? OR LOWER(email) = ?`
	var count int
	if err := s.db.QueryRowContext(ctx, query, trimmed, trimmed).Scan(&count); err != nil {
		return false, err
	}
	if count > 0 {
		return true, nil
	}

	// 2. If identifier has domain (e.g. user@domain.com), also check prefix as username
	if atIdx := strings.Index(trimmed, "@"); atIdx > 0 {
		prefix := trimmed[:atIdx]
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM authorized_users WHERE LOWER(username) = ?`, prefix).Scan(&count); err == nil && count > 0 {
			return true, nil
		}
	}

	return false, nil
}

// SaveAuthorizedUsers atomically saves or updates multiple users from ITA API sync.
func (s *SQLiteStorage) SaveAuthorizedUsers(ctx context.Context, users []AuthorizedUser) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	now := time.Now()
	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO authorized_users (username, email, phone, full_name, source, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(username) DO UPDATE SET
			email = CASE WHEN excluded.email != '' THEN excluded.email ELSE authorized_users.email END,
			phone = CASE WHEN excluded.phone != '' THEN excluded.phone ELSE authorized_users.phone END,
			full_name = CASE WHEN excluded.full_name != '' THEN excluded.full_name ELSE authorized_users.full_name END,
			source = excluded.source,
			updated_at = excluded.updated_at
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, u := range users {
		uname := strings.TrimSpace(u.Username)
		if uname == "" {
			continue
		}
		source := u.Source
		if source == "" {
			source = "ita_sync"
		}
		if _, err := stmt.ExecContext(ctx, uname, strings.TrimSpace(u.Email), NormalizePhoneNumber(u.Phone), strings.TrimSpace(u.FullName), source, now, now); err != nil {
			return err
		}
	}

	return tx.Commit()
}

// ListAuthorizedUsers retrieves all authorized users from the database.
func (s *SQLiteStorage) ListAuthorizedUsers(ctx context.Context) ([]AuthorizedUser, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, username, COALESCE(email, ''), COALESCE(phone, ''), COALESCE(full_name, ''), source, created_at, updated_at FROM authorized_users ORDER BY username ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []AuthorizedUser
	for rows.Next() {
		var u AuthorizedUser
		if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.Phone, &u.FullName, &u.Source, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, err
		}
		list = append(list, u)
	}
	return list, nil
}

// AddAuthorizedUser adds a single authorized user (manual whitelist).
func (s *SQLiteStorage) AddAuthorizedUser(ctx context.Context, user AuthorizedUser) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	uname := strings.TrimSpace(user.Username)
	if uname == "" {
		return errors.New("username cannot be empty")
	}
	source := user.Source
	if source == "" {
		source = "manual"
	}

	now := time.Now()
	query := `
		INSERT INTO authorized_users (username, email, phone, full_name, source, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(username) DO UPDATE SET
			email = excluded.email,
			phone = CASE WHEN excluded.phone != '' THEN excluded.phone ELSE authorized_users.phone END,
			full_name = excluded.full_name,
			source = excluded.source,
			updated_at = excluded.updated_at
	`
	_, err := s.db.ExecContext(ctx, query, uname, strings.TrimSpace(user.Email), NormalizePhoneNumber(user.Phone), strings.TrimSpace(user.FullName), source, now, now)
	return err
}

// LookupAuthorizedUserPhone looks up the stored mobile phone number matching any of the given identifiers (username or email).
func (s *SQLiteStorage) LookupAuthorizedUserPhone(ctx context.Context, identifiers ...string) (string, error) {
	for _, raw := range identifiers {
		trimmed := strings.ToLower(strings.TrimSpace(raw))
		if trimmed == "" {
			continue
		}
		var phone string
		err := s.db.QueryRowContext(ctx,
			`SELECT COALESCE(phone, '') FROM authorized_users WHERE (LOWER(username) = ? OR LOWER(email) = ?) AND COALESCE(phone, '') != '' LIMIT 1`,
			trimmed, trimmed,
		).Scan(&phone)
		if err == nil && strings.TrimSpace(phone) != "" {
			return strings.TrimSpace(phone), nil
		}
		if atIdx := strings.Index(trimmed, "@"); atIdx > 0 {
			prefix := trimmed[:atIdx]
			err = s.db.QueryRowContext(ctx,
				`SELECT COALESCE(phone, '') FROM authorized_users WHERE LOWER(username) = ? AND COALESCE(phone, '') != '' LIMIT 1`,
				prefix,
			).Scan(&phone)
			if err == nil && strings.TrimSpace(phone) != "" {
				return strings.TrimSpace(phone), nil
			}
		}
	}
	return "", ErrNotFound
}

// UpdateAuthorizedUserPhone updates the mobile phone number for an existing user in authorized_users.
func (s *SQLiteStorage) UpdateAuthorizedUserPhone(ctx context.Context, username, phone string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	trimmed := strings.TrimSpace(username)
	if trimmed == "" {
		return errors.New("username cannot be empty")
	}
	normPhone := NormalizePhoneNumber(phone)
	res, err := s.db.ExecContext(ctx,
		`UPDATE authorized_users SET phone = ?, updated_at = ? WHERE LOWER(username) = LOWER(?)`,
		normPhone, time.Now(), trimmed,
	)
	if err != nil {
		return err
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteAuthorizedUser removes a user from the authorized users table.
func (s *SQLiteStorage) DeleteAuthorizedUser(ctx context.Context, username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	trimmed := strings.TrimSpace(username)
	if trimmed == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM authorized_users WHERE LOWER(username) = LOWER(?)`, trimmed)
	return err
}

// GetAdminUser fetches an admin user record by username.
func (s *SQLiteStorage) GetAdminUser(ctx context.Context, username string) (*AdminUser, error) {
	trimmed := strings.ToLower(strings.TrimSpace(username))
	if trimmed == "" {
		return nil, errors.New("username cannot be empty")
	}

	var u AdminUser
	var lockedUntil sql.NullTime
	query := `SELECT id, username, password_hash, must_change_password, failed_attempts, locked_until, created_at, updated_at FROM admin_users WHERE LOWER(username) = ?`
	err := s.db.QueryRowContext(ctx, query, trimmed).Scan(
		&u.ID, &u.Username, &u.PasswordHash, &u.MustChangePassword, &u.FailedAttempts, &lockedUntil, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if lockedUntil.Valid {
		u.LockedUntil = &lockedUntil.Time
	}
	return &u, nil
}

// AuthenticateAdmin verifies credentials for the admin user, checking lockout and password hash.
func (s *SQLiteStorage) AuthenticateAdmin(ctx context.Context, username, password string) (*AdminUser, error) {
	trimmed := strings.ToLower(strings.TrimSpace(username))
	if trimmed == "" || password == "" {
		return nil, errors.New("username and password are required")
	}

	var u AdminUser
	var lockedUntil sql.NullTime
	query := `SELECT id, username, password_hash, must_change_password, failed_attempts, locked_until, created_at, updated_at FROM admin_users WHERE LOWER(username) = ?`
	err := s.db.QueryRowContext(ctx, query, trimmed).Scan(
		&u.ID, &u.Username, &u.PasswordHash, &u.MustChangePassword, &u.FailedAttempts, &lockedUntil, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("invalid administrator credentials")
		}
		return nil, err
	}

	now := time.Now()
	if lockedUntil.Valid && now.Before(lockedUntil.Time) {
		remaining := time.Until(lockedUntil.Time).Round(time.Second)
		return nil, fmt.Errorf("account temporarily locked due to multiple failed attempts. Try again in %v", remaining)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)); err != nil {
		s.mu.Lock()
		_, _ = s.db.ExecContext(ctx, `UPDATE admin_users SET failed_attempts = failed_attempts + 1, updated_at = ? WHERE id = ?`, now, u.ID)
		if u.FailedAttempts+1 >= 5 {
			lockTime := now.Add(15 * time.Minute)
			_, _ = s.db.ExecContext(ctx, `UPDATE admin_users SET locked_until = ? WHERE id = ?`, lockTime, u.ID)
		}
		s.mu.Unlock()
		return nil, errors.New("invalid administrator credentials")
	}

	// Reset failure count on success
	s.mu.Lock()
	_, _ = s.db.ExecContext(ctx, `UPDATE admin_users SET failed_attempts = 0, locked_until = NULL, updated_at = ? WHERE id = ?`, now, u.ID)
	s.mu.Unlock()

	return &u, nil
}

// UpdateAdminPassword updates the administrator password, sets must_change_password to false, and resets failures.
func (s *SQLiteStorage) UpdateAdminPassword(ctx context.Context, username, newPassword string) error {
	trimmed := strings.ToLower(strings.TrimSpace(username))
	if len(newPassword) < 8 {
		return errors.New("new password must be at least 8 characters long")
	}
	if newPassword == "admin" || newPassword == "admin123" {
		return errors.New("new password cannot be the default password ('admin' or 'admin123')")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hashing password: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	res, err := s.db.ExecContext(ctx, `UPDATE admin_users SET password_hash = ?, must_change_password = 0, failed_attempts = 0, locked_until = NULL, updated_at = ? WHERE LOWER(username) = ?`, string(hash), now, trimmed)
	if err != nil {
		return err
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return errors.New("administrator user not found")
	}
	return nil
}

const encryptedSecretPrefix = "enc:v1:"

func (s *SQLiteStorage) encryptSettingSecret(plaintext string) (string, error) {
	if plaintext == "" || strings.HasPrefix(plaintext, encryptedSecretPrefix) || len(s.encryptionKey) != 32 {
		return plaintext, nil
	}
	cipherBytes, err := pkgcrypto.Encrypt(s.encryptionKey, []byte(plaintext))
	if err != nil {
		return "", err
	}
	return encryptedSecretPrefix + base64.StdEncoding.EncodeToString(cipherBytes), nil
}

func (s *SQLiteStorage) decryptSettingSecret(val string) (string, error) {
	if !strings.HasPrefix(val, encryptedSecretPrefix) {
		return val, nil
	}
	if len(s.encryptionKey) != 32 {
		return "", errors.New("cannot decrypt persisted secret: encryption key not configured")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(val, encryptedSecretPrefix))
	if err != nil {
		return "", fmt.Errorf("decoding encrypted setting secret: %w", err)
	}
	plain, err := pkgcrypto.Decrypt(s.encryptionKey, raw)
	if err != nil {
		return "", fmt.Errorf("decrypting setting secret: %w", err)
	}
	return string(plain), nil
}

// SaveAdminSettings persists the Admin Console gateway settings as JSON in SQLite.
// Sensitive credentials (SMTPPassword, ITAAPIPassword) are encrypted at rest when an encryption key is configured.
func (s *SQLiteStorage) SaveAdminSettings(ctx context.Context, settings *config.AdminSettingsPayload) error {
	if settings == nil {
		return errors.New("settings payload cannot be nil")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	toStore := *settings
	var err error
	if toStore.SMTPPassword, err = s.encryptSettingSecret(toStore.SMTPPassword); err != nil {
		return fmt.Errorf("encrypting smtp password: %w", err)
	}
	if toStore.SMSAuthToken, err = s.encryptSettingSecret(toStore.SMSAuthToken); err != nil {
		return fmt.Errorf("encrypting sms auth token: %w", err)
	}
	if len(toStore.SMSProfiles) > 0 {
		encProfiles := make(map[string]config.SMSGatewayProfile, len(toStore.SMSProfiles))
		for k, prof := range toStore.SMSProfiles {
			if prof.AuthToken != "" {
				encTok, tokErr := s.encryptSettingSecret(prof.AuthToken)
				if tokErr != nil {
					return fmt.Errorf("encrypting sms profile %s auth token: %w", k, tokErr)
				}
				prof.AuthToken = encTok
			}
			encProfiles[k] = prof
		}
		toStore.SMSProfiles = encProfiles
	}
	if toStore.ITAAPIPassword, err = s.encryptSettingSecret(toStore.ITAAPIPassword); err != nil {
		return fmt.Errorf("encrypting ita api password: %w", err)
	}

	raw, err := json.Marshal(&toStore)
	if err != nil {
		return fmt.Errorf("marshaling gateway settings: %w", err)
	}

	now := time.Now().UTC()
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO gateway_settings (id, settings_json, updated_at)
		VALUES (1, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			settings_json = excluded.settings_json,
			updated_at = excluded.updated_at
	`, string(raw), now)
	if err != nil {
		return fmt.Errorf("saving gateway settings: %w", err)
	}
	return nil
}

// GetAdminSettings loads persisted Admin Console gateway settings from SQLite.
func (s *SQLiteStorage) GetAdminSettings(ctx context.Context) (*config.AdminSettingsPayload, error) {
	var raw string
	err := s.db.QueryRowContext(ctx, `SELECT settings_json FROM gateway_settings WHERE id = 1`).Scan(&raw)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying gateway settings: %w", err)
	}

	var settings config.AdminSettingsPayload
	if err := json.Unmarshal([]byte(raw), &settings); err != nil {
		return nil, fmt.Errorf("unmarshaling gateway settings: %w", err)
	}

	if settings.SMTPPassword, err = s.decryptSettingSecret(settings.SMTPPassword); err != nil {
		return nil, err
	}
	if settings.SMSAuthToken, err = s.decryptSettingSecret(settings.SMSAuthToken); err != nil {
		return nil, err
	}
	for k, prof := range settings.SMSProfiles {
		if prof.AuthToken != "" {
			decTok, decErr := s.decryptSettingSecret(prof.AuthToken)
			if decErr != nil {
				return nil, decErr
			}
			prof.AuthToken = decTok
			settings.SMSProfiles[k] = prof
		}
	}
	if settings.ITAAPIPassword, err = s.decryptSettingSecret(settings.ITAAPIPassword); err != nil {
		return nil, err
	}
	return &settings, nil
}
