package mfa

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

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
	FullName  string    `json:"full_name"`
	Source    string    `json:"source"` // "ita_sync" or "manual"
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
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

	// Email OTP methods
	SaveEmailOTP(ctx context.Context, userKey string, hmacDigest []byte, expiresAt, resendAfter time.Time) error
	VerifyAndConsumeEmailOTP(ctx context.Context, userKey string, code string, pepper string, maxAttempts int) (bool, error)
	CheckEmailOTPResend(ctx context.Context, userKey string) (time.Duration, error)

	// User Whitelist / Authorization methods
	IsUserAuthorized(ctx context.Context, identifier string) (bool, error)
	SaveAuthorizedUsers(ctx context.Context, users []AuthorizedUser) error
	ListAuthorizedUsers(ctx context.Context) ([]AuthorizedUser, error)
	AddAuthorizedUser(ctx context.Context, user AuthorizedUser) error
	DeleteAuthorizedUser(ctx context.Context, username string) error
}

type SQLiteStorage struct {
	db *sql.DB
	mu sync.Mutex // Mutex to serialize SQLite transaction writes safely
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

	CREATE TABLE IF NOT EXISTS authorized_users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL COLLATE NOCASE,
		email TEXT COLLATE NOCASE,
		full_name TEXT,
		source TEXT NOT NULL DEFAULT 'ita_sync',
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL,
		UNIQUE(username)
	);
	CREATE UNIQUE INDEX IF NOT EXISTS idx_authorized_users_username ON authorized_users(username);
	CREATE INDEX IF NOT EXISTS idx_authorized_users_email ON authorized_users(email);
	`

	if _, err := s.db.ExecContext(ctx, schema); err != nil {
		return err
	}

	// Schema migrations for existing databases
	_, _ = s.db.ExecContext(ctx, "ALTER TABLE mfa_secrets ADD COLUMN failed_attempts INTEGER DEFAULT 0;")
	_, _ = s.db.ExecContext(ctx, "ALTER TABLE mfa_secrets ADD COLUMN locked_until DATETIME;")
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

func (s *SQLiteStorage) SaveEmailOTP(ctx context.Context, userKey string, hmacDigest []byte, expiresAt, resendAfter time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	query := `INSERT INTO email_otps (user_key, hmac_digest, expires_at, resend_after, attempts, consumed, created_at, updated_at)
	          VALUES (?, ?, ?, ?, 0, 0, ?, ?)
	          ON CONFLICT(user_key) DO UPDATE SET
	              hmac_digest = excluded.hmac_digest,
	              expires_at = excluded.expires_at,
	              resend_after = excluded.resend_after,
	              attempts = 0,
	              consumed = 0,
	              updated_at = excluded.updated_at`

	_, err := s.db.ExecContext(ctx, query, userKey, hmacDigest, expiresAt, resendAfter, now, now)
	return err
}

func (s *SQLiteStorage) CheckEmailOTPResend(ctx context.Context, userKey string) (time.Duration, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := `SELECT resend_after FROM email_otps WHERE user_key = ? LIMIT 1`
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

func (s *SQLiteStorage) VerifyAndConsumeEmailOTP(ctx context.Context, userKey string, code string, pepper string, maxAttempts int) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return false, fmt.Errorf("begin verify tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	query := `SELECT hmac_digest, expires_at, attempts, consumed FROM email_otps WHERE user_key = ? LIMIT 1`
	var storedDigest []byte
	var expiresAt time.Time
	var attempts int
	var consumed int

	err = tx.QueryRowContext(ctx, query, userKey).Scan(&storedDigest, &expiresAt, &attempts, &consumed)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, ErrNotFound
		}
		return false, fmt.Errorf("querying email otp: %w", err)
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
		_, _ = tx.ExecContext(ctx, `UPDATE email_otps SET attempts = attempts + 1, updated_at = ? WHERE user_key = ?`, now, userKey)
		_ = tx.Commit()
		return false, ErrInvalidCode
	}

	// 5. Successful match: Atomically mark consumed
	_, err = tx.ExecContext(ctx, `UPDATE email_otps SET consumed = 1, updated_at = ? WHERE user_key = ?`, now, userKey)
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
		INSERT INTO authorized_users (username, email, full_name, source, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(username) DO UPDATE SET
			email = CASE WHEN excluded.email != '' THEN excluded.email ELSE authorized_users.email END,
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
		if _, err := stmt.ExecContext(ctx, uname, strings.TrimSpace(u.Email), strings.TrimSpace(u.FullName), source, now, now); err != nil {
			return err
		}
	}

	return tx.Commit()
}

// ListAuthorizedUsers retrieves all authorized users from the database.
func (s *SQLiteStorage) ListAuthorizedUsers(ctx context.Context) ([]AuthorizedUser, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, username, COALESCE(email, ''), COALESCE(full_name, ''), source, created_at, updated_at FROM authorized_users ORDER BY username ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []AuthorizedUser
	for rows.Next() {
		var u AuthorizedUser
		if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.FullName, &u.Source, &u.CreatedAt, &u.UpdatedAt); err != nil {
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
		INSERT INTO authorized_users (username, email, full_name, source, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(username) DO UPDATE SET
			email = excluded.email,
			full_name = excluded.full_name,
			source = excluded.source,
			updated_at = excluded.updated_at
	`
	_, err := s.db.ExecContext(ctx, query, uname, strings.TrimSpace(user.Email), strings.TrimSpace(user.FullName), source, now, now)
	return err
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
