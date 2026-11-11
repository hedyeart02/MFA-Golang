package mfa

import (
	"context"
	"database/sql"
	"encoding/base32"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hidayat-SE/samlguard/internal/config"
	"go.uber.org/zap"
)

func setupTestStorage(t *testing.T) Storage {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test_mfa.db")

	storage, err := NewSQLiteStorage(dbPath)
	if err != nil {
		t.Fatalf("failed to create test sqlite storage: %v", err)
	}
	t.Cleanup(func() {
		_ = storage.Close()
	})
	return storage
}

func setupTestService(t *testing.T, storage Storage, isProd, allowDummy bool) *Service {
	t.Helper()
	cfg := &config.Config{
		Env: "development",
		MFA: config.MFAConfig{
			Issuer:         "SAMLGuard",
			AllowDummyOTP:  allowDummy,
			OTPExpiry:      2 * time.Minute,
			ResendCooldown: 10 * time.Second,
			ServerPepper:   "test-pepper-secret-32-bytes-long",
			EncryptionKey:  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			TOTPSkew:       1,
			MaxRetries:     3,
		},
	}
	if isProd {
		cfg.Env = "production"
	}

	logger := zap.NewNop()
	smtpSender := NewSMTPSender("", 0, "", "", "", "", "", logger)
	return NewService(storage, smtpSender, cfg, logger)
}

func TestDummyOTPEnforcement(t *testing.T) {
	storage := setupTestStorage(t)

	// Case 1: Dev mode with allow_dummy_otp = true
	devSvc := setupTestService(t, storage, false, true)
	ok, err := devSvc.CheckDummyOTP("000000")
	if err != nil || !ok {
		t.Fatalf("expected dummy OTP to be accepted in dev mode with flag true, got ok=%v, err=%v", ok, err)
	}

	// Case 2: Dev mode with allow_dummy_otp = false
	devDisabledSvc := setupTestService(t, storage, false, false)
	ok, err = devDisabledSvc.CheckDummyOTP("000000")
	if ok || err == nil {
		t.Fatalf("expected dummy OTP to be rejected when allow_dummy_otp = false, got ok=%v, err=%v", ok, err)
	}

	// Case 3: Production mode with allow_dummy_otp = true (attempted bypass)
	prodSvc := setupTestService(t, storage, true, true)
	ok, err = prodSvc.CheckDummyOTP("000000")
	if ok || err == nil {
		t.Fatalf("expected dummy OTP to be strictly rejected in production mode, got ok=%v, err=%v", ok, err)
	}
}

func TestEmailOTPAtomicVerification(t *testing.T) {
	storage := setupTestStorage(t)
	svc := setupTestService(t, storage, false, false)
	ctx := context.Background()
	userKey := "https://idp.example.com|user-123"
	email := "user@example.com"

	// 1. Send OTP
	err := svc.GenerateAndSendEmailOTP(ctx, userKey, email)
	if err != nil {
		t.Fatalf("GenerateAndSendEmailOTP failed: %v", err)
	}

	// 2. Cooldown check - immediate resend must fail
	err = svc.GenerateAndSendEmailOTP(ctx, userKey, email)
	if err == nil {
		t.Fatal("expected resend cooldown to trigger, but succeeded")
	}

	// Read digest and test incorrect attempt incrementing without consuming
	query := `SELECT hmac_digest, attempts, consumed FROM email_otps WHERE user_key = ?`
	var (
		digest   []byte
		attempts int
		consumed int
	)
	_ = storage.(*SQLiteStorage).db.QueryRow(query, userKey).Scan(&digest, &attempts, &consumed)
	if consumed != 0 {
		t.Fatal("expected unconsumed OTP initially")
	}

	// 3. Submit wrong code
	valid, err := svc.VerifyEmailOTP(ctx, userKey, "999999")
	if valid || err == nil {
		t.Fatal("expected invalid code to fail verification")
	}

	// Verify attempt counter incremented and consumed is still 0
	_ = storage.(*SQLiteStorage).db.QueryRow(query, userKey).Scan(&digest, &attempts, &consumed)
	if attempts != 1 || consumed != 0 {
		t.Fatalf("expected attempts=1, consumed=0; got attempts=%d, consumed=%d", attempts, consumed)
	}
}

func TestTOTPPendingEnrollmentAndAtomicActivation(t *testing.T) {
	storage := setupTestStorage(t)
	svc := setupTestService(t, storage, false, false)
	ctx := context.Background()
	userKey := "https://idp.example.com|user-totp-456"

	// 1. Start enrollment
	enrollData, err := svc.StartTOTPEnrollment(ctx, userKey, "user@example.com")
	if err != nil {
		t.Fatalf("StartTOTPEnrollment failed: %v", err)
	}
	if enrollData.SecretKey == "" || enrollData.QRCodeDataURI == "" {
		t.Fatal("expected secret key and QR data URI to be populated")
	}

	// User should not yet have an active secret
	if svc.HasActiveTOTP(ctx, userKey) {
		t.Fatal("user should not have active TOTP before verification")
	}

	// 2. Generate valid TOTP code from secret
	validCode := generateHOTP(decodeBase32(enrollData.SecretKey), uint64(time.Now().Unix()/30))

	// 3. Verify and activate pending secret
	activated, err := svc.VerifyAndActivatePendingTOTP(ctx, userKey, validCode)
	if err != nil || !activated {
		t.Fatalf("VerifyAndActivatePendingTOTP failed: %v", err)
	}

	// User must now have active TOTP
	if !svc.HasActiveTOTP(ctx, userKey) {
		t.Fatal("user should now have active TOTP")
	}

	// 4. Test Replay Protection: Re-submitting the exact same code in the same window must fail!
	replayOk, err := svc.VerifyTOTP(ctx, userKey, validCode)
	if replayOk || err == nil {
		t.Fatal("expected TOTP replay to be rejected, but it succeeded")
	}
}

func decodeBase32(s string) []byte {
	b, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
	return b
}

func TestSQLiteStorage_AutoCreateParentDir(t *testing.T) {
	tempBase := t.TempDir()
	nestedDir := filepath.Join(tempBase, "sub", "nested", "data")
	dbPath := filepath.Join(nestedDir, "samlguard.db")

	storage, err := NewSQLiteStorage(dbPath)
	if err != nil {
		t.Fatalf("expected NewSQLiteStorage to auto-create nested directory, got error: %v", err)
	}
	defer storage.Close()

	if _, err := os.Stat(nestedDir); os.IsNotExist(err) {
		t.Fatalf("expected nested directory %q to be created", nestedDir)
	}
}

func TestLegacyMFADatabaseMigrationAndTOTPPreservation(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "legacy_mfa.db")

	// 1. Manually create legacy schema mimicking the 2024 microservices architecture
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed to open raw sqlite: %v", err)
	}

	legacySchema := `
	CREATE TABLE mfa_secrets (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		method TEXT NOT NULL,
		secret_encrypted BLOB,
		backup_codes_hash TEXT,
		retry_count INTEGER DEFAULT 0,
		last_retry_at DATETIME,
		verified BOOLEAN DEFAULT 1,
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL
	);
	CREATE INDEX idx_mfa_secrets_user_id ON mfa_secrets(user_id);
	`
	if _, err := db.Exec(legacySchema); err != nil {
		db.Close()
		t.Fatalf("failed to create legacy schema: %v", err)
	}

	cfg := &config.Config{
		Env: "development",
		MFA: config.MFAConfig{
			Issuer:         "SAMLGuard",
			AllowDummyOTP:  false,
			OTPExpiry:      2 * time.Minute,
			ResendCooldown: 10 * time.Second,
			ServerPepper:   "test-pepper-secret-32-bytes-long",
			EncryptionKey:  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			TOTPSkew:       1,
			MaxRetries:     3,
		},
	}
	logger := zap.NewNop()
	tempSvc := NewService(nil, nil, cfg, logger)

	// Encrypt a known TOTP secret using the service encryption key
	rawSecret := "JBSWY3DPEHPK3PXP" // standard test base32 secret
	encryptedSecret, err := tempSvc.encrypt([]byte(rawSecret))
	if err != nil {
		db.Close()
		t.Fatalf("failed to encrypt test secret: %v", err)
	}

	legacyUser := "https://idp.example.com|legacy-user-001"
	now := time.Now().UTC()
	insertQuery := `INSERT INTO mfa_secrets (id, user_id, method, secret_encrypted, backup_codes_hash, retry_count, last_retry_at, verified, created_at, updated_at)
	                VALUES (?, ?, 'totp', ?, '', 0, NULL, 1, ?, ?)`
	if _, err := db.Exec(insertQuery, "sec-legacy-1", legacyUser, encryptedSecret, now, now); err != nil {
		db.Close()
		t.Fatalf("failed to insert legacy record: %v", err)
	}
	db.Close()

	// 2. Open this legacy database with SAMLGuard NewSQLiteStorage
	// This must trigger automated schema migration without data loss
	storage, err := NewSQLiteStorage(dbPath)
	if err != nil {
		t.Fatalf("expected NewSQLiteStorage to migrate legacy schema successfully, got: %v", err)
	}
	defer storage.Close()

	// 3. Verify the migrated storage can read the active TOTP secret
	ctx := context.Background()
	activeSec, err := storage.GetActiveTOTPSecret(ctx, legacyUser)
	if err != nil {
		t.Fatalf("expected to find active TOTP secret for migrated legacy user, got: %v", err)
	}
	if activeSec.UserKey != legacyUser {
		t.Fatalf("expected user_key %q, got %q", legacyUser, activeSec.UserKey)
	}
	if activeSec.Status != "active" {
		t.Fatalf("expected status 'active', got %q", activeSec.Status)
	}

	// 4. Verify TOTP verification works seamlessly with the migrated secret
	svc := NewService(storage, NewSMTPSender("", 0, "", "", "", "", "", logger), cfg, logger)
	if !svc.HasActiveTOTP(ctx, legacyUser) {
		t.Fatal("expected svc.HasActiveTOTP to return true for migrated user")
	}

	validCode := generateHOTP(decodeBase32(rawSecret), uint64(time.Now().Unix()/30))
	ok, err := svc.VerifyTOTP(ctx, legacyUser, validCode)
	if err != nil || !ok {
		t.Fatalf("expected TOTP verification to succeed for migrated user, got ok=%v, err=%v", ok, err)
	}
}

func TestSQLiteStorage_AdminSettingsPersistence(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "settings.db")
	storage, err := NewSQLiteStorage(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteStorage failed: %v", err)
	}
	defer storage.Close()

	ctx := context.Background()
	if _, err := storage.GetAdminSettings(ctx); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound before saving settings, got %v", err)
	}

	first := &config.AdminSettingsPayload{
		EntityID:           "https://samlguard.local:8443",
		ACSURL:             "https://ita.local/callback",
		IdPEntityID:        "https://idp.local/realm",
		IdPSSOURL:          "https://idp.local/sso",
		MFADefaultProvider: "totp",
		SMTPHost:           "smtp1.local",
		SMTPPort:           587,
		SMTPPassword:       "secret1",
	}
	if err := storage.SaveAdminSettings(ctx, first); err != nil {
		t.Fatalf("SaveAdminSettings failed: %v", err)
	}

	second := &config.AdminSettingsPayload{
		EntityID:           "https://samlguard.local:18080",
		ACSURL:             "https://ita.local/api/current/authentication/saml2-callback",
		IdPEntityID:        "https://keycloak.local/realms/ita",
		IdPSSOURL:          "https://keycloak.local/realms/ita/protocol/saml",
		MFADefaultProvider: "email",
		SMTPHost:           "smtp2.local",
		SMTPPort:           2525,
		SMTPPassword:       "secret2",
		ITAEnforceWhitelist: true,
	}
	if err := storage.SaveAdminSettings(ctx, second); err != nil {
		t.Fatalf("SaveAdminSettings upsert failed: %v", err)
	}

	loaded, err := storage.GetAdminSettings(ctx)
	if err != nil {
		t.Fatalf("GetAdminSettings failed: %v", err)
	}
	if loaded.EntityID != second.EntityID || loaded.SMTPHost != "smtp2.local" || loaded.SMTPPassword != "secret2" || !loaded.ITAEnforceWhitelist {
		t.Fatalf("unexpected loaded settings: %+v", loaded)
	}
}
