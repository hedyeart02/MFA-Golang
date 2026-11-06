package mfa

import (
	"context"
	"encoding/base32"
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
