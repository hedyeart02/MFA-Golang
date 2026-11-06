package mfa

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/hidayat-SE/samlguard/internal/config"
	"go.uber.org/zap"
)

type Service struct {
	storage    Storage
	smtpSender *SMTPSender
	cfg        *config.Config
	logger     *zap.Logger
}

type EnrollmentData struct {
	UserKey         string
	SecretKey       string
	ProvisioningURI string
	QRCodeDataURI   string
}

func NewService(storage Storage, smtpSender *SMTPSender, cfg *config.Config, logger *zap.Logger) *Service {
	return &Service{
		storage:    storage,
		smtpSender: smtpSender,
		cfg:        cfg,
		logger:     logger,
	}
}

// CheckDummyOTP validates if the dummy OTP 000000 was supplied.
func (s *Service) CheckDummyOTP(code string) (bool, error) {
	if code != "000000" {
		return false, nil
	}

	// Strictly reject in production mode
	if s.cfg.IsProduction() {
		if s.logger != nil {
			s.logger.Error("security alert: dummy OTP (000000) rejected in production mode")
		}
		return false, errors.New("dummy OTP is forbidden in production mode")
	}

	if !s.cfg.MFA.AllowDummyOTP {
		return false, errors.New("dummy OTP is disabled")
	}

	if s.logger != nil {
		s.logger.Info("dummy OTP (000000) accepted for development testing")
	}
	return true, nil
}

// --- TOTP Implementation ---

// StartTOTPEnrollment initiates enrollment or re-enrollment without overwriting any active secret.
// If a pending enrollment already exists for the user, it reuses the pending secret to preserve scanning.
func (s *Service) StartTOTPEnrollment(ctx context.Context, userKey, accountName string) (*EnrollmentData, error) {
	var base32Secret string

	// Check if a pending secret already exists for this user to preserve across failed attempts
	if existingPending, err := s.storage.GetPendingTOTPSecret(ctx, userKey); err == nil && existingPending != nil {
		if decrypted, err := s.decrypt(existingPending.SecretEncrypted); err == nil && len(decrypted) > 0 {
			base32Secret = string(decrypted)
		}
	}

	if base32Secret == "" {
		return s.StartTOTPEnrollmentForce(ctx, userKey, accountName)
	}

	issuer := s.cfg.MFA.Issuer
	if issuer == "" {
		issuer = "SAMLGuard"
	}
	uri := BuildProvisioningURI(issuer, accountName, base32Secret)
	qrDataURI, err := GenerateQRCodePNGDataURI(uri, 200)
	if err != nil {
		return nil, fmt.Errorf("generating qr data uri: %w", err)
	}

	return &EnrollmentData{
		UserKey:         userKey,
		SecretKey:       base32Secret,
		ProvisioningURI: uri,
		QRCodeDataURI:   qrDataURI,
	}, nil
}

// StartTOTPEnrollmentForce generates a fresh pending secret, overwriting any previous pending secret (F-09)
func (s *Service) StartTOTPEnrollmentForce(ctx context.Context, userKey, accountName string) (*EnrollmentData, error) {
	secretBytes := make([]byte, 20)
	if _, err := io.ReadFull(rand.Reader, secretBytes); err != nil {
		return nil, fmt.Errorf("generating totp random bytes: %w", err)
	}

	base32Secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secretBytes)

	// Encrypt secret at rest
	encrypted, err := s.encrypt([]byte(base32Secret))
	if err != nil {
		return nil, fmt.Errorf("encrypting totp secret: %w", err)
	}

	sec := &MFASecret{
		ID:              uuid.New().String(),
		UserKey:         userKey,
		Method:          "totp",
		Status:          "pending",
		SecretEncrypted: encrypted,
	}

	if err := s.storage.SavePendingTOTPSecret(ctx, sec); err != nil {
		return nil, fmt.Errorf("saving pending totp secret: %w", err)
	}

	issuer := s.cfg.MFA.Issuer
	if issuer == "" {
		issuer = "SAMLGuard"
	}
	uri := BuildProvisioningURI(issuer, accountName, base32Secret)
	qrDataURI, err := GenerateQRCodePNGDataURI(uri, 200)
	if err != nil {
		return nil, fmt.Errorf("generating qr data uri: %w", err)
	}

	return &EnrollmentData{
		UserKey:         userKey,
		SecretKey:       base32Secret,
		ProvisioningURI: uri,
		QRCodeDataURI:   qrDataURI,
	}, nil
}

// VerifyAndActivatePendingTOTP confirms initial setup and atomically promotes pending to active
func (s *Service) VerifyAndActivatePendingTOTP(ctx context.Context, userKey, code string) (bool, error) {
	if bypass, err := s.CheckDummyOTP(code); bypass || err != nil {
		if bypass {
			currentTimestep := time.Now().Unix() / 30
			_ = s.storage.ActivateTOTPSecret(ctx, userKey, currentTimestep)
			return true, nil
		}
		return false, err
	}

	pending, err := s.storage.GetPendingTOTPSecret(ctx, userKey)
	if err != nil {
		return false, err
	}

	// Check if account is temporarily locked
	if pending.LockedUntil != nil && time.Now().UTC().Before(*pending.LockedUntil) {
		return false, ErrAccountLocked
	}

	decrypted, err := s.decrypt(pending.SecretEncrypted)
	if err != nil {
		return false, fmt.Errorf("decrypting pending secret: %w", err)
	}

	valid, timestep := s.validateRFC6238TOTP(code, string(decrypted), s.cfg.MFA.TOTPSkew)
	if !valid {
		locked, _ := s.storage.IncrementTOTPFailure(ctx, userKey, 5, 5*time.Minute)
		if locked {
			return false, ErrAccountLocked
		}
		return false, ErrInvalidCode
	}

	// Atomically activate and record initial timestep
	if err := s.storage.ActivateTOTPSecret(ctx, userKey, timestep); err != nil {
		return false, fmt.Errorf("activating totp secret: %w", err)
	}

	_ = s.storage.ResetTOTPFailure(ctx, userKey)
	return true, nil
}

// VerifyTOTP verifies a standard login code against the active secret and enforces database replay protection
func (s *Service) VerifyTOTP(ctx context.Context, userKey, code string) (bool, error) {
	if bypass, err := s.CheckDummyOTP(code); bypass || err != nil {
		return bypass, err
	}

	active, err := s.storage.GetActiveTOTPSecret(ctx, userKey)
	if err != nil {
		return false, err
	}

	// Check if account is temporarily locked (F-08)
	if active.LockedUntil != nil && time.Now().UTC().Before(*active.LockedUntil) {
		return false, ErrAccountLocked
	}

	decrypted, err := s.decrypt(active.SecretEncrypted)
	if err != nil {
		return false, fmt.Errorf("decrypting active secret: %w", err)
	}

	valid, timestep := s.validateRFC6238TOTP(code, string(decrypted), s.cfg.MFA.TOTPSkew)
	if !valid {
		locked, _ := s.storage.IncrementTOTPFailure(ctx, userKey, 5, 5*time.Minute)
		if locked {
			return false, ErrAccountLocked
		}
		return false, ErrInvalidCode
	}

	// Replay protection: ensure timestep > last_accepted_timestep
	if timestep <= active.LastAcceptedTimestep {
		_, _ = s.storage.IncrementTOTPFailure(ctx, userKey, 5, 5*time.Minute)
		return false, ErrTimestepReplayed
	}

	// Atomically record new accepted timestep
	if err := s.storage.RecordTOTPTimestep(ctx, userKey, timestep); err != nil {
		return false, err
	}

	_ = s.storage.ResetTOTPFailure(ctx, userKey)
	return true, nil
}

// HasActiveTOTP checks if the user has an existing verified TOTP enrollment
func (s *Service) HasActiveTOTP(ctx context.Context, userKey string) bool {
	sec, err := s.storage.GetActiveTOTPSecret(ctx, userKey)
	return err == nil && sec != nil
}

// RFC 6238 TOTP computation
func (s *Service) validateRFC6238TOTP(code, base32Secret string, skew uint) (bool, int64) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(base32Secret)))
	if err != nil {
		return false, 0
	}

	now := time.Now().Unix()
	currentTimestep := now / 30

	intSkew := int64(skew)
	for t := currentTimestep - intSkew; t <= currentTimestep+intSkew; t++ {
		expected := generateHOTP(key, uint64(t))
		if subtle.ConstantTimeCompare([]byte(code), []byte(expected)) == 1 {
			return true, t
		}
	}

	return false, 0
}

func generateHOTP(secret []byte, counter uint64) string {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)

	mac := hmac.New(sha1.New, secret)
	mac.Write(buf)
	h := mac.Sum(nil)

	offset := h[len(h)-1] & 0x0f
	binaryCode := ((int(h[offset]) & 0x7f) << 24) |
		((int(h[offset+1]) & 0xff) << 16) |
		((int(h[offset+2]) & 0xff) << 8) |
		(int(h[offset+3]) & 0xff)

	otpCode := binaryCode % 1000000
	return fmt.Sprintf("%06d", otpCode)
}

// --- Email OTP Implementation ---

// GenerateAndSendEmailOTP creates a secure random OTP and dispatches it via SMTP
func (s *Service) GenerateAndSendEmailOTP(ctx context.Context, userKey, recipientEmail string) error {
	if recipientEmail == "" {
		return errors.New("recipient email is required")
	}

	// 1. Enforce resend cooldown
	remaining, err := s.storage.CheckEmailOTPResend(ctx, userKey)
	if err != nil && errors.Is(err, ErrCooldownActive) {
		return fmt.Errorf("%w: wait %d seconds before requesting a new code", ErrCooldownActive, int(remaining.Seconds()))
	}

	// 2. Cryptographically secure random 6-digit OTP
	code, err := generateSecureNumericOTP(6)
	if err != nil {
		return fmt.Errorf("generating secure otp: %w", err)
	}

	// 3. Digest code with HMAC-SHA256 using server pepper
	pepper := s.cfg.MFA.ServerPepper
	if pepper == "" {
		pepper = "samlguard-default-server-pepper-secret-key"
	}

	mac := hmac.New(sha256.New, []byte(pepper))
	mac.Write([]byte(code))
	digest := mac.Sum(nil)

	expiry := s.cfg.MFA.OTPExpiry
	if expiry <= 0 {
		expiry = 5 * time.Minute
	}
	cooldown := s.cfg.MFA.ResendCooldown
	if cooldown <= 0 {
		cooldown = 60 * time.Second
	}

	now := time.Now().UTC()
	expiresAt := now.Add(expiry)
	resendAfter := now.Add(cooldown)

	// 4. Save to database
	if err := s.storage.SaveEmailOTP(ctx, userKey, digest, expiresAt, resendAfter); err != nil {
		return fmt.Errorf("persisting email otp: %w", err)
	}

	// 5. Send via SMTP
	if err := s.smtpSender.Send(ctx, recipientEmail, code); err != nil {
		return fmt.Errorf("smtp delivery failed: %w", err)
	}

	return nil
}

// VerifyEmailOTP validates an email OTP atomically
func (s *Service) VerifyEmailOTP(ctx context.Context, userKey, code string) (bool, error) {
	if bypass, err := s.CheckDummyOTP(code); bypass || err != nil {
		return bypass, err
	}

	pepper := s.cfg.MFA.ServerPepper
	if pepper == "" {
		pepper = "samlguard-default-server-pepper-secret-key"
	}

	maxRetries := s.cfg.MFA.MaxRetries
	if maxRetries <= 0 {
		maxRetries = 5
	}

	return s.storage.VerifyAndConsumeEmailOTP(ctx, userKey, code, pepper, maxRetries)
}

func generateSecureNumericOTP(length int) (string, error) {
	if length <= 0 {
		length = 6
	}
	digits := "0123456789"
	var sb strings.Builder
	sb.Grow(length)

	max := big.NewInt(int64(len(digits)))
	for i := 0; i < length; i++ {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		sb.WriteByte(digits[n.Int64()])
	}
	return sb.String(), nil
}

// AES-256-GCM encryption helpers (F-04)
func (s *Service) encrypt(plaintext []byte) ([]byte, error) {
	keyBytes, err := s.getEncryptionKey()
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

func (s *Service) decrypt(ciphertext []byte) ([]byte, error) {
	keyBytes, err := s.getEncryptionKey()
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, encryptedData := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, encryptedData, nil)
}

func (s *Service) getEncryptionKey() ([]byte, error) {
	hexKey := strings.TrimSpace(s.cfg.MFA.EncryptionKey)
	if hexKey != "" {
		if b, err := hex.DecodeString(hexKey); err == nil && len(b) == 32 {
			return b, nil
		}
	}
	if s.cfg.IsProduction() {
		return nil, errors.New("production security violation: mfa.encryption_key must be configured with a 32-byte hex key")
	}
	// In non-production testing mode if key not provided: derive deterministic dev key
	devKey := sha256.Sum256([]byte("samlguard-development-only-encryption-key-not-for-production"))
	return devKey[:], nil
}
