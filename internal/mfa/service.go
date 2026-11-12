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
	storage         Storage
	smtpSender      *SMTPSender
	smsSender       *SMSSender
	cfg             *config.Config
	logger          *zap.Logger
	ephemeralEncKey []byte
	ephemeralPepper []byte
}

type EnrollmentData struct {
	UserKey         string
	SecretKey       string
	ProvisioningURI string
	QRCodeDataURI   string
}

func NewService(storage Storage, smtpSender *SMTPSender, cfg *config.Config, logger *zap.Logger) *Service {
	var env string
	var smsCfg config.SMSConfig
	if cfg != nil {
		env = cfg.Env
		smsCfg = cfg.SMS
	}
	svc := &Service{
		storage:    storage,
		smtpSender: smtpSender,
		smsSender:  NewSMSSender(smsCfg, env, logger),
		cfg:        cfg,
		logger:     logger,
	}

	isProd := cfg != nil && cfg.IsProduction()
	if !isProd {
		if cfg == nil || strings.TrimSpace(cfg.MFA.EncryptionKey) == "" {
			key := make([]byte, 32)
			if _, err := io.ReadFull(rand.Reader, key); err == nil {
				svc.ephemeralEncKey = key
				if logger != nil {
					logger.Warn("mfa.encryption_key is not configured; generated ephemeral development encryption key (not persisted across restarts)")
				}
			}
		}
		if cfg == nil || strings.TrimSpace(cfg.MFA.ServerPepper) == "" {
			pepper := make([]byte, 32)
			if _, err := io.ReadFull(rand.Reader, pepper); err == nil {
				svc.ephemeralPepper = pepper
			}
		}
	}

	return svc
}

// SMTPSender returns the active SMTPSender instance.
func (s *Service) SMTPSender() *SMTPSender {
	return s.smtpSender
}

// UpdateSMTPSender safely swaps the active SMTPSender.
func (s *Service) UpdateSMTPSender(sender *SMTPSender) {
	s.smtpSender = sender
}

// SMSSender returns the active SMSSender instance.
func (s *Service) SMSSender() *SMSSender {
	return s.smsSender
}

// UpdateSMSSender safely swaps the active SMSSender.
func (s *Service) UpdateSMSSender(sender *SMSSender) {
	s.smsSender = sender
}

// Storage returns the underlying Storage instance.
func (s *Service) Storage() Storage {
	return s.storage
}

// IsUserAuthorized checks whether an identifier (username or email) is authorized to log in.
func (s *Service) IsUserAuthorized(ctx context.Context, identifier string) (bool, error) {
	if s.cfg != nil && !s.cfg.ITA.EnforceUserWhitelist {
		return true, nil // Whitelist enforcement disabled
	}

	// 1. Check database authorized users table (synced from ITA or added manually)
	if s.storage != nil {
		authorized, err := s.storage.IsUserAuthorized(ctx, identifier)
		if err == nil && authorized {
			return true, nil
		}
	}

	// 2. Check config manual fallback list
	if s.cfg != nil {
		normalized := strings.ToLower(strings.TrimSpace(identifier))
		for _, u := range s.cfg.ITA.ManualAllowedUsers {
			if strings.ToLower(strings.TrimSpace(u)) == normalized {
				return true, nil
			}
		}
		// Also check prefix if identifier is an email (e.g. itaadmin@samlguard.local -> itaadmin)
		if atIdx := strings.Index(normalized, "@"); atIdx > 0 {
			prefix := normalized[:atIdx]
			for _, u := range s.cfg.ITA.ManualAllowedUsers {
				if strings.ToLower(strings.TrimSpace(u)) == prefix {
					return true, nil
				}
			}
		}
	}

	return false, nil
}

// TestEmail sends a test email using either provided parameters or active settings.
func (s *Service) TestEmail(ctx context.Context, host string, port int, username, password, from, fromName, encryption, recipient string) error {
	if host == "" {
		host = s.cfg.SMTP.Host
	}
	if port <= 0 {
		port = s.cfg.SMTP.Port
	}
	if username == "" {
		username = s.cfg.SMTP.Username
	}
	if password == "" && host == s.cfg.SMTP.Host && username == s.cfg.SMTP.Username {
		password = s.cfg.SMTP.Password
	}
	if from == "" {
		from = s.cfg.SMTP.From
	}
	if fromName == "" {
		fromName = s.cfg.SMTP.FromName
	}
	if encryption == "" {
		encryption = s.cfg.SMTP.Encryption
	}

	sender := NewSMTPSender(host, port, username, password, from, fromName, encryption, s.logger)
	return sender.SendTestEmail(ctx, recipient)
}

// TestSMS sends a diagnostic test SMS using either provided parameters or active settings.
func (s *Service) TestSMS(ctx context.Context, smsCfg config.SMSConfig, recipient string) error {
	if smsCfg.Provider == "" && s.cfg != nil {
		smsCfg.Provider = s.cfg.SMS.Provider
	}
	if smsCfg.AuthToken == "" && s.cfg != nil {
		prov := smsCfg.EffectiveProvider()
		if prof := s.cfg.SMS.ProfileForProvider(prov); prof.AuthToken != "" {
			smsCfg.AuthToken = prof.AuthToken
		} else if prov == s.cfg.SMS.EffectiveProvider() {
			smsCfg.AuthToken = s.cfg.SMS.AuthToken
		}
	}
	if smsCfg.MessageTemplate == "" && s.cfg != nil {
		smsCfg.MessageTemplate = s.cfg.SMS.MessageTemplate
	}
	env := ""
	if s.cfg != nil {
		env = s.cfg.Env
	}
	sender := NewSMSSender(smsCfg, env, s.logger)
	return sender.SendTestSMS(ctx, recipient)
}

// LookupUserPhone finds a registered phone number for any of the given identifiers from authorized_users.
func (s *Service) LookupUserPhone(ctx context.Context, identifiers ...string) string {
	if s.storage == nil {
		return ""
	}
	phone, err := s.storage.LookupAuthorizedUserPhone(ctx, identifiers...)
	if err != nil {
		return ""
	}
	return phone
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

// --- Email & SMS OTP Implementation ---

func (s *Service) generateAndDispatchOTP(
	ctx context.Context,
	userKey string,
	checkResend func(context.Context, string) (time.Duration, error),
	saveOTP func(context.Context, string, []byte, time.Time, time.Time) error,
	dispatch func(string) error,
) error {
	if remaining, err := checkResend(ctx, userKey); err != nil && errors.Is(err, ErrCooldownActive) {
		return fmt.Errorf("%w: wait %d seconds before requesting a new code", ErrCooldownActive, int(remaining.Seconds()))
	}

	code, err := generateSecureNumericOTP(6)
	if err != nil {
		return fmt.Errorf("generating secure otp: %w", err)
	}

	pepper, err := s.getServerPepper()
	if err != nil {
		return err
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
	if err := saveOTP(ctx, userKey, digest, now.Add(expiry), now.Add(cooldown)); err != nil {
		return fmt.Errorf("persisting otp: %w", err)
	}

	return dispatch(code)
}

func (s *Service) verifyChallengeOTP(ctx context.Context, userKey, code string, verifyFn func(context.Context, string, string, string, int) (bool, error)) (bool, error) {
	if bypass, err := s.CheckDummyOTP(code); bypass || err != nil {
		return bypass, err
	}

	pepper, err := s.getServerPepper()
	if err != nil {
		return false, err
	}

	maxRetries := s.cfg.MFA.MaxRetries
	if maxRetries <= 0 {
		maxRetries = 5
	}

	return verifyFn(ctx, userKey, code, pepper, maxRetries)
}

// GenerateAndSendEmailOTP creates a secure random OTP and dispatches it via SMTP
func (s *Service) GenerateAndSendEmailOTP(ctx context.Context, userKey, recipientEmail string) error {
	if recipientEmail == "" {
		return errors.New("recipient email is required")
	}
	return s.generateAndDispatchOTP(
		ctx,
		userKey,
		s.storage.CheckEmailOTPResend,
		s.storage.SaveEmailOTP,
		func(code string) error {
			if err := s.smtpSender.Send(ctx, recipientEmail, code); err != nil {
				return fmt.Errorf("smtp delivery failed: %w", err)
			}
			return nil
		},
	)
}

// VerifyEmailOTP validates an email OTP atomically
func (s *Service) VerifyEmailOTP(ctx context.Context, userKey, code string) (bool, error) {
	return s.verifyChallengeOTP(ctx, userKey, code, s.storage.VerifyAndConsumeEmailOTP)
}

// GenerateAndSendSMSOTP creates a secure random OTP and dispatches it via the active SMS gateway
func (s *Service) GenerateAndSendSMSOTP(ctx context.Context, userKey, recipientPhone string) error {
	normPhone := NormalizePhoneNumber(recipientPhone)
	if normPhone == "" {
		return errors.New("no mobile phone number is registered for this account")
	}
	return s.generateAndDispatchOTP(
		ctx,
		userKey,
		s.storage.CheckSMSOTPResend,
		s.storage.SaveSMSOTP,
		func(code string) error {
			if err := s.smsSender.Send(ctx, normPhone, code); err != nil {
				return fmt.Errorf("sms delivery failed: %w", err)
			}
			return nil
		},
	)
}

// VerifySMSOTP validates an SMS OTP atomically
func (s *Service) VerifySMSOTP(ctx context.Context, userKey, code string) (bool, error) {
	return s.verifyChallengeOTP(ctx, userKey, code, s.storage.VerifyAndConsumeSMSOTP)
}

func (s *Service) getServerPepper() (string, error) {
	if s.cfg != nil {
		if pepper := strings.TrimSpace(s.cfg.MFA.ServerPepper); pepper != "" {
			return pepper, nil
		}
		if s.cfg.IsProduction() {
			return "", errors.New("production security violation: mfa.server_pepper must be configured")
		}
	}
	if len(s.ephemeralPepper) > 0 {
		return hex.EncodeToString(s.ephemeralPepper), nil
	}
	return "", errors.New("mfa server pepper is not initialized")
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
	if s.cfg != nil {
		hexKey := strings.TrimSpace(s.cfg.MFA.EncryptionKey)
		if hexKey != "" {
			if b, err := hex.DecodeString(hexKey); err == nil && len(b) == 32 {
				return b, nil
			}
			return nil, errors.New("invalid mfa.encryption_key: must be a 64-character hex string")
		}
		if s.cfg.IsProduction() {
			return nil, errors.New("production security violation: mfa.encryption_key must be configured with a 32-byte hex key")
		}
	}
	if len(s.ephemeralEncKey) == 32 {
		return s.ephemeralEncKey, nil
	}
	return nil, errors.New("mfa encryption key is not initialized")
}
