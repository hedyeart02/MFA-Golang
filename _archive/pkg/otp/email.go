package otp

import (
	"fmt"
	"sync"
	"time"

	"github.com/hidayat-SE/samlguard/pkg/utils"
)

// OTPSender is the interface for delivering OTP codes to users.
// Implementations can use email, SMS, or logging for development.
type OTPSender interface {
	Send(recipient, code string) error
	Method() string
}

// EmailOTPService handles email-based OTP generation and delivery.
type EmailOTPService struct {
	sender   OTPSender
	length   int
	expiry   time.Duration
	codes    map[string]otpRecord
	mu       sync.RWMutex
}

// otpRecord stores a generated OTP with its expiration.
type otpRecord struct {
	code      string
	expiresAt time.Time
	attempts  int
}

// NewEmailOTPService creates an email OTP service.
func NewEmailOTPService(sender OTPSender, length int, expiry time.Duration) *EmailOTPService {
	svc := &EmailOTPService{
		sender: sender,
		length: length,
		expiry: expiry,
		codes:  make(map[string]otpRecord),
	}

	go svc.cleanupExpired()

	return svc
}

// Generate creates and sends a new OTP code to the recipient.
func (s *EmailOTPService) Generate(userID, recipient string) error {
	code, err := utils.GenerateNumericCode(s.length)
	if err != nil {
		return fmt.Errorf("generating OTP code: %w", err)
	}

	s.mu.Lock()
	s.codes[userID] = otpRecord{
		code:      code,
		expiresAt: time.Now().Add(s.expiry),
		attempts:  0,
	}
	s.mu.Unlock()

	if err := s.sender.Send(recipient, code); err != nil {
		return fmt.Errorf("sending OTP to %s: %w", recipient, err)
	}

	return nil
}

// Validate checks if the provided code matches the stored OTP.
func (s *EmailOTPService) Validate(userID, code string, maxAttempts int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	record, exists := s.codes[userID]
	if !exists {
		return fmt.Errorf("no OTP found for user")
	}

	if time.Now().After(record.expiresAt) {
		delete(s.codes, userID)
		return fmt.Errorf("OTP has expired")
	}

	record.attempts++
	if record.attempts > maxAttempts {
		delete(s.codes, userID)
		return fmt.Errorf("maximum attempts exceeded")
	}

	s.codes[userID] = record

	if record.code != code {
		return fmt.Errorf("invalid OTP code")
	}

	delete(s.codes, userID)
	return nil
}

// Invalidate removes the OTP for the given user.
func (s *EmailOTPService) Invalidate(userID string) {
	s.mu.Lock()
	delete(s.codes, userID)
	s.mu.Unlock()
}

// cleanupExpired periodically removes expired OTP records.
func (s *EmailOTPService) cleanupExpired() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for id, record := range s.codes {
			if now.After(record.expiresAt) {
				delete(s.codes, id)
			}
		}
		s.mu.Unlock()
	}
}
