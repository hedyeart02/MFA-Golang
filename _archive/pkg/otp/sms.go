package otp

import "time"

// SMSOTPService handles SMS-based OTP generation and delivery.
// It reuses the same core logic as EmailOTPService with an SMS sender.
type SMSOTPService struct {
	inner *EmailOTPService
}

// NewSMSOTPService creates an SMS OTP service with the given sender.
func NewSMSOTPService(sender OTPSender, length int, expiry time.Duration) *SMSOTPService {
	return &SMSOTPService{
		inner: NewEmailOTPService(sender, length, expiry),
	}
}

// Generate creates and sends a new OTP code via SMS.
func (s *SMSOTPService) Generate(userID, phoneNumber string) error {
	return s.inner.Generate(userID, phoneNumber)
}

// Validate checks if the provided code matches the stored OTP.
func (s *SMSOTPService) Validate(userID, code string, maxAttempts int) error {
	return s.inner.Validate(userID, code, maxAttempts)
}

// Invalidate removes the OTP for the given user.
func (s *SMSOTPService) Invalidate(userID string) {
	s.inner.Invalidate(userID)
}
