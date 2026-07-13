// Package otp provides TOTP, Email OTP, SMS OTP, and backup code
// functionality for multi-factor authentication.
package otp

import (
	"fmt"
	"time"

	"github.com/pquerna/otp/totp"
)

// TOTPService handles Time-based One-Time Password operations.
type TOTPService struct {
	issuer string
	skew   uint
}

// NewTOTPService creates a TOTP service with the given issuer name and time skew.
func NewTOTPService(issuer string, skew uint) *TOTPService {
	return &TOTPService{
		issuer: issuer,
		skew:   skew,
	}
}

// GenerateKey creates a new TOTP secret for the given account.
// Returns the secret key and the provisioning URI for QR code generation.
func (s *TOTPService) GenerateKey(accountName string) (secret string, provisioningURI string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      s.issuer,
		AccountName: accountName,
		Period:      30,
		Digits:      6,
		Algorithm:   0, // SHA1 (default, most compatible)
	})
	if err != nil {
		return "", "", fmt.Errorf("generating TOTP key: %w", err)
	}

	return key.Secret(), key.URL(), nil
}

// Validate checks if the provided TOTP code is valid for the given secret.
func (s *TOTPService) Validate(code, secret string) bool {
	valid, err := totp.ValidateCustom(code, secret, time.Now(), totp.ValidateOpts{
		Period: 30,
		Skew:   s.skew,
		Digits: 6,
	})
	if err != nil {
		return false
	}
	return valid
}
