package utils

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

var (
	emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	otpRegex   = regexp.MustCompile(`^\d{6,10}$`)
)

// ValidateEmail checks if the provided string is a valid email format.
func ValidateEmail(email string) error {
	if email == "" {
		return fmt.Errorf("email is required")
	}
	if len(email) > 254 {
		return fmt.Errorf("email exceeds maximum length of 254 characters")
	}
	if !emailRegex.MatchString(email) {
		return fmt.Errorf("invalid email format")
	}
	return nil
}

// ValidateURL checks if the provided string is a valid absolute URL.
func ValidateURL(rawURL string) error {
	if rawURL == "" {
		return fmt.Errorf("URL is required")
	}
	parsed, err := url.ParseRequestURI(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL format: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("URL must include scheme and host")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("URL scheme must be http or https")
	}
	return nil
}

// ValidateUUID checks if the provided string is a valid UUID v4.
func ValidateUUID(id string) error {
	if id == "" {
		return fmt.Errorf("UUID is required")
	}
	if _, err := uuid.Parse(id); err != nil {
		return fmt.Errorf("invalid UUID format: %w", err)
	}
	return nil
}

// ValidateOTP checks if the provided string is a valid numeric OTP code.
func ValidateOTP(code string) error {
	if code == "" {
		return fmt.Errorf("verification code is required")
	}
	if !otpRegex.MatchString(code) {
		return fmt.Errorf("verification code must be 6-10 digits")
	}
	return nil
}

// ValidateStringLength checks that a string falls within the specified bounds.
func ValidateStringLength(field, value string, min, max int) error {
	length := len(strings.TrimSpace(value))
	if length < min {
		return fmt.Errorf("%s must be at least %d characters", field, min)
	}
	if length > max {
		return fmt.Errorf("%s must not exceed %d characters", field, max)
	}
	return nil
}

// ValidateRequired checks that a string field is not empty.
func ValidateRequired(field, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s is required", field)
	}
	return nil
}

// ValidateMFAMethod checks that the MFA method is supported.
func ValidateMFAMethod(method string) error {
	switch method {
	case "totp", "email", "sms", "backup":
		return nil
	default:
		return fmt.Errorf("unsupported MFA method: %s (allowed: totp, email, sms, backup)", method)
	}
}

// ValidateSeverity checks that the severity level is valid.
func ValidateSeverity(severity string) error {
	switch severity {
	case "info", "warn", "error":
		return nil
	default:
		return fmt.Errorf("invalid severity: %s (allowed: info, warn, error)", severity)
	}
}
