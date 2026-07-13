package utils

import (
	"fmt"
	"net/http"
)

// AppError represents an application-level error with HTTP status mapping.
type AppError struct {
	StatusCode int
	Code       string
	Message    string
	Err        error
}

// Error implements the error interface.
func (e *AppError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap returns the underlying error for errors.Is/errors.As support.
func (e *AppError) Unwrap() error {
	return e.Err
}

// NewBadRequest creates a 400 Bad Request error.
func NewBadRequest(code, message string) *AppError {
	return &AppError{
		StatusCode: http.StatusBadRequest,
		Code:       code,
		Message:    message,
	}
}

// NewUnauthorized creates a 401 Unauthorized error.
func NewUnauthorized(code, message string) *AppError {
	return &AppError{
		StatusCode: http.StatusUnauthorized,
		Code:       code,
		Message:    message,
	}
}

// NewForbidden creates a 403 Forbidden error.
func NewForbidden(code, message string) *AppError {
	return &AppError{
		StatusCode: http.StatusForbidden,
		Code:       code,
		Message:    message,
	}
}

// NewNotFound creates a 404 Not Found error.
func NewNotFound(code, message string) *AppError {
	return &AppError{
		StatusCode: http.StatusNotFound,
		Code:       code,
		Message:    message,
	}
}

// NewConflict creates a 409 Conflict error.
func NewConflict(code, message string) *AppError {
	return &AppError{
		StatusCode: http.StatusConflict,
		Code:       code,
		Message:    message,
	}
}

// NewTooManyRequests creates a 429 Too Many Requests error.
func NewTooManyRequests(code, message string) *AppError {
	return &AppError{
		StatusCode: http.StatusTooManyRequests,
		Code:       code,
		Message:    message,
	}
}

// NewInternalError creates a 500 Internal Server Error.
func NewInternalError(code, message string, err error) *AppError {
	return &AppError{
		StatusCode: http.StatusInternalServerError,
		Code:       code,
		Message:    message,
		Err:        err,
	}
}

// Wrap wraps an existing error with additional context.
func Wrap(err error, code, message string) *AppError {
	return &AppError{
		StatusCode: http.StatusInternalServerError,
		Code:       code,
		Message:    message,
		Err:        err,
	}
}

// Sentinel errors for common conditions.
var (
	ErrUserNotFound      = NewNotFound("USER_NOT_FOUND", "User not found")
	ErrSessionNotFound   = NewNotFound("SESSION_NOT_FOUND", "Session not found")
	ErrSessionExpired    = NewUnauthorized("SESSION_EXPIRED", "Session has expired")
	ErrSessionRevoked    = NewUnauthorized("SESSION_REVOKED", "Session has been revoked")
	ErrInvalidToken      = NewUnauthorized("INVALID_TOKEN", "Invalid or expired token")
	ErrInvalidOTP        = NewBadRequest("INVALID_OTP", "Invalid verification code")
	ErrOTPExpired        = NewBadRequest("OTP_EXPIRED", "Verification code has expired")
	ErrMFANotEnabled     = NewBadRequest("MFA_NOT_ENABLED", "MFA is not enabled for this user")
	ErrMFAAlreadyEnabled = NewConflict("MFA_ALREADY_ENABLED", "MFA is already enabled")
	ErrMaxRetries        = NewTooManyRequests("MAX_RETRIES", "Maximum verification attempts exceeded")
	ErrRateLimited       = NewTooManyRequests("RATE_LIMITED", "Too many requests, please try again later")
	ErrSAMLValidation    = NewBadRequest("SAML_VALIDATION_FAILED", "SAML assertion validation failed")
	ErrSAMLSignature     = NewBadRequest("SAML_SIGNATURE_INVALID", "SAML assertion signature is invalid")
	ErrSAMLExpired       = NewBadRequest("SAML_ASSERTION_EXPIRED", "SAML assertion has expired")
	ErrSAMLReplay        = NewBadRequest("SAML_REPLAY_DETECTED", "SAML assertion replay detected")
	ErrSAMLUnsigned      = NewBadRequest("SAML_UNSIGNED", "SAML assertion must be signed")
)
