package errors

type ErrorCode string

const (
	// Auth
	ErrAuthFailed   ErrorCode = "AUTH-1000"
	ErrAuthExpired  ErrorCode = "AUTH-1001"
	
	// MFA
	ErrMFAInvalid   ErrorCode = "MFA-2000"
	ErrMFAExpired   ErrorCode = "MFA-2001"
	
	// SAML
	ErrInvalidAssertion ErrorCode = "SAML-3000"
	ErrReplayAttack     ErrorCode = "SAML-3001"
	ErrInvalidSignature ErrorCode = "SAML-3002"
	ErrClockSkew        ErrorCode = "SAML-3003"
	
	// Certificate
	ErrCertExpired ErrorCode = "CERT-4000"
	ErrCertInvalid ErrorCode = "CERT-4001"
	
	// Session
	ErrSessionInvalid ErrorCode = "SESSION-5000"
	ErrSessionExpired ErrorCode = "SESSION-5001"
	
	// Audit
	ErrAuditFailed ErrorCode = "AUDIT-6000"
)

type AppError struct {
	Code    ErrorCode
	Message string
	Err     error
}

func (e *AppError) Error() string {
	if e.Err != nil {
		return string(e.Code) + ": " + e.Message + " - " + e.Err.Error()
	}
	return string(e.Code) + ": " + e.Message
}
