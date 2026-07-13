package mfa

// EnrollRequest is the request to enroll a user in MFA.
type EnrollRequest struct {
	UserID string `json:"user_id" binding:"required"`
	Method string `json:"method" binding:"required"`
	Email  string `json:"email"`
	Phone  string `json:"phone"`
}

// EnrollResponse contains enrollment data (e.g., TOTP provisioning URI).
type EnrollResponse struct {
	Method         string   `json:"method"`
	ProvisioningURI string  `json:"provisioning_uri,omitempty"`
	BackupCodes    []string `json:"backup_codes,omitempty"`
	Message        string   `json:"message,omitempty"`
}

// ChallengeRequest is the request to send an MFA challenge.
type ChallengeRequest struct {
	UserID          string `json:"user_id" binding:"required"`
	Method          string `json:"method"`
	DeviceFingerprint string `json:"device_fingerprint"`
}

// ChallengeResponse indicates an MFA challenge has been issued.
type ChallengeResponse struct {
	Method    string `json:"method"`
	Sent      bool   `json:"sent"`
	ExpiresIn int    `json:"expires_in"`
	Message   string `json:"message"`
}

// VerifyRequest is the request to verify an MFA code.
type VerifyRequest struct {
	UserID          string `json:"user_id" binding:"required"`
	Code            string `json:"code" binding:"required"`
	Method          string `json:"method"`
	TrustDevice     bool   `json:"trust_device"`
	DeviceFingerprint string `json:"device_fingerprint"`
	DeviceName      string `json:"device_name"`
}

// VerifyResponse indicates the result of MFA verification.
type VerifyResponse struct {
	Verified      bool   `json:"verified"`
	Message       string `json:"message"`
	RemainingCodes int   `json:"remaining_codes,omitempty"`
}

// DisableRequest is the request to disable MFA for a user.
type DisableRequest struct {
	UserID string `json:"user_id" binding:"required"`
	Code   string `json:"code" binding:"required"`
}
