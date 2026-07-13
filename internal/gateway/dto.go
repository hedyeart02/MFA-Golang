package gateway

// MFAChallengeData holds data for rendering the MFA challenge page.
type MFAChallengeData struct {
	UserID     string `json:"user_id"`
	Email      string `json:"email"`
	Method     string `json:"method"`
	RelayState string `json:"relay_state"`
	CSRFToken  string `json:"csrf_token"`
	Message    string `json:"message"`
	ExpiresIn  int    `json:"expires_in"`
}

// MFASubmitRequest holds the MFA form submission data.
type MFASubmitRequest struct {
	UserID            string `form:"user_id" binding:"required"`
	Email             string `form:"email"`
	Code              string `form:"code" binding:"required"`
	Method            string `form:"method"`
	RelayState        string `form:"relay_state"`
	CSRFToken         string `form:"csrf_token" binding:"required"`
	TrustDevice       bool   `form:"trust_device"`
	DeviceFingerprint string `form:"device_fingerprint"`
}

// SAMLPostFormData holds data for the SAML POST binding auto-submit form.
type SAMLPostFormData struct {
	Destination  string
	SAMLResponse string
	RelayState   string
}

// HealthResponse is the health check response.
type HealthResponse struct {
	Status   string            `json:"status"`
	Service  string            `json:"service"`
	Version  string            `json:"version"`
	Services map[string]string `json:"services,omitempty"`
}
