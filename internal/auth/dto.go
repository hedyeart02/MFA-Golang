package auth

// ValidateRequest is the request to validate a SAML response.
type ValidateRequest struct {
	SAMLResponse string `json:"saml_response" binding:"required"`
	RelayState   string `json:"relay_state"`
}

// ValidateResponse contains the validated user information.
type ValidateResponse struct {
	Valid       bool              `json:"valid"`
	UserID      string            `json:"user_id"`
	Email       string            `json:"email"`
	DisplayName string            `json:"display_name"`
	NameID      string            `json:"name_id"`
	IdPEntityID string            `json:"idp_entity_id"`
	Attributes  map[string]string `json:"attributes"`
	Error       string            `json:"error,omitempty"`
}

// GenerateAssertionRequest is the request to generate a new signed assertion.
type GenerateAssertionRequest struct {
	UserID       string            `json:"user_id" binding:"required"`
	Email        string            `json:"email" binding:"required"`
	DisplayName  string            `json:"display_name"`
	NameID       string            `json:"name_id" binding:"required"`
	Attributes   map[string]string `json:"attributes"`
	SPEntityID   string            `json:"sp_entity_id" binding:"required"`
	SPACSURL     string            `json:"sp_acs_url" binding:"required"`
	Audience     string            `json:"audience" binding:"required"`
	InResponseTo string            `json:"in_response_to"`
	RelayState   string            `json:"relay_state"`
}

// GenerateAssertionResponse contains the generated SAML response.
type GenerateAssertionResponse struct {
	SAMLResponse string `json:"saml_response"`
	RelayState   string `json:"relay_state"`
	Destination  string `json:"destination"`
}

// RegisterMetadataRequest is the request to register SP or IdP metadata.
type RegisterMetadataRequest struct {
	Type        string `json:"type" binding:"required"`
	EntityID    string `json:"entity_id" binding:"required"`
	MetadataURL string `json:"metadata_url"`
	MetadataXML string `json:"metadata_xml"`
}
