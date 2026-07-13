// Package saml provides SAML 2.0 types shared across the gateway.
package saml

import "time"

// SAMLRequest represents a parsed SAML AuthnRequest.
type SAMLRequest struct {
	ID               string `json:"id"`
	Issuer           string `json:"issuer"`
	ACSURL           string `json:"acs_url"`
	Destination      string `json:"destination"`
	ProtocolBinding  string `json:"protocol_binding"`
	RelayState       string `json:"relay_state"`
	ForceAuthn       bool   `json:"force_authn"`
	IsPassive        bool   `json:"is_passive"`
	NameIDPolicy     string `json:"name_id_policy"`
}

// SAMLAttribute represents a single SAML attribute name-value pair.
type SAMLAttribute struct {
	Name         string   `json:"name"`
	FriendlyName string   `json:"friendly_name,omitempty"`
	Values       []string `json:"values"`
}

// SAMLUserInfo holds extracted user attributes from a validated assertion.
type SAMLUserInfo struct {
	NameID      string            `json:"name_id"`
	Email       string            `json:"email"`
	DisplayName string            `json:"display_name,omitempty"`
	FirstName   string            `json:"first_name,omitempty"`
	LastName    string            `json:"last_name,omitempty"`
	Groups      []string          `json:"groups,omitempty"`
	Attributes  []SAMLAttribute   `json:"attributes"`
	IdPEntityID string            `json:"idp_entity_id"`
	SessionIndex string           `json:"session_index,omitempty"`
	RawAttributes map[string][]string `json:"raw_attributes,omitempty"`
}

// AssertionRequest contains the data needed to generate a new signed assertion.
type AssertionRequest struct {
	UserInfo     SAMLUserInfo `json:"user_info"`
	SPEntityID   string       `json:"sp_entity_id"`
	SPACSURL     string       `json:"sp_acs_url"`
	Audience     string       `json:"audience"`
	InResponseTo string       `json:"in_response_to"`
	RelayState   string       `json:"relay_state"`
}

// AssertionResponse contains the generated SAML response XML.
type AssertionResponse struct {
	SAMLResponse string `json:"saml_response"`
	RelayState   string `json:"relay_state"`
	Destination  string `json:"destination"`
}

// ValidationRequest contains a raw SAML response for validation.
type ValidationRequest struct {
	SAMLResponse string `json:"saml_response"`
	RelayState   string `json:"relay_state"`
}

// ValidationResponse contains the result of SAML response validation.
type ValidationResponse struct {
	Valid    bool         `json:"valid"`
	UserInfo SAMLUserInfo `json:"user_info,omitempty"`
	Error    string       `json:"error,omitempty"`
}

// SPConfig holds Service Provider SAML configuration.
type SPConfig struct {
	EntityID    string `json:"entity_id"`
	ACSURL      string `json:"acs_url"`
	MetadataURL string `json:"metadata_url"`
	CertFile    string `json:"cert_file"`
	KeyFile     string `json:"key_file"`
}

// IdPConfig holds Identity Provider SAML configuration.
type IdPConfig struct {
	EntityID    string `json:"entity_id"`
	SSOURL      string `json:"sso_url"`
	SLOURL      string `json:"slo_url"`
	MetadataURL string `json:"metadata_url"`
	CertFile    string `json:"cert_file"`
}

// AssertionIDRecord tracks assertion IDs for replay detection.
type AssertionIDRecord struct {
	AssertionID string    `json:"assertion_id"`
	ExpiresAt   time.Time `json:"expires_at"`
}
