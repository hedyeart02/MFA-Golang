package model

import (
	"time"
)

// MetadataSource defines where the metadata was loaded from (URL, File, Static)
type MetadataSource string

// MetadataHash is the SHA-256 hash of the raw XML source bytes
type MetadataHash string

// MetadataVersion tracks sequential updates (useful for diff engine)
type MetadataVersion int

type MetadataLoadedAt time.Time
type MetadataExpiresAt time.Time

// TrustStatus defines the trust validation state of a certificate or metadata
type TrustStatus string

const (
	TrustStatusTrusted   TrustStatus = "TRUSTED"
	TrustStatusUntrusted TrustStatus = "UNTRUSTED"
	TrustStatusUnknown   TrustStatus = "UNKNOWN"
)

// Endpoint represents a SAML service endpoint (SSO, SLO)
type Endpoint struct {
	Binding  string
	Location string
	Response string
}

// CertificateDescriptor represents an X.509 certificate bundled in the metadata
type CertificateDescriptor struct {
	Use               string // "signing", "encryption"
	RawPEM            string // Base64 raw encoded bytes
	SHA1Fingerprint   string
	SHA256Fingerprint string
	Subject           string
	Issuer            string
	NotBefore         time.Time
	NotAfter          time.Time
	Trust             TrustStatus
}

type Organization struct {
	Name        string
	DisplayName string
	URL         string
}

type Contact struct {
	Type         string // "technical", "support", "administrative"
	GivenName    string
	EmailAddress string
}

// ProviderCapabilities tracks supported SAML features extracted from metadata
type ProviderCapabilities struct {
	SupportsArtifact      bool
	SupportsLogout        bool
	RequiresSignedAuthn   bool
	RequiresSignedLogout  bool
	SupportedNameIDFormat []string
}

// MetadataDescriptor is the canonical, normalized representation of IdP metadata.
type MetadataDescriptor struct {
	EntityID     string
	ValidUntil   *time.Time
	CacheDuration time.Duration

	Certificates []CertificateDescriptor
	SSOEndpoints []Endpoint
	SLOEndpoints []Endpoint

	Organization *Organization
	Contacts     []Contact

	Capabilities ProviderCapabilities

	// Tracking Metadata state
	Source    MetadataSource
	Hash      MetadataHash
	Version   MetadataVersion
	LoadedAt  MetadataLoadedAt
	ExpiresAt MetadataExpiresAt
}

// SigningPolicy dictates what aspects of a Federation interaction must be cryptographically signed
type SigningPolicy struct {
	SignAuthnRequests      bool
	SignLogoutRequest      bool
	RequireSignedResponse  bool
	RequireSignedAssertion bool
	AllowedAlgorithms      []string
}

// TrustPolicy dictates constraints on the trusted identity provider
type TrustPolicy struct {
	EnforceCertificateExpiry bool
	EnforceChainValidation   bool
	PinnedFingerprints       []string
}

// FederationContext represents the final synthesized adapter output ready for proxying
type FederationContext struct {
	ProviderName        string // "Microsoft Entra", "Okta", etc.
	DetectedProvider    string
	DetectionConfidence string // "HIGH", "MEDIUM", "LOW"
	EntityID            string

	ActiveSSOEndpoint Endpoint
	ActiveSLOEndpoint *Endpoint // Optional

	SigningCertificates []CertificateDescriptor

	Capabilities ProviderCapabilities
	SigningPolicy SigningPolicy
	TrustPolicy   TrustPolicy

	// Internal link back to original loaded descriptor hash for diffing
	SourceHash MetadataHash
}

