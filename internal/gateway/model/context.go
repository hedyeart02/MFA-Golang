package model

import "time"

// SecurityFlags captures safety mechanisms passed during validation
type SecurityFlags struct {
	IsSigned        bool
	IsEncrypted     bool
	ReplayDetected  bool
	ClockSkewValid  bool
	BindingSecure   bool
}

// ValidationResult summarizes validation outcomes
type ValidationResult struct {
	IsValid      bool
	ErrorMessage string
	FailedPolicy string
}

// AuthenticationContext is the canonical SAML payload processed by the gateway
type AuthenticationContext struct {
	// Tracing
	RequestID     string
	CorrelationID string
	TraceID       string

	// Pipeline Metrics (Milestone 6.5)
	Metrics PipelineMetrics

	// Connection Properties (Milestone 6)
	OriginalClientIP  string
	XForwardedFor     string
	TLSVersion        uint16
	TLSCipher         uint16
	Host              string
	RequestMethod     string

	// Raw Inputs
	RawRequest      []byte
	RawXML          []byte
	RawBinding      string
	OriginalURL     string
	RequestSize     int
	CompressionMethod string
	ReceivedAt      time.Time

	// SAML AuthnRequest Fields
	RequestIDFromSP             string
	RelayState                  string
	IssueInstant                time.Time
	Destination                 string
	Issuer                      string
	EntityID                    string
	AssertionConsumerServiceURL string
	ProtocolBinding             string
	RequestBinding              string
	ForceAuthn                  bool
	IsPassive                   bool
	NameIDPolicy                string
	RequestedAuthnContext       string

	// Security & Validation
	SignaturePresent   bool
	SignatureAlgorithm string
	DigestAlgorithm    string
	Compression        bool
	ClockSkew          time.Duration
	SecurityFlags      SecurityFlags
	ValidationResult   ValidationResult

	// Resolution
	ProviderType string
	Metadata     interface{}

	// Upstream Validated SAML Assertion Identity
	UpstreamEntityID    string
	SubjectNameID       string
	SubjectNameIDFormat string
	ImmutableUserID     string
	UserIdentityKey     string
	UserEmail           string
	UserDisplayName     string
	UserGroups          []string
	MappedGroups        []string
	UserAttributes      map[string][]string

	// SAML Correlation State
	ITAAuthnRequestID string
	ITARelayState     string
	OutboundRequestID string
	ITAACSURL         string
}

// PipelineMetrics tracks the precise duration of each architectural layer execution
type PipelineMetrics struct {
	DecodeDuration    time.Duration
	InflateDuration   time.Duration
	ParseDuration     time.Duration
	NormalizeDuration time.Duration
	ValidateDuration  time.Duration
	PeakMemoryBytes   uint64
	MaxInflateRatio   float64
	MaxXMLSize        int
}
