package model

import "time"

// TransportResult holds the data successfully extracted from the HTTP boundary
type TransportResult struct {
	RawBase64        string
	CompressedBytes  []byte
	InflatedBytes    []byte
	SHA256           string
	CompressionRatio float64
	InflatedSize     int
	RelayState       string
	BindingType      string
}

// ParseResult holds the isolated evaluation of the XML payload
type ParseResult struct {
	Request       *RawAuthnRequest
	Warnings      []string
	SecurityEvents []string
}

// RawAuthnRequest represents the structurally parsed but un-normalized SAML Request
type RawAuthnRequest struct {
	ID           string
	Issuer       string
	IssueInstant string
	Destination  string
	AssertionURL string
	Protocol     string
	ForceAuthn   bool
	IsPassive    bool
}

// MetadataDescriptor provides strongly typed access to Identity Provider metadata
type MetadataDescriptor struct {
	EntityID    string
	SSOEndpoint string
	SLOEndpoint string
	Certificates [][]byte
	ValidUntil  time.Time
}
