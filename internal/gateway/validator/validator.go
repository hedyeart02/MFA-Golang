package validator

import "github.com/hidayat-SE/samlguard/internal/gateway/model"

// SyntaxValidator ensures the request obeys physical constraints (size, valid XML, compression)
type SyntaxValidator interface {
	ValidateSyntax(ctx *model.AuthenticationContext) error
}

// SignatureValidator verifies the digital signature of the SAML request
type SignatureValidator interface {
	ValidateSignature(ctx *model.AuthenticationContext) error
}

// SchemaValidator ensures the structural integrity and bounds
type SchemaValidator interface {
	ValidateSchema(ctx *model.AuthenticationContext) error
}

// ReplayValidator prevents replay attacks using a backend cache
type ReplayValidator interface {
	ValidateReplay(ctx *model.AuthenticationContext) error
}

// ClockValidator enforces IssueInstant boundaries and clock skew
type ClockValidator interface {
	ValidateClockSkew(ctx *model.AuthenticationContext) error
}

// PolicyValidator enforces SAML 2.0 semantic rules (Destination, Issuer, Protocol)
type PolicyValidator interface {
	ValidatePolicy(ctx *model.AuthenticationContext) error
}
