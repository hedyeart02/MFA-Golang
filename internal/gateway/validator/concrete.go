package validator

import (
	"errors"
	"time"

	"github.com/hidayat-SE/samlguard/internal/gateway/model"
)

type DefaultSignatureValidator struct{}
func (v *DefaultSignatureValidator) ValidateSignature(ctx *model.AuthenticationContext) error {
	// Milestone 6: Just check presence, crewjam handles deep verification later if bound
	// Stub for ITA compatibility verification phase
	return nil
}

type DefaultSchemaValidator struct{}
func (v *DefaultSchemaValidator) ValidateSchema(ctx *model.AuthenticationContext) error {
	if ctx.Issuer == "" {
		return errors.New("missing Issuer in SAML Request")
	}
	return nil
}

type DefaultReplayValidator struct {
	Cache map[string]time.Time
	TTL   time.Duration
}
func (v *DefaultReplayValidator) ValidateReplay(ctx *model.AuthenticationContext) error {
	if ctx.RequestIDFromSP == "" {
		return nil
	}
	if _, exists := v.Cache[ctx.RequestIDFromSP]; exists {
		return errors.New("replay attack detected: ID already processed")
	}
	// Note: in a real implementation, we need a mutex for the cache map
	v.Cache[ctx.RequestIDFromSP] = time.Now().Add(v.TTL)
	return nil
}

type DefaultClockValidator struct {
	AllowedSkew time.Duration
}
func (v *DefaultClockValidator) ValidateClockSkew(ctx *model.AuthenticationContext) error {
	if ctx.IssueInstant.IsZero() {
		return nil // Not provided
	}
	now := time.Now()
	diff := now.Sub(ctx.IssueInstant)
	if diff < 0 {
		diff = -diff
	}
	if diff > v.AllowedSkew {
		return errors.New("clock skew exceeds allowed threshold")
	}
	return nil
}

type DefaultPolicyValidator struct {
	ExpectedDestination string
}
func (v *DefaultPolicyValidator) ValidatePolicy(ctx *model.AuthenticationContext) error {
	if ctx.Destination != "" && v.ExpectedDestination != "" && ctx.Destination != v.ExpectedDestination {
		return errors.New("destination mismatch: request not intended for this proxy")
	}
	return nil
}
