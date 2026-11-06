package validator

import (
	"errors"
	"fmt"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/hidayat-SE/samlguard/internal/gateway/model"
)

// DefaultSignatureValidator enforces fail-closed behavior for SAML message signatures.
// When AllowUnsigned is true, unsigned SAML AuthnRequests (e.g. from SP HTTP-Redirect) are allowed.
type DefaultSignatureValidator struct {
	AllowUnsigned bool
}

func (v *DefaultSignatureValidator) ValidateSignature(ctx *model.AuthenticationContext) error {
	if ctx == nil {
		return errors.New("authentication context is nil")
	}
	if v.AllowUnsigned && !ctx.SecurityFlags.IsSigned {
		return nil
	}
	if ctx.SecurityFlags.IsSigned {
		return errors.New("signature verification is not implemented: fail-closed security boundary enforced")
	}
	ctx.SecurityFlags.IsSigned = false
	return errors.New("signature verification is not implemented: fail-closed security boundary enforced")
}

// DefaultSyntaxValidator ensures the request obeys physical constraints (size, valid UTF-8)
type DefaultSyntaxValidator struct {
	MaxXMLSize int
}

func (v *DefaultSyntaxValidator) ValidateSyntax(ctx *model.AuthenticationContext) error {
	if ctx == nil {
		return errors.New("authentication context is nil")
	}
	if len(ctx.RawXML) == 0 {
		return errors.New("raw XML payload is empty")
	}
	if v.MaxXMLSize > 0 && len(ctx.RawXML) > v.MaxXMLSize {
		return fmt.Errorf("raw XML payload size %d exceeds maximum allowed size of %d bytes", len(ctx.RawXML), v.MaxXMLSize)
	}
	if !utf8.Valid(ctx.RawXML) {
		return errors.New("raw XML payload contains invalid UTF-8 characters")
	}
	return nil
}

// DefaultSchemaValidator ensures mandatory fields like Issuer are present
type DefaultSchemaValidator struct{}

func (v *DefaultSchemaValidator) ValidateSchema(ctx *model.AuthenticationContext) error {
	if ctx == nil {
		return errors.New("authentication context is nil")
	}
	if ctx.Issuer == "" {
		return errors.New("missing Issuer in SAML Request")
	}
	return nil
}

// DefaultReplayValidator provides thread-safe in-memory replay attack detection.
// NOTE: This provides localized in-memory synchronization for concurrent goroutines
// on a single instance. It does NOT provide distributed replay protection across clustered gateway nodes.
type DefaultReplayValidator struct {
	mu    sync.Mutex
	Cache map[string]time.Time
	TTL   time.Duration
}

func NewDefaultReplayValidator(ttl time.Duration) *DefaultReplayValidator {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &DefaultReplayValidator{
		Cache: make(map[string]time.Time),
		TTL:   ttl,
	}
}

func (v *DefaultReplayValidator) ValidateReplay(ctx *model.AuthenticationContext) error {
	if ctx == nil || ctx.RequestIDFromSP == "" {
		return nil
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	if v.Cache == nil {
		v.Cache = make(map[string]time.Time)
	}

	now := time.Now()

	// Check if ID is in cache and has not expired
	if exp, exists := v.Cache[ctx.RequestIDFromSP]; exists {
		if now.Before(exp) {
			return errors.New("replay attack detected: ID already processed")
		}
		delete(v.Cache, ctx.RequestIDFromSP)
	}

	// Housekeeping: periodic purge of expired entries when cache size exceeds threshold
	if len(v.Cache) > 1000 {
		for id, exp := range v.Cache {
			if now.After(exp) {
				delete(v.Cache, id)
			}
		}
	}

	v.Cache[ctx.RequestIDFromSP] = now.Add(v.TTL)
	return nil
}

// DefaultClockValidator enforces IssueInstant boundaries and clock skew
type DefaultClockValidator struct {
	AllowedSkew time.Duration
}

func (v *DefaultClockValidator) ValidateClockSkew(ctx *model.AuthenticationContext) error {
	if ctx == nil || ctx.IssueInstant.IsZero() {
		return nil // Not provided
	}
	skew := v.AllowedSkew
	if skew <= 0 {
		skew = 5 * time.Minute
	}

	now := time.Now()
	diff := now.Sub(ctx.IssueInstant)
	if diff < 0 {
		diff = -diff
	}
	if diff > skew {
		return errors.New("clock skew exceeds allowed threshold")
	}
	return nil
}

// DefaultPolicyValidator enforces SAML 2.0 semantic destination rules
type DefaultPolicyValidator struct {
	ExpectedDestination string
}

func (v *DefaultPolicyValidator) ValidatePolicy(ctx *model.AuthenticationContext) error {
	if ctx == nil {
		return errors.New("authentication context is nil")
	}
	if ctx.Destination != "" && v.ExpectedDestination != "" && ctx.Destination != v.ExpectedDestination {
		return errors.New("destination mismatch: request not intended for this proxy")
	}
	return nil
}
