package builder

import (
	"time"

	"github.com/hidayat-SE/samlguard/internal/gateway/model"
)

type DefaultNormalizer struct{}

func (n *DefaultNormalizer) Normalize(parsed *model.ParseResult, ctx *model.AuthenticationContext) error {
	raw := parsed.Request
	if raw == nil {
		return nil
	}

	ctx.RequestIDFromSP = raw.ID
	ctx.Issuer = raw.Issuer
	ctx.Destination = raw.Destination
	ctx.AssertionConsumerServiceURL = raw.AssertionURL
	ctx.ProtocolBinding = raw.Protocol
	ctx.ForceAuthn = raw.ForceAuthn
	ctx.IsPassive = raw.IsPassive

	if parsedInstant, err := time.Parse(time.RFC3339, raw.IssueInstant); err == nil {
		ctx.IssueInstant = parsedInstant
	}

	// Apply warnings/security events from parser
	// E.g. attach them to a diagnostics slice in ctx, but we'll just set validation result for now
	if len(parsed.SecurityEvents) > 0 {
		ctx.ValidationResult.IsValid = false
		ctx.ValidationResult.ErrorMessage = parsed.SecurityEvents[0]
	} else {
		ctx.ValidationResult.IsValid = true
	}

	return nil
}
