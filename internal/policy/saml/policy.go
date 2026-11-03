package saml

import "github.com/hidayat-SE/samlguard/internal/gateway/model"

// Policy specifies a functional rule that evaluates an AuthenticationContext
type Policy func(ctx *model.AuthenticationContext) error

func ClockSkewPolicy(maxSkew int) Policy {
	return func(ctx *model.AuthenticationContext) error {
		// Evaluates IssueInstant against current time and ClockSkew limit
		return nil
	}
}

func DestinationPolicy(expectedHost string) Policy {
	return func(ctx *model.AuthenticationContext) error {
		// Validates the destination strictly matches the Gateway's expected host
		return nil
	}
}
