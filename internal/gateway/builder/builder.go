package builder

import (
	"github.com/hidayat-SE/samlguard/internal/gateway/model"
)

// Normalizer adapts the raw parsed payload into standard internal fields
type Normalizer interface {
	Normalize(parsed *model.ParseResult, ctx *model.AuthenticationContext) error
}

// ContextBuilder constructs the final AuthenticationContext using normalized data and resolution outcomes
type ContextBuilder interface {
	Build(ctx *model.AuthenticationContext) (*model.AuthenticationContext, error)
}
