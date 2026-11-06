package builder

import (
	"errors"

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

// DefaultContextBuilder provides the production ContextBuilder implementation
type DefaultContextBuilder struct{}

func NewDefaultContextBuilder() *DefaultContextBuilder {
	return &DefaultContextBuilder{}
}

func (b *DefaultContextBuilder) Build(ctx *model.AuthenticationContext) (*model.AuthenticationContext, error) {
	if ctx == nil {
		return nil, errors.New("authentication context cannot be nil")
	}

	// Finalize context flags and validation summary
	if ctx.ValidationResult.ErrorMessage == "" && ctx.ValidationResult.IsValid {
		ctx.ValidationResult.IsValid = true
	}

	return ctx, nil
}
