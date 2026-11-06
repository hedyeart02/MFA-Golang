package resolver

import (
	"errors"
	"fmt"
	"strings"

	"github.com/hidayat-SE/samlguard/internal/federation/adapter"
	fedmodel "github.com/hidayat-SE/samlguard/internal/federation/model"
	"github.com/hidayat-SE/samlguard/internal/gateway/model"
)

// ProviderResolver determines the backing IdP Strategy based on metadata
type ProviderResolver interface {
	ResolveProvider(ctx *model.AuthenticationContext) (string, error)
}

// DefaultProviderResolver resolves configured providers using explicit configuration or metadata
type DefaultProviderResolver struct {
	Registry            *adapter.Registry
	ConfiguredProviders map[string]string // EntityID or Alias -> Provider ID
}

func NewDefaultProviderResolver(reg *adapter.Registry, configuredProviders map[string]string) *DefaultProviderResolver {
	if configuredProviders == nil {
		configuredProviders = make(map[string]string)
	}
	return &DefaultProviderResolver{
		Registry:            reg,
		ConfiguredProviders: configuredProviders,
	}
}

func (r *DefaultProviderResolver) ResolveProvider(ctx *model.AuthenticationContext) (string, error) {
	if ctx == nil {
		return "", errors.New("cannot resolve provider: authentication context is nil")
	}

	if r.Registry == nil {
		return "", errors.New("cannot resolve provider: adapter registry is nil")
	}

	// 1. Explicit ProviderType in context
	if strings.TrimSpace(ctx.ProviderType) != "" {
		if a, found := r.Registry.GetAdapter(ctx.ProviderType); found {
			return a.Info().ID, nil
		}
		return "", fmt.Errorf("unknown provider ID %q: provider not registered in adapter registry", ctx.ProviderType)
	}

	// 2. Explicit configuration mapping for Issuer
	if strings.TrimSpace(ctx.Issuer) != "" {
		if providerID, ok := r.ConfiguredProviders[ctx.Issuer]; ok {
			if a, found := r.Registry.GetAdapter(providerID); found {
				return a.Info().ID, nil
			}
			return "", fmt.Errorf("configured provider ID %q for issuer %q is not registered in adapter registry", providerID, ctx.Issuer)
		}
	}

	// 3. Inspect metadata if present
	if ctx.Metadata != nil {
		if md, ok := ctx.Metadata.(*fedmodel.MetadataDescriptor); ok {
			for _, a := range r.Registry.Adapters() {
				// Avoid arbitrary fallback to generic unless matched
				if a.Info().ID != "generic" && a.Supports(md) {
					return a.Info().ID, nil
				}
			}
		}
	}

	// 4. Reject unknown provider IDs - strictly avoid implicit fallback to an arbitrary provider
	issuer := ctx.Issuer
	if issuer == "" {
		issuer = "(empty)"
	}
	return "", fmt.Errorf("unable to resolve provider for issuer %q: unknown provider (no implicit fallback permitted)", issuer)
}
