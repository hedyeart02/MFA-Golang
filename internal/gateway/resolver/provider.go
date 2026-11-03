package resolver

import "github.com/hidayat-SE/samlguard/internal/gateway/model"

// ProviderResolver determines the backing IdP Strategy based on metadata
type ProviderResolver interface {
	ResolveProvider(ctx *model.AuthenticationContext) (string, error)
}
