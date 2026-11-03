package pipeline

import (
	"context"
	"github.com/hidayat-SE/samlguard/internal/gateway/model"
)

// AuthnPipeline glues the stages together sequentially:
// Binding -> Decoder -> Normalizer -> Validator -> MetadataResolver -> ProviderResolver -> ContextBuilder
type AuthnPipeline interface {
	Execute(ctx context.Context, input interface{}) (*model.AuthenticationContext, error)
}
