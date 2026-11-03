package metadata

import (
	"context"

	"github.com/hidayat-SE/samlguard/internal/federation/adapter"
	"github.com/hidayat-SE/samlguard/internal/federation/model"
)

// Resolver orchestrates the entire Federation Metadata Pipeline
type Resolver struct {
	Loader     MetadataLoader
	Parser     *Parser
	Normalizer *Normalizer
	Validator  MetadataValidator
	Cache      *Cache
	Registry   *adapter.Registry
}

func (r *Resolver) ResolveContext(ctx context.Context, source string) (*model.FederationContext, error) {
	// 1. Check Cache
	if cachedMd, hit := r.Cache.Get(source); hit {
		return r.dispatchToAdapter(cachedMd)
	}

	// 2. Load
	rawXML, err := r.Loader.Load(ctx, source)
	if err != nil {
		return nil, err
	}

	// 3. Parse (Isolates crewjam struct entirely within this boundary)
	md, err := r.Parser.Parse(rawXML)
	if err != nil {
		return nil, err
	}

	// 4. Normalize (deep extraction without exposing crewjam)
	if err := r.Normalizer.Normalize(rawXML, md); err != nil {
		return nil, err
	}

	// 5. Validate
	if err := r.Validator.Validate(md); err != nil {
		return nil, err
	}

	// 6. Cache
	ttl := md.CacheDuration
	if ttl == 0 {
		ttl = 24 * 60 * 60 * 1000 * 1000 * 1000 // 24 hours fallback
	}
	r.Cache.Set(source, md, ttl)

	// 7. Adapter Dispatch
	return r.dispatchToAdapter(md)
}

func (r *Resolver) dispatchToAdapter(md *model.MetadataDescriptor) (*model.FederationContext, error) {
	providerAdapter, confidence, err := r.Registry.DetectProvider(md)
	if err != nil {
		return nil, err
	}

	fedCtx, err := providerAdapter.BuildFederationContext(md)
	if err != nil {
		return nil, err
	}

	// Inject detection metrics back into context
	fedCtx.DetectedProvider = providerAdapter.Info().ID
	fedCtx.DetectionConfidence = confidence

	return fedCtx, nil
}
