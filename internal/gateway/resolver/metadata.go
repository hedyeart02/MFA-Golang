package resolver

import "context"

type MetadataProvider interface {
	FetchMetadata(ctx context.Context, entityID string) (interface{}, error)
}

type StaticMetadataProvider struct{}

func (s *StaticMetadataProvider) FetchMetadata(ctx context.Context, entityID string) (interface{}, error) {
	return nil, nil // Stub
}

type HTTPMetadataProvider struct{}

func (h *HTTPMetadataProvider) FetchMetadata(ctx context.Context, entityID string) (interface{}, error) {
	return nil, nil // Stub
}

// MetadataResolver coordinates fetching metadata through defined providers without performing HTTP directly
type MetadataResolver interface {
	Resolve(ctx context.Context, entityID string) (interface{}, error)
}
