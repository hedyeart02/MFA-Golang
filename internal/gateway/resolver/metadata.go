package resolver

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hidayat-SE/samlguard/internal/federation/metadata"
	fedmodel "github.com/hidayat-SE/samlguard/internal/federation/model"
)

// MetadataProvider retrieves metadata for a specified entity
type MetadataProvider interface {
	FetchMetadata(ctx context.Context, entityID string) (interface{}, error)
}

// StaticMetadataProvider loads and parses metadata from a configured local file
type StaticMetadataProvider struct {
	SourcePath string
	Loader     metadata.MetadataLoader
	Parser     *metadata.Parser
}

func NewStaticMetadataProvider(sourcePath string, loader metadata.MetadataLoader, p *metadata.Parser) *StaticMetadataProvider {
	if loader == nil {
		loader = &metadata.StaticFileLoader{}
	}
	if p == nil {
		p = &metadata.Parser{}
	}
	return &StaticMetadataProvider{
		SourcePath: sourcePath,
		Loader:     loader,
		Parser:     p,
	}
}

func (s *StaticMetadataProvider) FetchMetadata(ctx context.Context, entityID string) (interface{}, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(s.SourcePath) == "" {
		return nil, errors.New("static metadata source path cannot be empty")
	}
	loader := s.Loader
	if loader == nil {
		loader = &metadata.StaticFileLoader{}
	}
	rawXML, err := loader.Load(ctx, s.SourcePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load static metadata from %q: %w", s.SourcePath, err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(rawXML) == 0 {
		return nil, fmt.Errorf("static metadata source %q is empty", s.SourcePath)
	}

	p := s.Parser
	if p == nil {
		p = &metadata.Parser{}
	}
	md, err := p.ParseEntity(rawXML, entityID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse static metadata for entityID %q: %w", entityID, err)
	}
	return md, nil
}

// HTTPMetadataProvider fails-closed as unnecessary network-fetching features are disabled
type HTTPMetadataProvider struct{}

func (h *HTTPMetadataProvider) FetchMetadata(ctx context.Context, entityID string) (interface{}, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, errors.New("HTTP metadata fetching is not enabled: configured local metadata sources must be used")
}

// MetadataResolver coordinates fetching metadata through defined providers without performing HTTP directly
type MetadataResolver interface {
	Resolve(ctx context.Context, entityID string) (interface{}, error)
}

// DefaultMetadataResolver coordinates retrieving and parsing metadata using hardened parsers
type DefaultMetadataResolver struct {
	Sources       map[string]string // entityID -> source file path
	DefaultSource string            // fallback source file path
	Loader        metadata.MetadataLoader
	Parser        *metadata.Parser
	Provider      MetadataProvider
}

func NewDefaultMetadataResolver(sources map[string]string, defaultSource string, loader metadata.MetadataLoader, p *metadata.Parser) *DefaultMetadataResolver {
	if sources == nil {
		sources = make(map[string]string)
	}
	if loader == nil {
		loader = &metadata.StaticFileLoader{}
	}
	if p == nil {
		p = &metadata.Parser{}
	}
	return &DefaultMetadataResolver{
		Sources:       sources,
		DefaultSource: defaultSource,
		Loader:        loader,
		Parser:        p,
	}
}

func (r *DefaultMetadataResolver) Resolve(ctx context.Context, entityID string) (interface{}, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// 1. Determine metadata source
	var sourcePath string
	if entityID != "" {
		sourcePath = r.Sources[entityID]
	}
	if sourcePath == "" {
		sourcePath = r.DefaultSource
	}

	if sourcePath == "" {
		if r.Provider != nil {
			return r.Provider.FetchMetadata(ctx, entityID)
		}
		if entityID == "" {
			return nil, errors.New("cannot resolve metadata: entityID is empty and no default metadata source configured")
		}
		return nil, fmt.Errorf("metadata source unavailable: entityID %q not found in configured sources", entityID)
	}

	// 2. Load metadata bytes
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	loader := r.Loader
	if loader == nil {
		loader = &metadata.StaticFileLoader{}
	}

	rawXML, err := loader.Load(ctx, sourcePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load metadata from source %q for entityID %q: %w", sourcePath, entityID, err)
	}
	if len(rawXML) == 0 {
		return nil, fmt.Errorf("metadata source %q for entityID %q is empty", sourcePath, entityID)
	}

	// 3. Parse with hardened parser
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	p := r.Parser
	if p == nil {
		p = &metadata.Parser{}
	}

	desc, err := p.ParseEntity(rawXML, entityID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse metadata from %q for entityID %q: %w", sourcePath, entityID, err)
	}
	if desc == nil {
		return nil, fmt.Errorf("metadata descriptor is nil for entityID %q", entityID)
	}

	// 4. Do not treat parsed metadata as trusted metadata
	desc.Source = fedmodel.MetadataSource(sourcePath)
	for i := range desc.Certificates {
		desc.Certificates[i].Trust = fedmodel.TrustStatusUnknown
	}

	return desc, nil
}
