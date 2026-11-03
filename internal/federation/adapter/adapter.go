package adapter

import (
	"errors"
	"strings"

	"github.com/hidayat-SE/samlguard/internal/federation/model"
)

// ProviderInfo describes the metadata about the adapter itself
type ProviderInfo struct {
	ID          string
	Name        string
	Description string
}

// ProviderAdapter handles transforming the normalized MetadataDescriptor into a specific FederationContext
type ProviderAdapter interface {
	Info() ProviderInfo
	// Supports evaluates the metadata to determine if this adapter natively supports it (e.g. looking at EntityID, namespaces)
	Supports(md *model.MetadataDescriptor) bool
	BuildFederationContext(md *model.MetadataDescriptor) (*model.FederationContext, error)
}

// Registry manages the collection of all registered Provider Adapters
type Registry struct {
	adapters []ProviderAdapter
}

// NewRegistry creates a registry injected with all known adapters
func NewRegistry(adapters ...ProviderAdapter) *Registry {
	return &Registry{
		adapters: adapters,
	}
}

// DetectProvider iterates through registered adapters calling Supports() to auto-detect the IDP.
// It falls back to the "generic" adapter if none match.
func (r *Registry) DetectProvider(md *model.MetadataDescriptor) (ProviderAdapter, string, error) {
	var genericAdapter ProviderAdapter

	for _, adapter := range r.adapters {
		info := adapter.Info()
		
		if info.ID == "generic" {
			genericAdapter = adapter
		} else if adapter.Supports(md) {
			// Found a specific adapter match
			return adapter, "HIGH", nil
		}
	}

	// Fallback detection logic if no explicit Supports() returned true, but we could infer it
	for _, adapter := range r.adapters {
		info := adapter.Info()
		if info.ID == "generic" {
			continue
		}
		
		// Weak inference (e.g., checking if entityID just contains the name)
		if strings.Contains(strings.ToLower(md.EntityID), strings.ToLower(info.ID)) {
			return adapter, "MEDIUM", nil
		}
	}

	if genericAdapter != nil {
		return genericAdapter, "LOW", nil
	}

	return nil, "", errors.New("no suitable provider adapter found and generic adapter is missing")
}
