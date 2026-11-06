package resolver

import (
	"strings"
	"testing"

	"github.com/hidayat-SE/samlguard/internal/federation/adapter"
	"github.com/hidayat-SE/samlguard/internal/federation/adapter/entra"
	fedmodel "github.com/hidayat-SE/samlguard/internal/federation/model"
	"github.com/hidayat-SE/samlguard/internal/gateway/model"
)

func setupTestRegistry() *adapter.Registry {
	entraAdapter := &entra.EntraAdapter{}
	genericAdapter := &adapter.GenericAdapter{}
	return adapter.NewRegistry(entraAdapter, genericAdapter)
}

func TestProviderResolver_ExplicitProviderType(t *testing.T) {
	reg := setupTestRegistry()
	resolver := NewDefaultProviderResolver(reg, nil)

	ctx := &model.AuthenticationContext{
		ProviderType: "entra",
	}

	p, err := resolver.ResolveProvider(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p != "entra" {
		t.Errorf("expected entra, got %s", p)
	}
}

func TestProviderResolver_ConfiguredMapping(t *testing.T) {
	reg := setupTestRegistry()
	mappings := map[string]string{
		"https://login.partner.com": "entra",
		"https://custom.idp.org":   "generic",
	}
	resolver := NewDefaultProviderResolver(reg, mappings)

	// Test Entra mapping
	ctx1 := &model.AuthenticationContext{
		Issuer: "https://login.partner.com",
	}
	p1, err := resolver.ResolveProvider(ctx1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p1 != "entra" {
		t.Errorf("expected entra, got %s", p1)
	}

	// Test Generic mapping
	ctx2 := &model.AuthenticationContext{
		Issuer: "https://custom.idp.org",
	}
	p2, err := resolver.ResolveProvider(ctx2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p2 != "generic" {
		t.Errorf("expected generic, got %s", p2)
	}
}

func TestProviderResolver_MetadataInspection(t *testing.T) {
	reg := setupTestRegistry()
	resolver := NewDefaultProviderResolver(reg, nil)

	ctx := &model.AuthenticationContext{
		Issuer: "https://sts.windows.net/tenant-xyz/",
		Metadata: &fedmodel.MetadataDescriptor{
			EntityID: "https://sts.windows.net/tenant-xyz/",
		},
	}

	p, err := resolver.ResolveProvider(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p != "entra" {
		t.Errorf("expected entra, got %s", p)
	}
}

func TestProviderResolver_UnknownProviderID(t *testing.T) {
	reg := setupTestRegistry()
	resolver := NewDefaultProviderResolver(reg, nil)

	// Unknown ProviderType requested
	ctx := &model.AuthenticationContext{
		ProviderType: "okta",
	}

	_, err := resolver.ResolveProvider(ctx)
	if err == nil {
		t.Fatal("expected error for unknown provider ID okta, got nil")
	}
	if !strings.Contains(err.Error(), "unknown provider ID") {
		t.Errorf("expected error to mention unknown provider ID, got %v", err)
	}
}

func TestProviderResolver_UnmappedIssuer_NoArbitraryFallback(t *testing.T) {
	reg := setupTestRegistry()
	resolver := NewDefaultProviderResolver(reg, nil)

	// Unmapped issuer with no matching metadata descriptor
	ctx := &model.AuthenticationContext{
		Issuer: "https://unregistered.random-idp.com",
	}

	_, err := resolver.ResolveProvider(ctx)
	if err == nil {
		t.Fatal("expected error for unmapped issuer (no arbitrary fallback), got nil")
	}
	if !strings.Contains(err.Error(), "no implicit fallback permitted") {
		t.Errorf("expected error about no implicit fallback, got %v", err)
	}
}

func TestProviderResolver_NilContext(t *testing.T) {
	reg := setupTestRegistry()
	resolver := NewDefaultProviderResolver(reg, nil)

	_, err := resolver.ResolveProvider(nil)
	if err == nil {
		t.Fatal("expected error for nil context, got nil")
	}
}

