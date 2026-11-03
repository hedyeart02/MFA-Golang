package adapter

import (
	"github.com/hidayat-SE/samlguard/internal/federation/model"
)

type GenericAdapter struct{}

func (a *GenericAdapter) Info() ProviderInfo {
	return ProviderInfo{
		ID:          "generic",
		Name:        "Generic SAML 2.0 Provider",
		Description: "Fallback adapter for standard compliant SAML 2.0 IdPs",
	}
}

func (a *GenericAdapter) Supports(md *model.MetadataDescriptor) bool {
	return true // Generic supports anything as a fallback
}

func (a *GenericAdapter) BuildFederationContext(md *model.MetadataDescriptor) (*model.FederationContext, error) {
	ctx := &model.FederationContext{
		ProviderName:        a.Info().Name,
		DetectedProvider:    a.Info().ID,
		DetectionConfidence: "LOW",
		EntityID:            md.EntityID,
		SigningCertificates: md.Certificates,
		Capabilities:        md.Capabilities,
		SourceHash:          md.Hash,
		SigningPolicy: model.SigningPolicy{
			RequireSignedAssertion: true, // safe default
		},
		TrustPolicy: model.TrustPolicy{
			EnforceCertificateExpiry: true,
			EnforceChainValidation:   false, // Generic defaults to false for chain validation
		},
	}

	if len(md.SSOEndpoints) > 0 {
		ctx.ActiveSSOEndpoint = md.SSOEndpoints[0]
	}
	if len(md.SLOEndpoints) > 0 {
		ctx.ActiveSLOEndpoint = &md.SLOEndpoints[0]
	}

	return ctx, nil
}
