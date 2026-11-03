package entra

import (
	"strings"

	"github.com/hidayat-SE/samlguard/internal/federation/adapter"
	"github.com/hidayat-SE/samlguard/internal/federation/model"
)

type EntraAdapter struct{}

func (a *EntraAdapter) Info() adapter.ProviderInfo {
	return adapter.ProviderInfo{
		ID:          "entra",
		Name:        "Microsoft Entra ID",
		Description: "Adapter for Microsoft Azure AD / Entra ID",
	}
}

func (a *EntraAdapter) Supports(md *model.MetadataDescriptor) bool {
	// Entra ID entity IDs typically look like: https://sts.windows.net/{tenant-id}/
	return strings.HasPrefix(md.EntityID, "https://sts.windows.net/")
}

func (a *EntraAdapter) BuildFederationContext(md *model.MetadataDescriptor) (*model.FederationContext, error) {
	ctx := &model.FederationContext{
		ProviderName:        a.Info().Name,
		DetectedProvider:    a.Info().ID,
		DetectionConfidence: "HIGH",
		EntityID:            md.EntityID,
		SigningCertificates: md.Certificates,
		Capabilities:        md.Capabilities,
		SourceHash:          md.Hash,
		SigningPolicy: model.SigningPolicy{
			RequireSignedAssertion: true,
			SignAuthnRequests:      false, // Entra often doesn't require signed authn requests by default
		},
		TrustPolicy: model.TrustPolicy{
			EnforceCertificateExpiry: true,
			EnforceChainValidation:   false,
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
