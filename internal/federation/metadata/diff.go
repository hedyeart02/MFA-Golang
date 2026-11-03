package metadata

import (
	"github.com/hidayat-SE/samlguard/internal/federation/model"
)

// DiffResult describes the changes detected between two metadata versions
type DiffResult struct {
	EntityIDChanged      bool
	CertificateChanged   bool
	EndpointChanged      bool
	SignatureAlgoChanged bool
	ValidUntilChanged    bool
	CacheDurationChanged bool
	NameIDFormatChanged  bool
	OrganizationChanged  bool
	ContactChanged       bool
	Differences          []string
}

// DiffEngine compares two normalized MetadataDescriptors to detect underlying IdP alterations
type DiffEngine struct{}

func (e *DiffEngine) Compare(old, new *model.MetadataDescriptor) *DiffResult {
	if old == nil || new == nil {
		return nil
	}

	res := &DiffResult{}

	// EntityID
	if old.EntityID != new.EntityID {
		res.EntityIDChanged = true
		res.Differences = append(res.Differences, "EntityID changed")
	}

	// Endpoints (SSO): Compare meaningful fields (Binding, Location, Response) deterministically
	if !endpointsEqual(old.SSOEndpoints, new.SSOEndpoints) {
		res.EndpointChanged = true
		if len(old.SSOEndpoints) != len(new.SSOEndpoints) {
			res.Differences = append(res.Differences, "SSO Endpoints count changed")
		} else {
			res.Differences = append(res.Differences, "SSO Endpoints modified")
		}
	}

	// Endpoints (SLO): Compare meaningful fields deterministically
	if !endpointsEqual(old.SLOEndpoints, new.SLOEndpoints) {
		res.EndpointChanged = true
		if len(old.SLOEndpoints) != len(new.SLOEndpoints) {
			res.Differences = append(res.Differences, "SLO Endpoints count changed")
		} else {
			res.Differences = append(res.Differences, "SLO Endpoints modified")
		}
	}

	// Certificates
	if len(old.Certificates) != len(new.Certificates) {
		res.CertificateChanged = true
		res.Differences = append(res.Differences, "Certificates count changed")
	} else {
		// Deep fingerprint comparison using SHA256Fingerprint as primary identity
		for i, cert := range old.Certificates {
			if cert.SHA256Fingerprint != new.Certificates[i].SHA256Fingerprint {
				res.CertificateChanged = true
				res.Differences = append(res.Differences, "Certificate fingerprint mismatch")
				break
			}
		}
	}

	// Capabilities
	if old.Capabilities.RequiresSignedAuthn != new.Capabilities.RequiresSignedAuthn {
		res.SignatureAlgoChanged = true
		res.Differences = append(res.Differences, "Signature requirements changed")
	}

	// ValidUntil
	if (old.ValidUntil == nil && new.ValidUntil != nil) || (old.ValidUntil != nil && new.ValidUntil == nil) {
		res.ValidUntilChanged = true
		res.Differences = append(res.Differences, "ValidUntil presence changed")
	} else if old.ValidUntil != nil && new.ValidUntil != nil && !old.ValidUntil.Equal(*new.ValidUntil) {
		res.ValidUntilChanged = true
		res.Differences = append(res.Differences, "ValidUntil value changed")
	}

	// CacheDuration
	if old.CacheDuration != new.CacheDuration {
		res.CacheDurationChanged = true
		res.Differences = append(res.Differences, "CacheDuration changed")
	}

	// NameIDFormat
	if len(old.Capabilities.SupportedNameIDFormat) != len(new.Capabilities.SupportedNameIDFormat) {
		res.NameIDFormatChanged = true
		res.Differences = append(res.Differences, "NameIDFormat count changed")
	}

	// Organization
	if (old.Organization == nil && new.Organization != nil) || (old.Organization != nil && new.Organization == nil) {
		res.OrganizationChanged = true
		res.Differences = append(res.Differences, "Organization presence changed")
	} else if old.Organization != nil && new.Organization != nil {
		if old.Organization.Name != new.Organization.Name || old.Organization.URL != new.Organization.URL {
			res.OrganizationChanged = true
			res.Differences = append(res.Differences, "Organization details changed")
		}
	}

	// Contacts
	if len(old.Contacts) != len(new.Contacts) {
		res.ContactChanged = true
		res.Differences = append(res.Differences, "Contact count changed")
	}

	return res
}

// endpointsEqual deterministically compares two endpoint slices regardless of element order.
// It checks Binding, Location, and Response.
func endpointsEqual(a, b []model.Endpoint) bool {
	if len(a) != len(b) {
		return false
	}
	counts := make(map[string]int, len(a))
	for _, ep := range a {
		key := ep.Binding + "::" + ep.Location + "::" + ep.Response
		counts[key]++
	}
	for _, ep := range b {
		key := ep.Binding + "::" + ep.Location + "::" + ep.Response
		counts[key]--
		if counts[key] < 0 {
			return false
		}
	}
	for _, count := range counts {
		if count != 0 {
			return false
		}
	}
	return true
}
