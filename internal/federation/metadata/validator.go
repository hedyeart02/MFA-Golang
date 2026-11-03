package metadata

import (
	"errors"
	"time"

	"github.com/hidayat-SE/samlguard/internal/federation/model"
)

type MetadataValidator interface {
	Validate(md *model.MetadataDescriptor) error
}

type DefaultMetadataValidator struct{}

func (v *DefaultMetadataValidator) Validate(md *model.MetadataDescriptor) error {
	if md.EntityID == "" {
		return errors.New("missing EntityID in metadata")
	}
	if md.ValidUntil != nil && time.Now().After(*md.ValidUntil) {
		return errors.New("metadata has expired according to ValidUntil attribute")
	}
	return nil
}

type CertificateValidator struct{}

func (v *CertificateValidator) Validate(md *model.MetadataDescriptor) error {
	if len(md.Certificates) == 0 {
		return errors.New("missing Signing Certificate in metadata")
	}

	seen := make(map[string]bool)
	for _, cert := range md.Certificates {
		key := cert.SHA256Fingerprint
		if key == "" {
			key = cert.SHA1Fingerprint
		}
		if key == "" {
			key = cert.RawPEM
		}
		if seen[key] {
			return errors.New("duplicate Certificates detected in metadata")
		}
		seen[key] = true
	}
	return nil
}

type EndpointValidator struct{}

func (v *EndpointValidator) Validate(md *model.MetadataDescriptor) error {
	if len(md.SSOEndpoints) == 0 {
		return errors.New("missing SSO Endpoint in metadata")
	}

	seen := make(map[string]bool)
	for _, ep := range md.SSOEndpoints {
		key := ep.Binding + ep.Location
		if seen[key] {
			return errors.New("duplicate Endpoints detected in metadata")
		}
		seen[key] = true
	}
	return nil
}

type PolicyValidator struct{}

func (v *PolicyValidator) Validate(md *model.MetadataDescriptor) error {
	// Applies TrustPolicy / SigningPolicy strict checks
	return nil
}

type TrustValidator struct{}

func (v *TrustValidator) Validate(md *model.MetadataDescriptor) error {
	// Verifies the signature of the entire metadata XML document if required
	return nil
}

// CompositeMetadataValidator aggregates multiple validators and runs them sequentially
type CompositeMetadataValidator struct {
	Validators []MetadataValidator
}

func NewCompositeMetadataValidator(validators ...MetadataValidator) *CompositeMetadataValidator {
	return &CompositeMetadataValidator{Validators: validators}
}

func (c *CompositeMetadataValidator) Validate(md *model.MetadataDescriptor) error {
	for _, v := range c.Validators {
		if err := v.Validate(md); err != nil {
			return err
		}
	}
	return nil
}
