package metadata

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/crewjam/saml"
	"github.com/hidayat-SE/samlguard/internal/federation/model"
)

// MaxMetadataSize limits the incoming raw XML payload size to prevent unbounded memory allocation / DoS.
const MaxMetadataSize = 10 * 1024 * 1024 // 10MB

// SAMLMetadataNamespace defines the canonical SAML 2.0 metadata XML namespace.
const SAMLMetadataNamespace = "urn:oasis:names:tc:SAML:2.0:metadata"

// Parser parses XML bytes via crewjam/saml and strictly outputs native domain models.
// Crewjam types are completely isolated inside this parser package.
type Parser struct{}

// Parse strictly maps crewjam structures to SAMLGuard MetadataDescriptor.
// When encountering an EntitiesDescriptor, it deterministically selects the first entity
// containing an IDPSSODescriptor.
func (p *Parser) Parse(rawXML []byte) (*model.MetadataDescriptor, error) {
	return p.ParseEntity(rawXML, "")
}

// ParseEntity parses SAML metadata and selects a specific entity by its EntityID.
// If entityID is empty, it uses the deterministic fallback (first entity with IDPSSODescriptor).
func (p *Parser) ParseEntity(rawXML []byte, entityID string) (*model.MetadataDescriptor, error) {
	entityDescriptor, err := parseCrewjamEntityDescriptor(rawXML, entityID)
	if err != nil {
		return nil, err
	}

	descriptor := &model.MetadataDescriptor{}
	if err := convertEntityDescriptor(entityDescriptor, descriptor); err != nil {
		return nil, err
	}

	return descriptor, nil
}

// parseCrewjamEntityDescriptor safely decodes raw XML into a crewjam EntityDescriptor with security checks:
// 1. Rejects oversized payloads (>10MB).
// 2. Rejects empty or whitespace-only payloads.
// 3. Forbids XML DTD declarations (DOCTYPE).
// 4. Validates the root element and SAML metadata namespace.
// 5. Handles both <EntityDescriptor> and <EntitiesDescriptor> containers deterministically.
func parseCrewjamEntityDescriptor(rawXML []byte, targetEntityID string) (*saml.EntityDescriptor, error) {
	trimmed := bytes.TrimSpace(rawXML)
	if len(trimmed) == 0 {
		return nil, errors.New("metadata XML payload is empty")
	}
	if len(rawXML) > MaxMetadataSize {
		return nil, fmt.Errorf("metadata XML exceeds maximum allowed size of %d bytes", MaxMetadataSize)
	}

	// 1. Explicitly reject DTD declarations in the payload
	if bytes.Contains(bytes.ToUpper(trimmed), []byte("<!DOCTYPE")) {
		return nil, errors.New("XML DTD declarations are strictly forbidden in SAML metadata")
	}

	// 2. Inspect root token for security, DTD directives, root element name, and namespace
	reader := io.LimitReader(bytes.NewReader(rawXML), int64(MaxMetadataSize))
	decoder := xml.NewDecoder(reader)

	var rootStart *xml.StartElement
	for {
		token, err := decoder.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil, errors.New("unexpected end of XML before root element")
			}
			return nil, fmt.Errorf("malformed XML: %w", err)
		}

		if directive, ok := token.(xml.Directive); ok {
			dirUpper := bytes.ToUpper(bytes.TrimSpace(directive))
			if bytes.HasPrefix(dirUpper, []byte("DOCTYPE")) {
				return nil, errors.New("XML DTD declarations are strictly forbidden in SAML metadata")
			}
		}

		if startElem, ok := token.(xml.StartElement); ok {
			rootStart = &startElem
			break
		}
	}

	if rootStart == nil {
		return nil, errors.New("no root XML element found in metadata")
	}

	// Validate SAML metadata namespace
	if rootStart.Name.Space != SAMLMetadataNamespace {
		return nil, fmt.Errorf("invalid or missing SAML metadata XML namespace %q; expected %q", rootStart.Name.Space, SAMLMetadataNamespace)
	}

	// Validate root element name
	switch rootStart.Name.Local {
	case "EntityDescriptor":
		var entity saml.EntityDescriptor
		readerEntity := io.LimitReader(bytes.NewReader(rawXML), int64(MaxMetadataSize))
		decEntity := xml.NewDecoder(readerEntity)
		if err := decEntity.Decode(&entity); err != nil {
			return nil, fmt.Errorf("failed to parse EntityDescriptor XML: %w", err)
		}
		if targetEntityID != "" && entity.EntityID != targetEntityID {
			return nil, fmt.Errorf("entity ID mismatch: expected %q, got %q", targetEntityID, entity.EntityID)
		}
		return &entity, nil

	case "EntitiesDescriptor":
		var entities saml.EntitiesDescriptor
		readerEntities := io.LimitReader(bytes.NewReader(rawXML), int64(MaxMetadataSize))
		decEntities := xml.NewDecoder(readerEntities)
		if err := decEntities.Decode(&entities); err != nil {
			return nil, fmt.Errorf("failed to parse EntitiesDescriptor XML: %w", err)
		}

		if len(entities.EntityDescriptors) == 0 {
			return nil, errors.New("EntitiesDescriptor contains no EntityDescriptor children")
		}

		// If a specific entity ID was requested, search for it
		if targetEntityID != "" {
			for i, ed := range entities.EntityDescriptors {
				if ed.EntityID == targetEntityID {
					return &entities.EntityDescriptors[i], nil
				}
			}
			return nil, fmt.Errorf("entity ID %q not found in EntitiesDescriptor", targetEntityID)
		}

		// Deterministic selection strategy:
		// 1. Select the first entity with an IDPSSODescriptor
		for i, ed := range entities.EntityDescriptors {
			if len(ed.IDPSSODescriptors) > 0 {
				return &entities.EntityDescriptors[i], nil
			}
		}
		// 2. Fall back to the first EntityDescriptor in the container
		return &entities.EntityDescriptors[0], nil

	default:
		return nil, fmt.Errorf("unsupported or unexpected root element <%s>; expected <EntityDescriptor> or <EntitiesDescriptor>", rootStart.Name.Local)
	}
}

// convertEntityDescriptor maps crewjam SAML structures into the native SAMLGuard model.MetadataDescriptor
func convertEntityDescriptor(ed *saml.EntityDescriptor, md *model.MetadataDescriptor) error {
	if ed == nil || md == nil {
		return errors.New("descriptor cannot be nil")
	}

	md.EntityID = ed.EntityID

	if !ed.ValidUntil.IsZero() {
		validUntil := ed.ValidUntil
		md.ValidUntil = &validUntil
	}
	if ed.CacheDuration != 0 {
		md.CacheDuration = ed.CacheDuration
	}

	for _, idp := range ed.IDPSSODescriptors {
		// SSO Endpoints
		for _, sso := range idp.SingleSignOnServices {
			md.SSOEndpoints = append(md.SSOEndpoints, model.Endpoint{
				Binding:  sso.Binding,
				Location: sso.Location,
				Response: sso.ResponseLocation,
			})
		}

		// SLO Endpoints
		for _, slo := range idp.SingleLogoutServices {
			md.SLOEndpoints = append(md.SLOEndpoints, model.Endpoint{
				Binding:  slo.Binding,
				Location: slo.Location,
				Response: slo.ResponseLocation,
			})
		}

		// KeyDescriptors / Certificates (Strict parsing)
		for _, kd := range idp.KeyDescriptors {
			use := kd.Use
			if use == "" {
				use = "signing"
			}
			for _, x509Cert := range kd.KeyInfo.X509Data.X509Certificates {
				certData := strings.TrimSpace(x509Cert.Data)
				if certData == "" {
					continue
				}
				certDesc, err := extractCertificateDescriptor(certData, use)
				if err != nil {
					return fmt.Errorf("failed to extract certificate for key descriptor (use=%s): %w", use, err)
				}
				md.Certificates = append(md.Certificates, *certDesc)
			}
		}

		// Capabilities
		for _, f := range idp.NameIDFormats {
			md.Capabilities.SupportedNameIDFormat = append(md.Capabilities.SupportedNameIDFormat, string(f))
		}
		if idp.WantAuthnRequestsSigned != nil && *idp.WantAuthnRequestsSigned {
			md.Capabilities.RequiresSignedAuthn = true
		}
		if len(idp.SingleLogoutServices) > 0 {
			md.Capabilities.SupportsLogout = true
		}
		if len(idp.ArtifactResolutionServices) > 0 {
			md.Capabilities.SupportsArtifact = true
		}
	}

	// Organization
	if ed.Organization != nil {
		md.Organization = &model.Organization{}
		if len(ed.Organization.OrganizationNames) > 0 {
			md.Organization.Name = ed.Organization.OrganizationNames[0].Value
		}
		if len(ed.Organization.OrganizationDisplayNames) > 0 {
			md.Organization.DisplayName = ed.Organization.OrganizationDisplayNames[0].Value
		}
		if len(ed.Organization.OrganizationURLs) > 0 {
			md.Organization.URL = ed.Organization.OrganizationURLs[0].Value
		}
	}

	// ContactPerson
	if ed.ContactPerson != nil {
		email := ""
		if len(ed.ContactPerson.EmailAddresses) > 0 {
			email = ed.ContactPerson.EmailAddresses[0]
		}
		md.Contacts = append(md.Contacts, model.Contact{
			Type:         ed.ContactPerson.ContactType,
			GivenName:    ed.ContactPerson.GivenName,
			EmailAddress: email,
		})
	}

	return nil
}

// extractCertificateDescriptor strictly decodes Base64, parses X.509 DER bytes, and computes fingerprints.
// It rejects malformed Base64 and invalid DER/X.509 certificates.
func extractCertificateDescriptor(certData string, use string) (*model.CertificateDescriptor, error) {
	clean := strings.TrimSpace(certData)
	if clean == "" {
		return nil, errors.New("empty certificate data")
	}

	// Strip any whitespace or newlines commonly found in XML Base64 text
	stripped := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
			return -1
		}
		return r
	}, clean)

	derBytes, err := base64.StdEncoding.DecodeString(stripped)
	if err != nil {
		return nil, fmt.Errorf("malformed base64 certificate data: %w", err)
	}
	if len(derBytes) == 0 {
		return nil, errors.New("decoded certificate byte slice is empty")
	}

	// Strict X.509 certificate parsing
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, fmt.Errorf("malformed DER/X.509 certificate: %w", err)
	}

	// Fingerprints generated strictly from validated DER bytes
	h256 := sha256.Sum256(cert.Raw)
	h1 := sha1.Sum(cert.Raw)
	sha256Hex := hex.EncodeToString(h256[:])
	sha1Hex := hex.EncodeToString(h1[:])

	subject := cert.Subject.CommonName
	if subject == "" {
		subject = cert.Subject.String()
	}
	issuer := cert.Issuer.CommonName
	if issuer == "" {
		issuer = cert.Issuer.String()
	}

	return &model.CertificateDescriptor{
		Use:               use,
		RawPEM:            clean,
		SHA1Fingerprint:   sha1Hex,
		SHA256Fingerprint: sha256Hex,
		Subject:           subject,
		Issuer:            issuer,
		NotBefore:         cert.NotBefore,
		NotAfter:          cert.NotAfter,
		Trust:             model.TrustStatusUnknown, // Explicitly separate parsing from trust validation
	}, nil
}
