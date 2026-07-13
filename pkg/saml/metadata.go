package saml

import (
	"encoding/xml"
	"fmt"
	"time"
)

// MetadataGenerator produces SAML 2.0 EntityDescriptor XML for the proxy IdP.
type MetadataGenerator struct {
	entityID    string
	ssoURL      string
	sloURL      string
	certBase64  string
}

// NewMetadataGenerator creates a metadata generator for the proxy IdP.
func NewMetadataGenerator(entityID, ssoURL, sloURL, certBase64 string) *MetadataGenerator {
	return &MetadataGenerator{
		entityID:   entityID,
		ssoURL:     ssoURL,
		sloURL:     sloURL,
		certBase64: certBase64,
	}
}

// GenerateIdPMetadata produces the XML EntityDescriptor for the proxy acting as an IdP.
func (g *MetadataGenerator) GenerateIdPMetadata() ([]byte, error) {
	metadata := entityDescriptor{
		XMLNS:    "urn:oasis:names:tc:SAML:2.0:metadata",
		DS:       "http://www.w3.org/2000/09/xmldsig#",
		EntityID: g.entityID,
		ValidUntil: time.Now().Add(365 * 24 * time.Hour).UTC().Format(timeFormat),
		IDPSSODescriptor: &idpSSODescriptor{
			ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
			WantAuthnRequestsSigned:    true,
			KeyDescriptors: []keyDescriptor{
				{
					Use: "signing",
					KeyInfo: keyInfo{
						X509Data: x509Data{
							X509Certificate: g.certBase64,
						},
					},
				},
			},
			NameIDFormats: []string{
				"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
				"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
				"urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
			},
			SingleSignOnServices: []singleSignOnService{
				{
					Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
					Location: g.ssoURL,
				},
				{
					Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
					Location: g.ssoURL,
				},
			},
		},
	}

	if g.sloURL != "" {
		metadata.IDPSSODescriptor.SingleLogoutServices = []singleLogoutService{
			{
				Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
				Location: g.sloURL,
			},
		}
	}

	output, err := xml.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshaling IdP metadata: %w", err)
	}

	return append([]byte(xml.Header), output...), nil
}

// GenerateSPMetadata produces the XML EntityDescriptor for the proxy acting as an SP
// to the upstream IdP.
func (g *MetadataGenerator) GenerateSPMetadata(acsURL string) ([]byte, error) {
	metadata := entityDescriptor{
		XMLNS:    "urn:oasis:names:tc:SAML:2.0:metadata",
		DS:       "http://www.w3.org/2000/09/xmldsig#",
		EntityID: g.entityID,
		ValidUntil: time.Now().Add(365 * 24 * time.Hour).UTC().Format(timeFormat),
		SPSSODescriptor: &spSSODescriptor{
			ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
			AuthnRequestsSigned:        true,
			WantAssertionsSigned:       true,
			KeyDescriptors: []keyDescriptor{
				{
					Use: "signing",
					KeyInfo: keyInfo{
						X509Data: x509Data{
							X509Certificate: g.certBase64,
						},
					},
				},
				{
					Use: "encryption",
					KeyInfo: keyInfo{
						X509Data: x509Data{
							X509Certificate: g.certBase64,
						},
					},
				},
			},
			NameIDFormats: []string{
				"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
			},
			AssertionConsumerServices: []assertionConsumerService{
				{
					Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
					Location: acsURL,
					Index:    0,
					IsDefault: true,
				},
			},
		},
	}

	output, err := xml.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshaling SP metadata: %w", err)
	}

	return append([]byte(xml.Header), output...), nil
}

// XML types for SAML metadata

type entityDescriptor struct {
	XMLName          xml.Name          `xml:"md:EntityDescriptor"`
	XMLNS            string            `xml:"xmlns:md,attr"`
	DS               string            `xml:"xmlns:ds,attr"`
	EntityID         string            `xml:"entityID,attr"`
	ValidUntil       string            `xml:"validUntil,attr,omitempty"`
	IDPSSODescriptor *idpSSODescriptor `xml:"md:IDPSSODescriptor,omitempty"`
	SPSSODescriptor  *spSSODescriptor  `xml:"md:SPSSODescriptor,omitempty"`
}

type idpSSODescriptor struct {
	ProtocolSupportEnumeration string               `xml:"protocolSupportEnumeration,attr"`
	WantAuthnRequestsSigned    bool                 `xml:"WantAuthnRequestsSigned,attr"`
	KeyDescriptors             []keyDescriptor      `xml:"md:KeyDescriptor"`
	NameIDFormats              []string             `xml:"md:NameIDFormat"`
	SingleSignOnServices       []singleSignOnService `xml:"md:SingleSignOnService"`
	SingleLogoutServices       []singleLogoutService `xml:"md:SingleLogoutService,omitempty"`
}

type spSSODescriptor struct {
	ProtocolSupportEnumeration string                    `xml:"protocolSupportEnumeration,attr"`
	AuthnRequestsSigned        bool                     `xml:"AuthnRequestsSigned,attr"`
	WantAssertionsSigned       bool                     `xml:"WantAssertionsSigned,attr"`
	KeyDescriptors             []keyDescriptor           `xml:"md:KeyDescriptor"`
	NameIDFormats              []string                  `xml:"md:NameIDFormat"`
	AssertionConsumerServices  []assertionConsumerService `xml:"md:AssertionConsumerService"`
}

type keyDescriptor struct {
	Use     string  `xml:"use,attr"`
	KeyInfo keyInfo `xml:"ds:KeyInfo"`
}

type keyInfo struct {
	X509Data x509Data `xml:"ds:X509Data"`
}

type x509Data struct {
	X509Certificate string `xml:"ds:X509Certificate"`
}

type singleSignOnService struct {
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
}

type singleLogoutService struct {
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
}

type assertionConsumerService struct {
	Binding   string `xml:"Binding,attr"`
	Location  string `xml:"Location,attr"`
	Index     int    `xml:"index,attr"`
	IsDefault bool   `xml:"isDefault,attr,omitempty"`
}
