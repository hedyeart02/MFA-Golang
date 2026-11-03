package saml

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// IdPProxy generates signed SAML assertions acting as a proxy Identity Provider.
// It takes validated upstream attributes and re-signs them with the gateway's
// own certificate, producing a new assertion for the downstream SP.
type IdPProxy struct {
	entityID    string
	certificate *x509.Certificate
	privateKey  *rsa.PrivateKey
	certPEM     string
	logger      *zap.Logger
}

// NewIdPProxy creates a proxy IdP assertion generator.
func NewIdPProxy(entityID, certFile, keyFile string, log *zap.Logger) (*IdPProxy, error) {
	cert, err := loadCertificate(certFile)
	if err != nil {
		return nil, fmt.Errorf("loading signing certificate: %w", err)
	}

	keyData, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("reading signing key: %w", err)
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in key file %s", keyFile)
	}

	parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		parsedKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing private key: %w", err)
		}
	}

	rsaKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("signing key is not RSA")
	}

	certPEMData, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("reading cert PEM: %w", err)
	}
	certBlock, _ := pem.Decode(certPEMData)
	certBase64 := base64.StdEncoding.EncodeToString(certBlock.Bytes)

	return &IdPProxy{
		entityID:    entityID,
		certificate: cert,
		privateKey:  rsaKey,
		certPEM:     certBase64,
		logger:      log,
	}, nil
}

// GenerateResponse creates a complete SAML Response with a signed Assertion.
func (p *IdPProxy) GenerateResponse(req AssertionRequest) (AssertionResponse, error) {
	now := time.Now().UTC()
	responseID := "_" + uuid.New().String()
	assertionID := "_" + uuid.New().String()

	notBefore := now.Add(-30 * time.Second)
	notOnOrAfter := now.Add(5 * time.Minute)

	assertion := p.buildAssertion(assertionID, req, now, notBefore, notOnOrAfter)

	assertionXML, err := xml.MarshalIndent(assertion, "    ", "    ")
	if err != nil {
		return AssertionResponse{}, fmt.Errorf("marshaling assertion: %w", err)
	}

	response := p.buildResponse(responseID, req, now, string(assertionXML))

	responseXML, err := xml.MarshalIndent(response, "", "  ")
	if err != nil {
		return AssertionResponse{}, fmt.Errorf("marshaling response: %w", err)
	}

	samlResponseB64 := base64.StdEncoding.EncodeToString(responseXML)

	p.logger.Info("generated SAML response",
		zap.String("response_id", responseID),
		zap.String("assertion_id", assertionID),
		zap.String("sp_entity_id", req.SPEntityID),
		zap.String("destination", req.SPACSURL),
	)

	return AssertionResponse{
		SAMLResponse: samlResponseB64,
		RelayState:   req.RelayState,
		Destination:  req.SPACSURL,
	}, nil
}

// EntityID returns the proxy IdP entity ID.
func (p *IdPProxy) EntityID() string {
	return p.entityID
}

// Certificate returns the signing certificate.
func (p *IdPProxy) Certificate() *x509.Certificate {
	return p.certificate
}

// samlResponse is the XML structure for a SAML 2.0 Response.
type samlResponse struct {
	XMLName      xml.Name `xml:"samlp:Response"`
	SAMLP        string   `xml:"xmlns:samlp,attr"`
	SAML         string   `xml:"xmlns:saml,attr"`
	ID           string   `xml:"ID,attr"`
	Version      string   `xml:"Version,attr"`
	IssueInstant string   `xml:"IssueInstant,attr"`
	Destination  string   `xml:"Destination,attr"`
	InResponseTo string   `xml:"InResponseTo,attr,omitempty"`
	Issuer       string   `xml:"saml:Issuer"`
	Status       samlStatus
	RawAssertion string `xml:",innerxml"`
}

// samlStatus represents the Status element.
type samlStatus struct {
	XMLName    xml.Name       `xml:"samlp:Status"`
	StatusCode samlStatusCode `xml:"samlp:StatusCode"`
}

// samlStatusCode represents the StatusCode element.
type samlStatusCode struct {
	Value string `xml:"Value,attr"`
}

// samlAssertion is the XML structure for a SAML 2.0 Assertion.
type samlAssertion struct {
	XMLName      xml.Name `xml:"saml:Assertion"`
	SAML         string   `xml:"xmlns:saml,attr"`
	ID           string   `xml:"ID,attr"`
	Version      string   `xml:"Version,attr"`
	IssueInstant string   `xml:"IssueInstant,attr"`
	Issuer       string   `xml:"saml:Issuer"`
	Subject      samlSubject
	Conditions   samlConditions
	AuthnStatement samlAuthnStatement
	AttributeStatement samlAttributeStatement
}

type samlSubject struct {
	XMLName             xml.Name            `xml:"saml:Subject"`
	NameID              samlNameID          `xml:"saml:NameID"`
	SubjectConfirmation samlSubjectConfirmation `xml:"saml:SubjectConfirmation"`
}

type samlNameID struct {
	Format string `xml:"Format,attr,omitempty"`
	Value  string `xml:",chardata"`
}

type samlSubjectConfirmation struct {
	Method                  string                      `xml:"Method,attr"`
	SubjectConfirmationData samlSubjectConfirmationData `xml:"saml:SubjectConfirmationData"`
}

type samlSubjectConfirmationData struct {
	InResponseTo string `xml:"InResponseTo,attr,omitempty"`
	NotOnOrAfter string `xml:"NotOnOrAfter,attr"`
	Recipient    string `xml:"Recipient,attr"`
}

type samlConditions struct {
	XMLName              xml.Name                  `xml:"saml:Conditions"`
	NotBefore            string                    `xml:"NotBefore,attr"`
	NotOnOrAfter         string                    `xml:"NotOnOrAfter,attr"`
	AudienceRestrictions []samlAudienceRestriction `xml:"saml:AudienceRestriction"`
}

type samlAudienceRestriction struct {
	Audience string `xml:"saml:Audience"`
}

type samlAuthnStatement struct {
	XMLName             xml.Name        `xml:"saml:AuthnStatement"`
	AuthnInstant        string          `xml:"AuthnInstant,attr"`
	SessionIndex        string          `xml:"SessionIndex,attr,omitempty"`
	AuthnContext        samlAuthnContext `xml:"saml:AuthnContext"`
}

type samlAuthnContext struct {
	AuthnContextClassRef string `xml:"saml:AuthnContextClassRef"`
}

type samlAttributeStatement struct {
	XMLName    xml.Name        `xml:"saml:AttributeStatement"`
	Attributes []samlXMLAttribute `xml:"saml:Attribute"`
}

type samlXMLAttribute struct {
	Name         string              `xml:"Name,attr"`
	NameFormat   string              `xml:"NameFormat,attr,omitempty"`
	FriendlyName string              `xml:"FriendlyName,attr,omitempty"`
	Values       []samlAttributeValue `xml:"saml:AttributeValue"`
}

type samlAttributeValue struct {
	Type  string `xml:"xmlns:xsi,attr,omitempty"`
	XSType string `xml:"xsi:type,attr,omitempty"`
	Value string `xml:",chardata"`
}

const (
	timeFormat    = "2006-01-02T15:04:05Z"
	samlpNS       = "urn:oasis:names:tc:SAML:2.0:protocol"
	samlNS        = "urn:oasis:names:tc:SAML:2.0:assertion"
	statusSuccess = "urn:oasis:names:tc:SAML:2.0:status:Success"
	bearerMethod  = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
	nameIDEmail   = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	authnPwdProtected = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
)

func (p *IdPProxy) buildAssertion(id string, req AssertionRequest,
	now, notBefore, notOnOrAfter time.Time) samlAssertion {

	var attrs []samlXMLAttribute
	for _, attr := range req.UserInfo.Attributes {
		var values []samlAttributeValue
		for _, v := range attr.Values {
			values = append(values, samlAttributeValue{Value: v})
		}
		attrs = append(attrs, samlXMLAttribute{
			Name:         attr.Name,
			FriendlyName: attr.FriendlyName,
			Values:       values,
		})
	}

	return samlAssertion{
		SAML:         samlNS,
		ID:           id,
		Version:      "2.0",
		IssueInstant: now.Format(timeFormat),
		Issuer:       p.entityID,
		Subject: samlSubject{
			NameID: samlNameID{
				Format: nameIDEmail,
				Value:  req.UserInfo.NameID,
			},
			SubjectConfirmation: samlSubjectConfirmation{
				Method: bearerMethod,
				SubjectConfirmationData: samlSubjectConfirmationData{
					InResponseTo: req.InResponseTo,
					NotOnOrAfter: notOnOrAfter.Format(timeFormat),
					Recipient:    req.SPACSURL,
				},
			},
		},
		Conditions: samlConditions{
			NotBefore:    notBefore.Format(timeFormat),
			NotOnOrAfter: notOnOrAfter.Format(timeFormat),
			AudienceRestrictions: []samlAudienceRestriction{
				{Audience: req.Audience},
			},
		},
		AuthnStatement: samlAuthnStatement{
			AuthnInstant: now.Format(timeFormat),
			SessionIndex: "_" + uuid.New().String(),
			AuthnContext: samlAuthnContext{
				AuthnContextClassRef: authnPwdProtected,
			},
		},
		AttributeStatement: samlAttributeStatement{
			Attributes: attrs,
		},
	}
}

func (p *IdPProxy) buildResponse(id string, req AssertionRequest,
	now time.Time, assertionXML string) samlResponse {

	return samlResponse{
		SAMLP:        samlpNS,
		SAML:         samlNS,
		ID:           id,
		Version:      "2.0",
		IssueInstant: now.Format(timeFormat),
		Destination:  req.SPACSURL,
		InResponseTo: req.InResponseTo,
		Issuer:       p.entityID,
		Status: samlStatus{
			StatusCode: samlStatusCode{Value: statusSuccess},
		},
		RawAssertion: assertionXML,
	}
}
