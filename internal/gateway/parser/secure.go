package parser

import (
	"bytes"
	"encoding/xml"

	"github.com/crewjam/saml"
	"github.com/hidayat-SE/samlguard/internal/gateway/model"
)

type SecureCrewjamParser struct{}

func (p *SecureCrewjamParser) ParseAuthnRequest(rawXML []byte) (*model.ParseResult, error) {
	result := &model.ParseResult{
		Warnings:      []string{},
		SecurityEvents: []string{},
	}

	// 1. Safe basic structural decoding using standard xml decoding which prevents external entities by default
	// We ensure it is structurally valid XML before feeding it to crewjam
	decoder := xml.NewDecoder(bytes.NewReader(rawXML))
	decoder.Strict = true

	// To check for basic well-formedness, we can attempt a dummy unmarshal
	// In production, we could inspect tokens to ban DTDs.
	var testInterface interface{}
	if err := xml.Unmarshal(rawXML, &testInterface); err != nil {
		return nil, err
	}

	// 2. Parse using crewjam
	var authnRequest saml.AuthnRequest
	err := xml.Unmarshal(rawXML, &authnRequest)
	if err != nil {
		result.SecurityEvents = append(result.SecurityEvents, "Malformed AuthnRequest structure")
		return result, err
	}

	// 3. Map to RawAuthnRequest
	result.Request = &model.RawAuthnRequest{
		ID:           authnRequest.ID,
		Issuer:       authnRequest.Issuer.Value,
		IssueInstant: authnRequest.IssueInstant.String(),
		Destination:  authnRequest.Destination,
		AssertionURL: authnRequest.AssertionConsumerServiceURL,
		Protocol:     authnRequest.ProtocolBinding,
	}

	if authnRequest.ForceAuthn != nil {
		result.Request.ForceAuthn = *authnRequest.ForceAuthn
	}
	if authnRequest.IsPassive != nil {
		result.Request.IsPassive = *authnRequest.IsPassive
	}

	return result, nil
}
