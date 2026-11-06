package gateway

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"github.com/hidayat-SE/samlguard/internal/config"
	goxmldsig "github.com/russellhaering/goxmldsig"
)

func TestSAMLResponseGenerator(t *testing.T) {
	cfg := &config.Config{
		SAML: config.SAMLConfig{
			EntityID:             "https://192.168.0.178:18080",
			ACSURL:               "https://192.168.0.119/api/current/authentication/saml2-callback",
			CertFile:             "../../cert/saml-signing.crt",
			KeyFile:              "../../cert/saml-signing.key",
			AuthnContextClassRef: "urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken",
			GroupMapping: map[string]string{
				"upstream-admins": "Admin",
				"upstream-users":  "Operator",
			},
			DefaultGroups: []string{}, // Must be empty
		},
	}

	gen, err := NewResponseGenerator(cfg)
	if err != nil {
		t.Fatalf("failed to create response generator: %v", err)
	}

	req := SAMLResponseRequest{
		InResponseTo:        "ITA-REQ-98765",
		Destination:         "https://192.168.0.119/api/current/authentication/saml2-callback",
		RelayState:          "custom-relay-state-value",
		Audience:            "https://192.168.0.119",
		Issuer:              "https://192.168.0.178:18080",
		SubjectNameID:       "apc-admin-user",
		SubjectNameIDFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
		Email:               "apc@example.com",
		DisplayName:         "APC Administrator",
		RawGroups:           []string{"upstream-admins", "unmapped-group"},
	}

	res, err := gen.GenerateResponse(req)
	if err != nil {
		t.Fatalf("GenerateResponse failed: %v", err)
	}

	if res.RelayState != req.RelayState {
		t.Errorf("expected RelayState %s, got %s", req.RelayState, res.RelayState)
	}
	if res.Destination != req.Destination {
		t.Errorf("expected Destination %s, got %s", req.Destination, res.Destination)
	}

	// Decode Base64 SAMLResponse
	xmlBytes, err := base64.StdEncoding.DecodeString(res.SAMLResponse)
	if err != nil {
		t.Fatalf("failed to decode SAMLResponse base64: %v", err)
	}
	xmlStr := string(xmlBytes)

	// Verify required elements and attributes
	if !strings.Contains(xmlStr, `InResponseTo="ITA-REQ-98765"`) {
		t.Error("missing InResponseTo attribute in SAML response")
	}
	if !strings.Contains(xmlStr, `Destination="https://192.168.0.119/api/current/authentication/saml2-callback"`) {
		t.Error("missing Destination attribute in SAML response")
	}
	if !strings.Contains(xmlStr, `<saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">apc-admin-user</saml:NameID>`) {
		t.Error("missing or incorrect Subject NameID")
	}
	if !strings.Contains(xmlStr, `urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken`) {
		t.Error("missing or incorrect AuthnContextClassRef")
	}
	if !strings.Contains(xmlStr, `ds:Signature`) {
		t.Error("missing XMLDSig digital signature")
	}

	// Verify group mapping (Admin from upstream-admins, unmapped-group discarded)
	if !strings.Contains(xmlStr, `<saml:AttributeValue>Admin</saml:AttributeValue>`) {
		t.Error("expected mapped Admin group to be present")
	}
	if strings.Contains(xmlStr, `unmapped-group`) {
		t.Error("unmapped group should not be included without explicit mapping")
	}
}

func TestSAMLResponseNoDefaultAdminGroup(t *testing.T) {
	cfg := &config.Config{
		SAML: config.SAMLConfig{
			EntityID:      "https://192.168.0.178:18080",
			ACSURL:        "https://192.168.0.119/api/current/authentication/saml2-callback",
			CertFile:      "../../cert/saml-signing.crt",
			KeyFile:       "../../cert/saml-signing.key",
			GroupMapping:  map[string]string{},
			DefaultGroups: []string{}, // No defaults
		},
	}

	gen, err := NewResponseGenerator(cfg)
	if err != nil {
		t.Fatalf("failed to create response generator: %v", err)
	}

	req := SAMLResponseRequest{
		InResponseTo:  "ITA-REQ-12345",
		SubjectNameID: "regular-user",
		RawGroups:     []string{"some-random-group"},
	}

	res, err := gen.GenerateResponse(req)
	if err != nil {
		t.Fatalf("GenerateResponse failed: %v", err)
	}

	xmlBytes, _ := base64.StdEncoding.DecodeString(res.SAMLResponse)
	xmlStr := string(xmlBytes)

	// Admin must NEVER be present by default!
	if strings.Contains(xmlStr, `Admin`) {
		t.Fatal("security violation: Admin group was granted when not mapped!")
	}
}

func TestSAMLResponse_IndependentXMLDSigVerification(t *testing.T) {
	certFile := "../../cert/saml-signing.crt"
	keyFile := "../../cert/saml-signing.key"

	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatalf("failed to read cert file: %v", err)
	}
	pBlock, _ := pem.Decode(certPEM)
	if pBlock == nil {
		t.Fatal("failed to decode pem")
	}
	parsedCert, err := x509.ParseCertificate(pBlock.Bytes)
	if err != nil {
		t.Fatalf("failed to parse x509 certificate: %v", err)
	}

	cfg := &config.Config{
		SAML: config.SAMLConfig{
			EntityID:             "https://192.168.0.178:18080",
			ACSURL:               "https://192.168.0.119/api/current/authentication/saml2-callback",
			CertFile:             certFile,
			KeyFile:              keyFile,
			AuthnContextClassRef: "urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken",
			GroupMapping: map[string]string{
				"admins": "Admin",
			},
		},
	}

	gen, err := NewResponseGenerator(cfg)
	if err != nil {
		t.Fatalf("failed to create response generator: %v", err)
	}

	req := SAMLResponseRequest{
		InResponseTo:        "ITA-CORR-12345",
		Destination:         "https://192.168.0.119/api/current/authentication/saml2-callback",
		Audience:            "https://192.168.0.119",
		Issuer:              "https://192.168.0.178:18080",
		SubjectNameID:       "apc-legit-user",
		SubjectNameIDFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
		Email:               "apc@example.com",
		DisplayName:         "APC Administrator",
		RawGroups:           []string{"admins"},
	}

	res, err := gen.GenerateResponse(req)
	if err != nil {
		t.Fatalf("GenerateResponse failed: %v", err)
	}

	xmlBytes, err := base64.StdEncoding.DecodeString(res.SAMLResponse)
	if err != nil {
		t.Fatalf("failed to decode base64: %v", err)
	}

	// 1. Independent XMLDSig Validation using W3C Exclusive C14N
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlBytes); err != nil {
		t.Fatalf("failed to parse xml: %v", err)
	}

	assertionEl := doc.FindElement("//Assertion")
	if assertionEl == nil {
		t.Fatal("Assertion element not found in response")
	}

	certStore := &goxmldsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{parsedCert},
	}
	valCtx := goxmldsig.NewDefaultValidationContext(certStore)

	validatedEl, err := valCtx.Validate(assertionEl)
	if err != nil {
		t.Fatalf("independent XMLDSig validation failed on untampered assertion: %v", err)
	}
	if validatedEl == nil {
		t.Fatal("validated assertion element is nil")
	}

	// 2. Tampering Test: modify Subject NameID in XML -> must fail signature validation!
	tamperedXMLStr := strings.Replace(string(xmlBytes), "apc-legit-user", "hacker-tampered-user", 1)
	tamperedDoc := etree.NewDocument()
	if err := tamperedDoc.ReadFromString(tamperedXMLStr); err != nil {
		t.Fatalf("failed to read tampered doc: %v", err)
	}
	tamperedAssertionEl := tamperedDoc.FindElement("//Assertion")
	_, err = valCtx.Validate(tamperedAssertionEl)
	if err == nil {
		t.Fatal("SECURITY ERROR: signature validation PASSED on tampered assertion!")
	}

	// 3. Tampering Test: modify group claim in XML -> must fail signature validation!
	tamperedGroupXML := strings.Replace(string(xmlBytes), "<saml:AttributeValue>Admin</saml:AttributeValue>", "<saml:AttributeValue>SuperAdmin</saml:AttributeValue>", 1)
	tamperedGroupDoc := etree.NewDocument()
	if err := tamperedGroupDoc.ReadFromString(tamperedGroupXML); err != nil {
		t.Fatalf("failed to read tampered group doc: %v", err)
	}
	tamperedGroupAssertionEl := tamperedGroupDoc.FindElement("//Assertion")
	_, err = valCtx.Validate(tamperedGroupAssertionEl)
	if err == nil {
		t.Fatal("SECURITY ERROR: signature validation PASSED on tampered group assertion!")
	}
}
