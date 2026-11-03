package metadata

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hidayat-SE/samlguard/internal/federation/model"
)

const (
	// Valid self-signed X.509 cert 1 (from cert/saml-signing.crt)
	validCert1Base64 = "MIIDXDCCAkSgAwIBAgIRAIpW32w8iqAmcNEa8CSRPjgwDQYJKoZIhvcNAQELBQAwPTELMAkGA1UEBhMCVVMxEjAQBgNVBAoTCVNBTUxHdWFyZDEaMBgGA1UEAxMRU0FNTEd1YXJkIFNpZ25pbmcwHhcNMjYwNzEyMDk0ODMxWhcNMjcwNzEyMDk0ODMxWjA9MQswCQYDVQQGEwJVUzESMBAGA1UEChMJU0FNTEd1YXJkMRowGAYDVQQDExFTQU1MR3VhcmQgU2lnbmluZzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANeKdrNvXAFcP+x3ium+CXBDkz5jGAXvAXaIVLFulUtYCh50uieJRRhTt/ugtb1WP3JKW5hX2r8yQAPkijop3z0RxVL+QTenTZ0EadUlculfBhtkGWnObGOdX7B6O9XWu82BYlrxXVhMXwS2/cHtrRcjGDbkWcZ63vQ7W2yZ4VtYe3IsLaKByMjYVw89wRWZTTaUFAJhJjpxqV8XmyeC1NJg7xTeBcQoWu+9VmT/AjVjPnHNafxEHaN9YSCZrFuyp4dVG4Ukay9tKbT49mSoHbefBKAB/BJNTbCgr+Pn9L/d8XvVEoWp+6VJ579iLh1lWEF02sfFlkC3m24C0Gijg1ECAwEAAaNXMFUwDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAwIAYDVR0RBBkwF4IVc2FtbGd1YXJkLmV4YW1wbGUuY29tMA0GCSqGSIb3DQEBCwUAA4IBAQBnoqlsQhCt6mVrzgTBfWzCGsOjy/cfJnhhiBeusFoSlRWhIoytGW/F8lDQxvi0U96hFAh6+iTkRZnFSE/tBtkPBg4Ad2AvIwSx8VtnSr0BFDzB9y71pm/REGcmztzuiywgk+UjCqYew3YgqNLXgwrNnyAjSDKi7a2V6YqccGyq0ErFawBGCnHS/24NlD1DuEooJJXtptbf3aSnL67nKDB3fsavz6CSWdZ76G3Yyu0HJUOSHGoiI69reDWjSzcWz8ARNydu6DLJrc2t1FgMUG+Tos/iDW63recRC/XSOr+blAFB2mX1grtuBUDpVcsL7u027lnC5Ob+ajcJQv4i1eqv"

	// Valid self-signed X.509 cert 2 (from cert/server.crt)
	validCert2Base64 = "MIIDdDCCAlygAwIBAgIQXMkLw77V0wi3Da0GSK2+4jANBgkqhkiG9w0BAQsFADBBMQswCQYDVQQGEwJVUzESMBAGA1UEChMJU0FNTEd1YXJkMR4wHAYDVQQDExVzYW1sZ3VhcmQuZXhhbXBsZS5jb20wHhcNMjYwNzEyMDk0ODMyWhcNMjcwNzEyMDk0ODMyWjBBMQswCQYDVQQGEwJVUzESMBAGA1UEChMJU0FNTEd1YXJkMR4wHAYDVQQDExVzYW1sZ3VhcmQuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDQljcc+QG5NDiF2IlrKKGLELUeTOjGPt9DnSAY6iH7E37xO3qxRGOPp+QuzF3tl8lkeXWBetP/cXx+Vc9NA1dqFsBmVQgLMK0Nd5jwjAVPKXv6/aULEZpKnHnLw4sr7a9V3SxSWdxZRuYSmNOnStvPyJIoDad8uTHGJ1RCUuL0ahdvQCMDSM1dpWewU/ELQtHibEqu8JpiWcUu3oxiOErq7w1NLYENeT1MGCDIUBXkjVXodHAqN8ooPOHKdgFxWKsab2U5A7e80Ybvr849tjMgrH4OnVCYXsaPXuvhxlFB7u+QhO8FDn2IXxyA6mt+rKIp8ZxagUH0MrjmpIv2tl2dAgMBAAGjaDBmMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMDEGA1UdEQQqMCiCFXNhbWxndWFyZC5leGFtcGxlLmNvbYIJbG9jYWxob3N0hwR/AAABMA0GCSqGSIb3DQEBCwUAA4IBAQBecikBujh8c7HpQNoXgSp+Qu7JB/Ik+VAHpzVwE8Iy3XVTcFA3EloEuUp6/fOP30bL+T6LkgxePsCop6woV/sGrzhgVspdH+tt4WntV6aIdPvIBDVbLidEnxi8aTmB8BRocl0LxYKKuizz0dDUmZA+TwJQm2xd/KnX4c41rbE1sXCzDXa2cY3yLAWRP2KxiT8nSGT1xvogdziu4N0GCyPZ/yjq0Jp7+OcaVeicG2wziPW4ZxBcCrp2kxoMphh3kWSW7v+Ay3m++gsGMiIke1wgeSorj0m2yqrP6XlZnmu+S3jZ3dgmBdI+o4sWttmQl/dAWOFqj6/6TTi+ZU80wF4P"

	sampleValidEntraXML = `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sts.windows.net/tenant-123/">
  <IDPSSODescriptor WantAuthnRequestsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>` + validCert1Base64 + `</X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://login.microsoftonline.com/tenant-123/slo" />
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://login.microsoftonline.com/tenant-123/sso-redirect" />
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://login.microsoftonline.com/tenant-123/sso-post" />
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
  </IDPSSODescriptor>
  <Organization>
    <OrganizationName xml:lang="en">Example Corp</OrganizationName>
    <OrganizationDisplayName xml:lang="en">Example Corporation</OrganizationDisplayName>
    <OrganizationURL xml:lang="en">https://example.com</OrganizationURL>
  </Organization>
</EntityDescriptor>`

	sampleMultipleKeysXML = `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>` + validCert1Base64 + `</X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <KeyDescriptor use="encryption">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>` + validCert2Base64 + `</X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso" />
  </IDPSSODescriptor>
</EntityDescriptor>`

	sampleMissingEntityIDXML = `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>` + validCert1Base64 + `</X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso" />
  </IDPSSODescriptor>
</EntityDescriptor>`

	sampleMissingSSOXML = `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>` + validCert1Base64 + `</X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>
  </IDPSSODescriptor>
</EntityDescriptor>`

	// EntitiesDescriptor XML containing multiple entities
	sampleEntitiesDescriptorXML = `<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" Name="FederationFeed">
  <EntityDescriptor entityID="https://sp.example.com">
    <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
      <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/acs" index="1" />
    </SPSSODescriptor>
  </EntityDescriptor>
  <EntityDescriptor entityID="https://idp-primary.example.com">
    <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
      <KeyDescriptor use="signing">
        <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
          <X509Data>
            <X509Certificate>` + validCert1Base64 + `</X509Certificate>
          </X509Data>
        </KeyInfo>
      </KeyDescriptor>
      <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp-primary.example.com/sso-redirect" />
      <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp-primary.example.com/sso-post" />
    </IDPSSODescriptor>
  </EntityDescriptor>
  <EntityDescriptor entityID="https://idp-secondary.example.com">
    <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
      <KeyDescriptor use="signing">
        <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
          <X509Data>
            <X509Certificate>` + validCert2Base64 + `</X509Certificate>
          </X509Data>
        </KeyInfo>
      </KeyDescriptor>
      <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp-secondary.example.com/sso" />
    </IDPSSODescriptor>
  </EntityDescriptor>
</EntitiesDescriptor>`
)

// 1. Valid metadata XML parsing
func TestValidMetadataXMLParsing(t *testing.T) {
	parser := &Parser{}
	md, err := parser.Parse([]byte(sampleValidEntraXML))
	if err != nil {
		t.Fatalf("unexpected error parsing valid metadata: %v", err)
	}

	if md.EntityID != "https://sts.windows.net/tenant-123/" {
		t.Errorf("expected entityID 'https://sts.windows.net/tenant-123/', got '%s'", md.EntityID)
	}

	if len(md.SSOEndpoints) != 2 {
		t.Errorf("expected 2 SSO endpoints, got %d", len(md.SSOEndpoints))
	}

	if len(md.SLOEndpoints) != 1 {
		t.Errorf("expected 1 SLO endpoint, got %d", len(md.SLOEndpoints))
	}

	if len(md.Certificates) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(md.Certificates))
	}

	cert := md.Certificates[0]
	if cert.Use != "signing" {
		t.Errorf("expected cert use 'signing', got '%s'", cert.Use)
	}
	if cert.SHA256Fingerprint == "" || cert.SHA1Fingerprint == "" {
		t.Errorf("expected fingerprints populated, got sha256='%s', sha1='%s'", cert.SHA256Fingerprint, cert.SHA1Fingerprint)
	}
	if cert.Trust != model.TrustStatusUnknown {
		t.Errorf("expected TrustStatusUnknown on parsed cert, got %s", cert.Trust)
	}

	if !md.Capabilities.RequiresSignedAuthn {
		t.Errorf("expected RequiresSignedAuthn=true, got false")
	}
	if !md.Capabilities.SupportsLogout {
		t.Errorf("expected SupportsLogout=true, got false")
	}

	if md.Organization == nil || md.Organization.Name != "Example Corp" {
		t.Errorf("expected Organization name 'Example Corp', got %+v", md.Organization)
	}

	// Verify that Normalizer runs idempotently on the parsed model
	normalizer := &Normalizer{}
	if err := normalizer.Normalize([]byte(sampleValidEntraXML), md); err != nil {
		t.Errorf("unexpected error from normalizer: %v", err)
	}
}

// Test with actual file fixture testdata/providers/entra/metadata.xml
func TestValidMetadataFixtureFile(t *testing.T) {
	filePath := "../../../testdata/providers/entra/metadata.xml"
	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Skipf("skipping testdata fixture check: %v", err)
		return
	}

	parser := &Parser{}
	md, err := parser.Parse(data)
	if err != nil {
		t.Fatalf("failed to parse entra testdata metadata: %v", err)
	}

	if md.EntityID != "https://sts.windows.net/dummy-tenant-id/" {
		t.Errorf("unexpected entityID from testdata: %s", md.EntityID)
	}
	if len(md.Certificates) == 0 {
		t.Errorf("expected at least 1 certificate in testdata metadata")
	}
}

// 2. XML Security: DTD rejection
func TestRejectDTDDeclarations(t *testing.T) {
	parser := &Parser{}

	dtdPayloads := [][]byte{
		[]byte(`<!DOCTYPE EntityDescriptor SYSTEM "evil.dtd"><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.evil.com"></EntityDescriptor>`),
		[]byte(`<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.evil.com"></EntityDescriptor>`),
		[]byte(`   <!doctype EntityDescriptor [ ]> <EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.evil.com"></EntityDescriptor>`),
	}

	for i, payload := range dtdPayloads {
		_, err := parser.Parse(payload)
		if err == nil {
			t.Errorf("case %d: expected error rejecting DTD, got nil", i)
		} else if !strings.Contains(err.Error(), "DTD declarations are strictly forbidden") {
			t.Errorf("case %d: expected DTD forbidden error, got: %v", i, err)
		}
	}
}

// 3. XML Security: Unexpected root elements
func TestRejectUnexpectedXMLRoots(t *testing.T) {
	parser := &Parser{}

	unexpectedRoots := [][]byte{
		[]byte(`<AuthnRequest xmlns="urn:oasis:names:tc:SAML:2.0:metadata" ID="123"></AuthnRequest>`),
		[]byte(`<Response xmlns="urn:oasis:names:tc:SAML:2.0:metadata" ID="123"></Response>`),
		[]byte(`<UnknownRoot xmlns="urn:oasis:names:tc:SAML:2.0:metadata"><Child>value</Child></UnknownRoot>`),
	}

	for i, payload := range unexpectedRoots {
		_, err := parser.Parse(payload)
		if err == nil {
			t.Errorf("case %d: expected error rejecting unexpected XML root, got nil", i)
		} else if !strings.Contains(err.Error(), "unsupported or unexpected root element") {
			t.Errorf("case %d: expected unexpected root error, got: %v", i, err)
		}
	}
}

// 4. XML Security: Incorrect namespace
func TestRejectIncorrectNamespace(t *testing.T) {
	parser := &Parser{}

	invalidNamespaces := [][]byte{
		[]byte(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:protocol" entityID="https://idp.example.com"></EntityDescriptor>`),
		[]byte(`<EntityDescriptor entityID="https://idp.example.com"></EntityDescriptor>`),
		[]byte(`<EntityDescriptor xmlns="http://evil.org/fake" entityID="https://idp.example.com"></EntityDescriptor>`),
	}

	for i, payload := range invalidNamespaces {
		_, err := parser.Parse(payload)
		if err == nil {
			t.Errorf("case %d: expected error rejecting invalid namespace, got nil", i)
		} else if !strings.Contains(err.Error(), "invalid or missing SAML metadata XML namespace") {
			t.Errorf("case %d: expected namespace error, got: %v", i, err)
		}
	}
}

// 5. XML Security: Payload size limits (> 10 MB)
func TestRejectOversizedPayload(t *testing.T) {
	parser := &Parser{}

	// Create payload > 10MB
	oversized := bytes.Repeat([]byte("A"), MaxMetadataSize+1024)
	_, err := parser.Parse(oversized)
	if err == nil {
		t.Errorf("expected error rejecting oversized payload, got nil")
	} else if !strings.Contains(err.Error(), "exceeds maximum allowed size") {
		t.Errorf("expected size limit error, got: %v", err)
	}
}

// 6. Invalid and Empty XML
func TestInvalidXML(t *testing.T) {
	parser := &Parser{}
	invalidInputs := [][]byte{
		[]byte("<EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\"><unclosed>"),
		[]byte("this is not xml at all"),
		[]byte("<<>>"),
	}

	for _, input := range invalidInputs {
		_, err := parser.Parse(input)
		if err == nil {
			t.Errorf("expected error for invalid XML '%s', got nil", string(input))
		}
	}
}

func TestEmptyMetadata(t *testing.T) {
	parser := &Parser{}
	emptyInputs := [][]byte{
		{},
		[]byte(""),
		[]byte("   \n\t  "),
	}

	for _, input := range emptyInputs {
		_, err := parser.Parse(input)
		if err == nil {
			t.Errorf("expected error for empty metadata, got nil")
		}
	}
}

// 7. Missing EntityID handling
func TestMissingEntityID(t *testing.T) {
	parser := &Parser{}
	md, err := parser.Parse([]byte(sampleMissingEntityIDXML))
	if err != nil {
		t.Fatalf("parser should handle XML structure, got error: %v", err)
	}

	validator := &DefaultMetadataValidator{}
	err = validator.Validate(md)
	if err == nil {
		t.Errorf("expected validation error for missing EntityID, got nil")
	} else if err.Error() != "missing EntityID in metadata" {
		t.Errorf("expected 'missing EntityID in metadata', got '%s'", err.Error())
	}
}

// 8. Certificate validation: Reject malformed Base64 and invalid DER
func TestStrictCertificateRejection(t *testing.T) {
	parser := &Parser{}

	// Case A: Malformed Base64 (invalid characters like non-base64 dots)
	malformedBase64XML := `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>!@#$NotValidBase64#$%^</X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso" />
  </IDPSSODescriptor>
</EntityDescriptor>`

	_, err := parser.Parse([]byte(malformedBase64XML))
	if err == nil {
		t.Errorf("expected error for malformed Base64 certificate, got nil")
	} else if !strings.Contains(err.Error(), "malformed base64 certificate") {
		t.Errorf("expected malformed base64 error, got: %v", err)
	}

	// Case B: Valid Base64, but invalid DER / X.509 ASN.1 data
	invalidDERXML := `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>` + base64.StdEncoding.EncodeToString([]byte("Not An X509 Cert")) + `</X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso" />
  </IDPSSODescriptor>
</EntityDescriptor>`

	_, err = parser.Parse([]byte(invalidDERXML))
	if err == nil {
		t.Errorf("expected error for invalid DER/X.509 certificate, got nil")
	} else if !strings.Contains(err.Error(), "malformed DER/X.509 certificate") {
		t.Errorf("expected malformed DER error, got: %v", err)
	}
}

// 9. Valid certificate fingerprint consistency from validated DER bytes
func TestValidCertificateFingerprints(t *testing.T) {
	parser := &Parser{}
	md, err := parser.Parse([]byte(sampleValidEntraXML))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(md.Certificates) == 0 {
		t.Fatalf("expected certificates in parsed metadata")
	}

	cert := md.Certificates[0]

	// Decode DER bytes independently
	derBytes, _ := base64.StdEncoding.DecodeString(validCert1Base64)
	x509Cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("fixture certificate itself must be valid: %v", err)
	}

	expectedSHA256 := sha256.Sum256(x509Cert.Raw)
	expectedSHA1 := sha1.Sum(x509Cert.Raw)

	if cert.SHA256Fingerprint != hex.EncodeToString(expectedSHA256[:]) {
		t.Errorf("SHA256 fingerprint mismatch. Expected: %s, got: %s", hex.EncodeToString(expectedSHA256[:]), cert.SHA256Fingerprint)
	}
	if cert.SHA1Fingerprint != hex.EncodeToString(expectedSHA1[:]) {
		t.Errorf("SHA1 fingerprint mismatch. Expected: %s, got: %s", hex.EncodeToString(expectedSHA1[:]), cert.SHA1Fingerprint)
	}
}

// 10. Multiple KeyDescriptors & declared roles
func TestMultipleKeyDescriptors(t *testing.T) {
	parser := &Parser{}
	md, err := parser.Parse([]byte(sampleMultipleKeysXML))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(md.Certificates) != 2 {
		t.Fatalf("expected 2 certificates for 2 KeyDescriptors, got %d", len(md.Certificates))
	}

	uses := map[string]bool{}
	for _, c := range md.Certificates {
		uses[c.Use] = true
	}

	if !uses["signing"] || !uses["encryption"] {
		t.Errorf("expected both 'signing' and 'encryption' key descriptors, got: %+v", uses)
	}
}

// 11. Duplicate certificates detection
func TestDuplicateCertificates(t *testing.T) {
	certVal := &CertificateValidator{}

	// Case A: 2 distinct certificates (pass)
	mdDistinct := &model.MetadataDescriptor{
		Certificates: []model.CertificateDescriptor{
			{Use: "signing", SHA256Fingerprint: "hash-cert-aaa", SHA1Fingerprint: "hash-cert-1"},
			{Use: "signing", SHA256Fingerprint: "hash-cert-bbb", SHA1Fingerprint: "hash-cert-2"},
		},
	}
	if err := certVal.Validate(mdDistinct); err != nil {
		t.Errorf("distinct certificates should pass validation, got: %v", err)
	}

	// Case B: duplicate certificates (fail)
	mdDuplicate := &model.MetadataDescriptor{
		Certificates: []model.CertificateDescriptor{
			{Use: "signing", SHA256Fingerprint: "duplicate-hash", SHA1Fingerprint: "dup-1"},
			{Use: "signing", SHA256Fingerprint: "duplicate-hash", SHA1Fingerprint: "dup-1"},
		},
	}
	err := certVal.Validate(mdDuplicate)
	if err == nil {
		t.Errorf("expected error for duplicate certificates, got nil")
	} else if err.Error() != "duplicate Certificates detected in metadata" {
		t.Errorf("expected 'duplicate Certificates detected in metadata', got '%s'", err.Error())
	}
}

// 12. Missing SSO endpoints detection
func TestMissingSSOEndpoints(t *testing.T) {
	parser := &Parser{}
	md, err := parser.Parse([]byte(sampleMissingSSOXML))
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	epVal := &EndpointValidator{}
	err = epVal.Validate(md)
	if err == nil {
		t.Errorf("expected error for missing SSO endpoint, got nil")
	} else if err.Error() != "missing SSO Endpoint in metadata" {
		t.Errorf("expected 'missing SSO Endpoint in metadata', got '%s'", err.Error())
	}
}

// 13. EntitiesDescriptor container handling
func TestEntitiesDescriptorHandling(t *testing.T) {
	parser := &Parser{}
	rawXML := []byte(sampleEntitiesDescriptorXML)

	// 13a. Deterministic default selection: selects first IdP entity (skips SP)
	mdDefault, err := parser.Parse(rawXML)
	if err != nil {
		t.Fatalf("unexpected error parsing EntitiesDescriptor: %v", err)
	}
	if mdDefault.EntityID != "https://idp-primary.example.com" {
		t.Errorf("expected deterministic default selection to pick first IdP 'https://idp-primary.example.com', got '%s'", mdDefault.EntityID)
	}
	if len(mdDefault.SSOEndpoints) != 2 {
		t.Errorf("expected 2 SSO endpoints for primary IdP, got %d", len(mdDefault.SSOEndpoints))
	}

	// 13b. Explicit selection by EntityID: select secondary IdP
	mdSecondary, err := parser.ParseEntity(rawXML, "https://idp-secondary.example.com")
	if err != nil {
		t.Fatalf("unexpected error parsing specific entity: %v", err)
	}
	if mdSecondary.EntityID != "https://idp-secondary.example.com" {
		t.Errorf("expected secondary IdP entityID, got '%s'", mdSecondary.EntityID)
	}

	// 13c. Explicit selection for non-existent EntityID: returns error
	_, err = parser.ParseEntity(rawXML, "https://nonexistent.example.com")
	if err == nil {
		t.Errorf("expected error when selecting non-existent entityID, got nil")
	} else if !strings.Contains(err.Error(), "not found in EntitiesDescriptor") {
		t.Errorf("expected entity not found error, got: %v", err)
	}
}

// 14. Diff Engine: In-depth endpoint comparison
func TestMetadataDiffEndpointComparison(t *testing.T) {
	diffEngine := &DiffEngine{}

	ep1 := model.Endpoint{Binding: "HTTP-Redirect", Location: "https://idp.example.com/sso", Response: ""}
	ep2 := model.Endpoint{Binding: "HTTP-POST", Location: "https://idp.example.com/sso", Response: ""}

	// 14a. Same endpoints -> No diff
	oldMD := &model.MetadataDescriptor{
		EntityID:     "https://idp.example.com",
		SSOEndpoints: []model.Endpoint{ep1, ep2},
	}
	newMDSame := &model.MetadataDescriptor{
		EntityID:     "https://idp.example.com",
		SSOEndpoints: []model.Endpoint{ep1, ep2},
	}
	resSame := diffEngine.Compare(oldMD, newMDSame)
	if resSame.EndpointChanged {
		t.Errorf("expected EndpointChanged=false for identical endpoints")
	}

	// 14b. Changed Location with same endpoint count -> Diff detected
	ep1ChangedLocation := model.Endpoint{Binding: "HTTP-Redirect", Location: "https://new-idp.example.com/sso", Response: ""}
	newMDChangedLoc := &model.MetadataDescriptor{
		EntityID:     "https://idp.example.com",
		SSOEndpoints: []model.Endpoint{ep1ChangedLocation, ep2},
	}
	resChangedLoc := diffEngine.Compare(oldMD, newMDChangedLoc)
	if !resChangedLoc.EndpointChanged {
		t.Errorf("expected EndpointChanged=true when Location changes with equal endpoint count")
	}

	// 14c. Changed Binding -> Diff detected
	ep1ChangedBinding := model.Endpoint{Binding: "HTTP-Artifact", Location: "https://idp.example.com/sso", Response: ""}
	newMDChangedBinding := &model.MetadataDescriptor{
		EntityID:     "https://idp.example.com",
		SSOEndpoints: []model.Endpoint{ep1ChangedBinding, ep2},
	}
	resChangedBinding := diffEngine.Compare(oldMD, newMDChangedBinding)
	if !resChangedBinding.EndpointChanged {
		t.Errorf("expected EndpointChanged=true when Binding changes")
	}

	// 14d. Added endpoint -> Diff detected
	ep3 := model.Endpoint{Binding: "SOAP", Location: "https://idp.example.com/soap", Response: ""}
	newMDAdded := &model.MetadataDescriptor{
		EntityID:     "https://idp.example.com",
		SSOEndpoints: []model.Endpoint{ep1, ep2, ep3},
	}
	resAdded := diffEngine.Compare(oldMD, newMDAdded)
	if !resAdded.EndpointChanged {
		t.Errorf("expected EndpointChanged=true when endpoint is added")
	}

	// 14e. Removed endpoint -> Diff detected
	newMDRemoved := &model.MetadataDescriptor{
		EntityID:     "https://idp.example.com",
		SSOEndpoints: []model.Endpoint{ep1},
	}
	resRemoved := diffEngine.Compare(oldMD, newMDRemoved)
	if !resRemoved.EndpointChanged {
		t.Errorf("expected EndpointChanged=true when endpoint is removed")
	}

	// 14f. Reordered equivalent endpoints -> No diff (deterministic, order-independent)
	newMDReordered := &model.MetadataDescriptor{
		EntityID:     "https://idp.example.com",
		SSOEndpoints: []model.Endpoint{ep2, ep1},
	}
	resReordered := diffEngine.Compare(oldMD, newMDReordered)
	if resReordered.EndpointChanged {
		t.Errorf("expected EndpointChanged=false for reordered equivalent endpoints")
	}
}

// 15. Diff Engine: Certificate comparison
func TestMetadataDiffCertificateComparison(t *testing.T) {
	diffEngine := &DiffEngine{}

	certA := model.CertificateDescriptor{
		Use:               "signing",
		SHA256Fingerprint: "fingerprint-alpha-sha256",
		SHA1Fingerprint:   "fingerprint-alpha-sha1",
	}
	certB := model.CertificateDescriptor{
		Use:               "signing",
		SHA256Fingerprint: "fingerprint-beta-sha256",
		SHA1Fingerprint:   "fingerprint-beta-sha1",
	}

	oldMD := &model.MetadataDescriptor{
		EntityID:     "https://idp.example.com",
		Certificates: []model.CertificateDescriptor{certA},
	}
	newMDIdentical := &model.MetadataDescriptor{
		EntityID:     "https://idp.example.com",
		Certificates: []model.CertificateDescriptor{certA},
	}
	if diffEngine.Compare(oldMD, newMDIdentical).CertificateChanged {
		t.Errorf("expected CertificateChanged=false for identical certificates")
	}

	newMDDifferent := &model.MetadataDescriptor{
		EntityID:     "https://idp.example.com",
		Certificates: []model.CertificateDescriptor{certB},
	}
	resDiff := diffEngine.Compare(oldMD, newMDDifferent)
	if !resDiff.CertificateChanged {
		t.Errorf("expected CertificateChanged=true when SHA256 fingerprints differ")
	}
}

// 16. Composite validator
func TestCompositeValidator(t *testing.T) {
	composite := NewCompositeMetadataValidator(
		&DefaultMetadataValidator{},
		&CertificateValidator{},
		&EndpointValidator{},
	)

	now := time.Now().Add(24 * time.Hour)
	validMD := &model.MetadataDescriptor{
		EntityID:   "https://idp.example.com",
		ValidUntil: &now,
		Certificates: []model.CertificateDescriptor{
			{Use: "signing", SHA256Fingerprint: "abc"},
		},
		SSOEndpoints: []model.Endpoint{
			{Binding: "HTTP-Redirect", Location: "https://idp.example.com/sso"},
		},
	}

	if err := composite.Validate(validMD); err != nil {
		t.Errorf("composite validator should pass for valid descriptor, got: %v", err)
	}

	invalidMD := &model.MetadataDescriptor{
		EntityID: "",
		Certificates: []model.CertificateDescriptor{
			{Use: "signing", SHA256Fingerprint: "abc"},
		},
		SSOEndpoints: []model.Endpoint{
			{Binding: "HTTP-Redirect", Location: "https://idp.example.com/sso"},
		},
	}

	if err := composite.Validate(invalidMD); err == nil {
		t.Errorf("composite validator should fail when child validator fails")
	}
}
