package resolver

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/hidayat-SE/samlguard/internal/federation/metadata"
	fedmodel "github.com/hidayat-SE/samlguard/internal/federation/model"
)

const sampleValidEntraXML = `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sts.windows.net/tenant-123/">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>MIIDXDCCAkSgAwIBAgIRAIpW32w8iqAmcNEa8CSRPjgwDQYJKoZIhvcNAQELBQAwPTELMAkGA1UEBhMCVVMxEjAQBgNVBAoTCVNBTUxHdWFyZDEaMBgGA1UEAxMRU0FNTEd1YXJkIFNpZ25pbmcwHhcNMjYwNzEyMDk0ODMxWhcNMjcwNzEyMDk0ODMxWjA9MQswCQYDVQQGEwJVUzESMBAGA1UEChMJU0FNTEd1YXJkMRowGAYDVQQDExFTQU1MR3VhcmQgU2lnbmluZzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANeKdrNvXAFcP+x3ium+CXBDkz5jGAXvAXaIVLFulUtYCh50uieJRRhTt/ugtb1WP3JKW5hX2r8yQAPkijop3z0RxVL+QTenTZ0EadUlculfBhtkGWnObGOdX7B6O9XWu82BYlrxXVhMXwS2/cHtrRcjGDbkWcZ63vQ7W2yZ4VtYe3IsLaKByMjYVw89wRWZTTaUFAJhJjpxqV8XmyeC1NJg7xTeBcQoWu+9VmT/AjVjPnHNafxEHaN9YSCZrFuyp4dVG4Ukay9tKbT49mSoHbefBKAB/BJNTbCgr+Pn9L/d8XvVEoWp+6VJ579iLh1lWEF02sfFlkC3m24C0Gijg1ECAwEAAaNXMFUwDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAwIAYDVR0RBBkwF4IVc2FtbGd1YXJkLmV4YW1wbGUuY29tMA0GCSqGSIb3DQEBCwUAA4IBAQBnoqlsQhCt6mVrzgTBfWzCGsOjy/cfJnhhiBeusFoSlRWhIoytGW/F8lDQxvi0U96hFAh6+iTkRZnFSE/tBtkPBg4Ad2AvIwSx8VtnSr0BFDzB9y71pm/REGcmztzuiywgk+UjCqYew3YgqNLXgwrNnyAjSDKi7a2V6YqccGyq0ErFawBGCnHS/24NlD1DuEooJJXtptbf3aSnL67nKDB3fsavz6CSWdZ76G3Yyu0HJUOSHGoiI69reDWjSzcWz8ARNydu6DLJrc2t1FgMUG+Tos/iDW63recRC/XSOr+blAFB2mX1grtuBUDpVcsL7u027lnC5Ob+ajcJQv4i1eqv</X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://login.microsoftonline.com/tenant-123/sso" />
  </IDPSSODescriptor>
</EntityDescriptor>`

func TestMetadataResolver_Success(t *testing.T) {
	memLoader := &metadata.MemoryLoader{
		Store: map[string][]byte{
			"entra_source": []byte(sampleValidEntraXML),
		},
	}

	res := NewDefaultMetadataResolver(
		map[string]string{
			"https://sts.windows.net/tenant-123/": "entra_source",
		},
		"",
		memLoader,
		&metadata.Parser{},
	)

	ctx := context.Background()
	result, err := res.Resolve(ctx, "https://sts.windows.net/tenant-123/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	md, ok := result.(*fedmodel.MetadataDescriptor)
	if !ok {
		t.Fatalf("expected *fedmodel.MetadataDescriptor, got %T", result)
	}

	if md.EntityID != "https://sts.windows.net/tenant-123/" {
		t.Errorf("expected entity ID https://sts.windows.net/tenant-123/, got %s", md.EntityID)
	}

	// Verify that certificates are NOT trusted by default
	if len(md.Certificates) == 0 {
		t.Fatal("expected certificates to be present")
	}
	for _, cert := range md.Certificates {
		if cert.Trust != fedmodel.TrustStatusUnknown {
			t.Errorf("expected certificate trust to be UNKNOWN, got %s", cert.Trust)
		}
	}
}

func TestMetadataResolver_ContextCancelled(t *testing.T) {
	memLoader := &metadata.MemoryLoader{
		Store: map[string][]byte{
			"entra_source": []byte(sampleValidEntraXML),
		},
	}

	res := NewDefaultMetadataResolver(
		map[string]string{"https://sts.windows.net/tenant-123/": "entra_source"},
		"",
		memLoader,
		&metadata.Parser{},
	)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := res.Resolve(ctx, "https://sts.windows.net/tenant-123/")
	if err == nil {
		t.Fatal("expected context cancellation error, got nil")
	}
}

func TestMetadataResolver_UnavailableSource(t *testing.T) {
	res := NewDefaultMetadataResolver(
		map[string]string{
			"https://sts.windows.net/tenant-123/": "non_existent_file.xml",
		},
		"",
		&metadata.StaticFileLoader{},
		&metadata.Parser{},
	)

	_, err := res.Resolve(context.Background(), "https://sts.windows.net/tenant-123/")
	if err == nil {
		t.Fatal("expected error for unavailable source, got nil")
	}
}

func TestMetadataResolver_UnconfiguredEntityID(t *testing.T) {
	res := NewDefaultMetadataResolver(
		map[string]string{},
		"",
		&metadata.StaticFileLoader{},
		&metadata.Parser{},
	)

	_, err := res.Resolve(context.Background(), "urn:unknown:entity")
	if err == nil {
		t.Fatal("expected error for unconfigured entityID, got nil")
	}
}

func TestMetadataResolver_ExplicitEntityIDMismatch(t *testing.T) {
	memLoader := &metadata.MemoryLoader{
		Store: map[string][]byte{
			"entra_source": []byte(sampleValidEntraXML),
		},
	}

	res := NewDefaultMetadataResolver(
		map[string]string{},
		"entra_source", // default source
		memLoader,
		&metadata.Parser{},
	)

	// The XML contains entityID "https://sts.windows.net/tenant-123/", but we ask for "https://different.example"
	_, err := res.Resolve(context.Background(), "https://different.example")
	if err == nil {
		t.Fatal("expected error for entity ID mismatch, got nil")
	}
}

func TestStaticMetadataProvider_Success(t *testing.T) {
	testdataRel := filepath.Join("..", "..", "..", "testdata", "providers", "entra", "metadata.xml")
	provider := NewStaticMetadataProvider(testdataRel, &metadata.StaticFileLoader{}, &metadata.Parser{})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	result, err := provider.FetchMetadata(ctx, "https://sts.windows.net/dummy-tenant-id/")
	if err != nil {
		t.Fatalf("unexpected error fetching static metadata: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil descriptor")
	}
	md := result.(*fedmodel.MetadataDescriptor)
	if md.EntityID != "https://sts.windows.net/dummy-tenant-id/" {
		t.Errorf("unexpected entityID %s", md.EntityID)
	}
}

func TestHTTPMetadataProvider_Disabled(t *testing.T) {
	h := &HTTPMetadataProvider{}
	_, err := h.FetchMetadata(context.Background(), "https://idp.example.com")
	if err == nil {
		t.Fatal("expected HTTPMetadataProvider to return error, got nil")
	}
}

