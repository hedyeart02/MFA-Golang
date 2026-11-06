package binding

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func deflateAndBase64(data []byte) string {
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	_, _ = w.Write(data)
	_ = w.Close()
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func TestBindingResolver_Redirect(t *testing.T) {
	resolver := NewDefaultBindingResolver()

	rawXML := "<samlp:AuthnRequest ID=\"_123\" />"
	encoded := deflateAndBase64([]byte(rawXML))

	req := httptest.NewRequest(http.MethodGet, "/saml/sso?SAMLRequest="+url.QueryEscape(encoded)+"&RelayState=test1", nil)

	resolved, err := resolver.Resolve(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resolved != BindingHTTPRedirect {
		t.Errorf("expected %q, got %q", BindingHTTPRedirect, resolved)
	}
}

func TestBindingResolver_POST(t *testing.T) {
	resolver := NewDefaultBindingResolver()

	rawXML := "<samlp:AuthnRequest ID=\"_post123\" />"
	encoded := base64Encode([]byte(rawXML))

	form := url.Values{}
	form.Set("SAMLRequest", encoded)
	form.Set("RelayState", "post_relay")

	req := httptest.NewRequest(http.MethodPost, "/saml/acs", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resolved, err := resolver.Resolve(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resolved != BindingHTTPPost {
		t.Errorf("expected %q, got %q", BindingHTTPPost, resolved)
	}
}

func TestBindingResolver_UnsupportedMethod(t *testing.T) {
	resolver := NewDefaultBindingResolver()

	req := httptest.NewRequest(http.MethodPut, "/saml/sso", nil)
	_, err := resolver.Resolve(req)
	if err == nil {
		t.Fatal("expected error for HTTP PUT, got nil")
	}
}

func TestBindingResolver_MissingSAMLRequest(t *testing.T) {
	resolver := NewDefaultBindingResolver()

	// GET without SAMLRequest
	reqGet := httptest.NewRequest(http.MethodGet, "/saml/sso", nil)
	_, err := resolver.Resolve(reqGet)
	if err == nil {
		t.Fatal("expected error for GET without SAMLRequest, got nil")
	}

	// POST without SAMLRequest
	reqPost := httptest.NewRequest(http.MethodPost, "/saml/acs", strings.NewReader("other=val"))
	reqPost.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_, err = resolver.Resolve(reqPost)
	if err == nil {
		t.Fatal("expected error for POST without SAMLRequest, got nil")
	}
}

func TestDecoder_HTTPRedirect_Success(t *testing.T) {
	decoder := &DefaultRequestDecoder{
		MaxRequestSize:   256 * 1024,
		MaxInflatedSize:  1024 * 1024,
		MaxCompressRatio: 20.0,
	}

	xmlContent := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_test_1" Version="2.0" />`
	encoded := deflateAndBase64([]byte(xmlContent))

	req := httptest.NewRequest(http.MethodGet, "/saml/sso?SAMLRequest="+url.QueryEscape(encoded)+"&RelayState=my_state", nil)

	res, err := decoder.Decode(req, BindingHTTPRedirect)
	if err != nil {
		t.Fatalf("unexpected decode error: %v", err)
	}

	if res.BindingType != BindingHTTPRedirect {
		t.Errorf("expected binding %s, got %s", BindingHTTPRedirect, res.BindingType)
	}
	if string(res.InflatedBytes) != xmlContent {
		t.Errorf("expected XML %s, got %s", xmlContent, string(res.InflatedBytes))
	}
	if res.RelayState != "my_state" {
		t.Errorf("expected RelayState my_state, got %s", res.RelayState)
	}
	if res.SHA256 == "" || res.SHA256 == "TODO_SHA256" {
		t.Errorf("expected valid computed SHA256, got %s", res.SHA256)
	}
}

func TestDecoder_HTTPPost_Success(t *testing.T) {
	decoder := &DefaultRequestDecoder{
		MaxRequestSize:  256 * 1024,
		MaxInflatedSize: 1024 * 1024,
	}

	xmlContent := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_post_test_1" />`
	encoded := base64Encode([]byte(xmlContent))

	form := url.Values{}
	form.Set("SAMLRequest", encoded)
	form.Set("RelayState", "post_state")

	req := httptest.NewRequest(http.MethodPost, "/saml/acs", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := decoder.Decode(req, BindingHTTPPost)
	if err != nil {
		t.Fatalf("unexpected decode error: %v", err)
	}

	if res.BindingType != BindingHTTPPost {
		t.Errorf("expected binding %s, got %s", BindingHTTPPost, res.BindingType)
	}
	if string(res.InflatedBytes) != xmlContent {
		t.Errorf("expected XML %s, got %s", xmlContent, string(res.InflatedBytes))
	}
	if res.RelayState != "post_state" {
		t.Errorf("expected RelayState post_state, got %s", res.RelayState)
	}
}

func TestDecoder_InvalidBase64(t *testing.T) {
	decoder := &DefaultRequestDecoder{}

	// Invalid Base64 in Redirect
	reqGet := httptest.NewRequest(http.MethodGet, "/saml/sso?SAMLRequest=!!!not-base-64!!!", nil)
	_, err := decoder.Decode(reqGet, BindingHTTPRedirect)
	if err == nil {
		t.Fatal("expected error for invalid base64 in Redirect, got nil")
	}

	// Invalid Base64 in POST
	form := url.Values{}
	form.Set("SAMLRequest", "???invalid-post-b64???")
	reqPost := httptest.NewRequest(http.MethodPost, "/saml/acs", strings.NewReader(form.Encode()))
	reqPost.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_, err = decoder.Decode(reqPost, BindingHTTPPost)
	if err == nil {
		t.Fatal("expected error for invalid base64 in POST, got nil")
	}
}

func TestDecoder_InvalidDeflate(t *testing.T) {
	decoder := &DefaultRequestDecoder{}

	// Valid Base64, but the data is plain text, NOT deflated
	plainXML := `<samlp:AuthnRequest ID="not-deflated" />`
	notDeflatedB64 := base64.StdEncoding.EncodeToString([]byte(plainXML))

	req := httptest.NewRequest(http.MethodGet, "/saml/sso?SAMLRequest="+url.QueryEscape(notDeflatedB64), nil)
	_, err := decoder.Decode(req, BindingHTTPRedirect)
	if err == nil {
		t.Fatal("expected error for non-deflated data in HTTP-Redirect, got nil")
	}
}

func TestDecoder_OversizedPayload(t *testing.T) {
	decoder := &DefaultRequestDecoder{
		MaxRequestSize:  50, // very small request limit
		MaxInflatedSize: 100,
	}

	xmlContent := strings.Repeat("A", 200)
	encoded := deflateAndBase64([]byte(xmlContent))

	req := httptest.NewRequest(http.MethodGet, "/saml/sso?SAMLRequest="+url.QueryEscape(encoded), nil)
	_, err := decoder.Decode(req, BindingHTTPRedirect)
	if err == nil {
		t.Fatal("expected error for payload exceeding MaxRequestSize, got nil")
	}
}

func TestDecoder_OversizedInflatedPayload(t *testing.T) {
	decoder := &DefaultRequestDecoder{
		MaxRequestSize:   10000,
		MaxInflatedSize:  50, // Small inflated limit
		MaxCompressRatio: 1000.0,
	}

	largeXML := strings.Repeat("X", 200)
	encoded := deflateAndBase64([]byte(largeXML))

	req := httptest.NewRequest(http.MethodGet, "/saml/sso?SAMLRequest="+url.QueryEscape(encoded), nil)
	_, err := decoder.Decode(req, BindingHTTPRedirect)
	if err == nil {
		t.Fatal("expected error for inflated payload exceeding MaxInflatedSize, got nil")
	}
}

func TestDecoder_CompressionRatioExceeded(t *testing.T) {
	decoder := &DefaultRequestDecoder{
		MaxRequestSize:   50000,
		MaxInflatedSize:  50000,
		MaxCompressRatio: 2.0, // Low ratio threshold
	}

	// Repeated zeroes compress extremely well
	highlyCompressible := strings.Repeat("0", 1000)
	encoded := deflateAndBase64([]byte(highlyCompressible))

	req := httptest.NewRequest(http.MethodGet, "/saml/sso?SAMLRequest="+url.QueryEscape(encoded), nil)
	_, err := decoder.Decode(req, BindingHTTPRedirect)
	if err == nil {
		t.Fatal("expected error for compression ratio exceeding limit, got nil")
	}
}

func TestDecoder_UnsupportedBinding(t *testing.T) {
	decoder := &DefaultRequestDecoder{}

	req := httptest.NewRequest(http.MethodGet, "/saml/sso", nil)
	_, err := decoder.Decode(req, "SOAP-Binding")
	if err == nil {
		t.Fatal("expected error for unsupported binding, got nil")
	}
}

func TestDecoder_InvalidUTF8(t *testing.T) {
	decoder := &DefaultRequestDecoder{}

	invalidUTF8 := []byte{0xff, 0xfe, 0xfd}
	encoded := deflateAndBase64(invalidUTF8)

	req := httptest.NewRequest(http.MethodGet, "/saml/sso?SAMLRequest="+url.QueryEscape(encoded), nil)
	_, err := decoder.Decode(req, BindingHTTPRedirect)
	if err == nil {
		t.Fatal("expected error for invalid UTF-8 payload, got nil")
	}
}

