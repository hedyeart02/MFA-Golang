package pipeline

import (
	"net/http/httptest"
	"testing"

	"github.com/hidayat-SE/samlguard/internal/gateway/binding"
	"github.com/hidayat-SE/samlguard/internal/gateway/builder"
	"github.com/hidayat-SE/samlguard/internal/gateway/model"
	"github.com/hidayat-SE/samlguard/internal/gateway/parser"
	"github.com/hidayat-SE/samlguard/internal/gateway/validator"
)

var dummySAMLRequest = "lZJRT4MwFIX/CulfKL1twGAYjEuyTDaXLfFhX0xpO2gTaEu7Uf33LW6JL5u+9N5zvnPvbUsWqx2b0T10G7z3gGZ/Nqql8x45R7pWbCil6QIFqHMGZJffmK1rM0lY670zxtY6GvC2A6mNTaNfC3hTDe20o4zF67w4B1e8F41nS0bJm2pC71v0W/D4vAavdJ+iS0qJj+tBqA1XU7K+c98aB/oA+hR9H734lF0+Fh/O71ZzK3h0zP9q1X65T3g7c699lE3t02rL4vX4Uq5l0o4cZzM8lV2H0y20o3hWqQv4J44ZcWvQdI2QAA=="

func BenchmarkDecodeAndInflate(b *testing.B) {
	req := httptest.NewRequest("GET", "/saml/sso?SAMLRequest="+dummySAMLRequest, nil)
	decoder := &binding.DefaultRequestDecoder{
		MaxRequestSize:   256000,
		MaxInflatedSize:  1048576,
		MaxCompressRatio: 10.0,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = decoder.Decode(req, "HTTP-Redirect")
	}
}

func BenchmarkCrewjamParse(b *testing.B) {
	rawXML := []byte("<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"mock-id\" Version=\"2.0\" IssueInstant=\"2026-07-13T12:00:00Z\"><saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">mock-issuer</saml:Issuer></samlp:AuthnRequest>")
	p := &parser.SecureCrewjamParser{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = p.ParseAuthnRequest(rawXML)
	}
}

func BenchmarkContextNormalization(b *testing.B) {
	norm := &builder.DefaultNormalizer{}
	parseRes := &model.ParseResult{
		Request: &model.RawAuthnRequest{
			ID:           "mock-id",
			Issuer:       "mock-issuer",
			IssueInstant: "2026-07-13T12:00:00Z",
		},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx := &model.AuthenticationContext{}
		_ = norm.Normalize(parseRes, ctx)
	}
}

func BenchmarkValidation(b *testing.B) {
	v := &validator.DefaultSchemaValidator{}
	ctx := &model.AuthenticationContext{
		Issuer: "urn:test:issuer",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = v.ValidateSchema(ctx)
	}
}
