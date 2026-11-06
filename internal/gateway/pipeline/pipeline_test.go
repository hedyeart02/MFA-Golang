package pipeline

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hidayat-SE/samlguard/internal/gateway/model"
)

// Mocks
type mockBinding struct{}

func (m *mockBinding) Resolve(r *http.Request) (string, error) { return "HTTP-Redirect", nil }

type mockDecoder struct{}

func (m *mockDecoder) Decode(r *http.Request, binding string) (*model.TransportResult, error) {
	return &model.TransportResult{
		InflatedBytes: []byte("<samlp:AuthnRequest />"),
		RelayState:    "state123",
	}, nil
}

type mockParser struct{}

func (m *mockParser) ParseAuthnRequest(rawXML []byte) (*model.ParseResult, error) {
	return &model.ParseResult{
		Request: &model.RawAuthnRequest{
			ID:     "mock-req-id",
			Issuer: "https://sp.mock.com",
		},
	}, nil
}

type mockNormalizer struct{}

func (m *mockNormalizer) Normalize(parsed *model.ParseResult, ctx *model.AuthenticationContext) error {
	ctx.RequestIDFromSP = parsed.Request.ID
	ctx.Issuer = parsed.Request.Issuer
	return nil
}

type mockValidator struct{}

func (m *mockValidator) ValidateSyntax(ctx *model.AuthenticationContext) error    { return nil }
func (m *mockValidator) ValidateSignature(ctx *model.AuthenticationContext) error { return nil }
func (m *mockValidator) ValidateSchema(ctx *model.AuthenticationContext) error    { return nil }
func (m *mockValidator) ValidateReplay(ctx *model.AuthenticationContext) error    { return nil }
func (m *mockValidator) ValidateClockSkew(ctx *model.AuthenticationContext) error { return nil }
func (m *mockValidator) ValidatePolicy(ctx *model.AuthenticationContext) error    { return nil }

type mockMetadataResolver struct{}

func (m *mockMetadataResolver) Resolve(ctx context.Context, entityID string) (interface{}, error) {
	return nil, nil
}

type mockProviderResolver struct{}

func (m *mockProviderResolver) ResolveProvider(ctx *model.AuthenticationContext) (string, error) {
	return "mock-provider", nil
}

type mockContextBuilder struct{}

func (m *mockContextBuilder) Build(ctx *model.AuthenticationContext) (*model.AuthenticationContext, error) {
	ctx.ValidationResult = model.ValidationResult{IsValid: true}
	return ctx, nil
}

func TestPipelineExecution(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/saml/sso?SAMLRequest=dummy", nil)

	p := &DefaultAuthnPipeline{
		BindingResolver: &mockBinding{},
		Decoder:         &mockDecoder{},
		ContextBuilder:  &mockContextBuilder{},
	}

	ctx, err := p.Execute(context.Background(), req)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if ctx.RequestID != "" {
		t.Errorf("Expected RequestID to be empty in dummy request, got %s", ctx.RequestID)
	}

	if !ctx.ValidationResult.IsValid {
		t.Errorf("Expected context to be valid")
	}

	if ctx.ReceivedAt.IsZero() {
		t.Errorf("Expected ReceivedAt to be set")
	}
}

func TestPipelineValidate_MissingDependencies(t *testing.T) {
	// Empty pipeline
	emptyPipeline := &DefaultAuthnPipeline{}
	if err := emptyPipeline.Validate(); err == nil {
		t.Fatal("expected validation error for empty pipeline, got nil")
	}

	// Partially populated pipeline (missing ContextBuilder)
	v := &mockValidator{}
	partialPipeline := &DefaultAuthnPipeline{
		BindingResolver:    &mockBinding{},
		Decoder:            &mockDecoder{},
		Parser:             &mockParser{},
		Normalizer:         &mockNormalizer{},
		SyntaxValidator:    v,
		SignatureValidator: v,
		SchemaValidator:    v,
		ReplayValidator:    v,
		ClockValidator:     v,
		PolicyValidator:    v,
		MetadataResolver:   &mockMetadataResolver{},
		ProviderResolver:   &mockProviderResolver{},
		// ContextBuilder missing
	}
	if err := partialPipeline.Validate(); err == nil {
		t.Fatal("expected validation error when ContextBuilder is missing, got nil")
	}

	// Fully populated pipeline
	partialPipeline.ContextBuilder = &mockContextBuilder{}
	if err := partialPipeline.Validate(); err != nil {
		t.Fatalf("unexpected validation error for fully populated pipeline: %v", err)
	}
}

func TestPipelineExecution_MissingMandatoryBinding(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/saml/sso", nil)

	p := &DefaultAuthnPipeline{
		// BindingResolver is nil
		Decoder: &mockDecoder{},
	}

	_, err := p.Execute(context.Background(), req)
	if err == nil {
		t.Fatal("expected error when BindingResolver is missing, got nil")
	}
}

func TestPipelineExecution_MissingMandatoryDecoder(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/saml/sso", nil)

	p := &DefaultAuthnPipeline{
		BindingResolver: &mockBinding{},
		// Decoder is nil
	}

	_, err := p.Execute(context.Background(), req)
	if err == nil {
		t.Fatal("expected error when Decoder is missing, got nil")
	}
}
