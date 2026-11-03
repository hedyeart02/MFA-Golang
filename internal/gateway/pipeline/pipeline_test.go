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
