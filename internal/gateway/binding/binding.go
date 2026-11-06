package binding

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/hidayat-SE/samlguard/internal/gateway/model"
)

// Binding identifiers
const (
	BindingHTTPRedirect = "HTTP-Redirect"
	BindingHTTPPost     = "HTTP-POST"

	SAMLBindingHTTPRedirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	SAMLBindingHTTPPost     = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
)

// BindingResolver employs Strategy Pattern to decode incoming HTTP bindings
type BindingResolver interface {
	Resolve(r *http.Request) (string, error)
}

// RequestDecoder extracts the raw bytes based on the resolved binding
type RequestDecoder interface {
	Decode(r *http.Request, binding string) (*model.TransportResult, error)
}

// DefaultBindingResolver inspects HTTP request attributes to identify the SAML binding
type DefaultBindingResolver struct{}

func NewDefaultBindingResolver() *DefaultBindingResolver {
	return &DefaultBindingResolver{}
}

func (b *DefaultBindingResolver) Resolve(r *http.Request) (string, error) {
	if r == nil {
		return "", errors.New("http request is nil")
	}

	switch r.Method {
	case http.MethodGet:
		if r.URL == nil {
			return "", errors.New("invalid request: URL is nil")
		}
		samlRequest := r.URL.Query().Get("SAMLRequest")
		if strings.TrimSpace(samlRequest) == "" {
			return "", errors.New("missing SAMLRequest query parameter for HTTP-Redirect binding")
		}
		return BindingHTTPRedirect, nil

	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			return "", fmt.Errorf("failed to parse form data for HTTP-POST binding: %w", err)
		}
		samlRequest := r.PostFormValue("SAMLRequest")
		if strings.TrimSpace(samlRequest) == "" {
			return "", errors.New("missing SAMLRequest form data for HTTP-POST binding")
		}
		return BindingHTTPPost, nil

	default:
		return "", fmt.Errorf("unsupported HTTP method %q: only GET (HTTP-Redirect) and POST (HTTP-POST) are supported", r.Method)
	}
}
