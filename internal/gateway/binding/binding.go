package binding

import (
	"net/http"
	"github.com/hidayat-SE/samlguard/internal/gateway/model"
)

// BindingResolver employs Strategy Pattern to decode incoming HTTP bindings
type BindingResolver interface {
	Resolve(r *http.Request) (string, error)
}

// RequestDecoder extracts the raw bytes based on the resolved binding
type RequestDecoder interface {
	Decode(r *http.Request, binding string) (*model.TransportResult, error)
}
