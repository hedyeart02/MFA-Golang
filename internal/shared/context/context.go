package context

import (
	"github.com/hidayat-SE/samlguard/pkg/logger"
)

// RequestContext holds observability and tracing parameters for the request
type RequestContext struct {
	RequestID     string
	CorrelationID string
	TraceID       string
	SpanID        string
	ClientIP      string
	UserAgent     string
	SessionID     string
	Logger        *logger.Logger
}
