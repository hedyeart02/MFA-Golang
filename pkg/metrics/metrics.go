package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	// Authentication Domain
	AuthSuccess = prometheus.NewCounter(prometheus.CounterOpts{Name: "auth_success_total"})
	AuthFailure = prometheus.NewCounter(prometheus.CounterOpts{Name: "auth_failure_total"})

	// SAML Domain
	SAMLAssertionsProcessed = prometheus.NewCounter(prometheus.CounterOpts{Name: "saml_assertions_total"})
	SAMLErrors              = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "saml_errors_total"}, []string{"type"})

	// MFA Domain
	MFASuccess = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "mfa_success_total"}, []string{"provider"})
	MFAFailure = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "mfa_failure_total"}, []string{"provider"})

	// Gateway Domain
	RequestDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "gateway_request_duration_seconds"}, []string{"method", "path", "status"})

	// Audit Domain
	AuditEventsLogged = prometheus.NewCounter(prometheus.CounterOpts{Name: "audit_events_total"})

	// Session Domain
	ActiveSessions = prometheus.NewGauge(prometheus.GaugeOpts{Name: "session_active_current"})
)

func init() {
	prometheus.MustRegister(AuthSuccess, AuthFailure)
	prometheus.MustRegister(SAMLAssertionsProcessed, SAMLErrors)
	prometheus.MustRegister(MFASuccess, MFAFailure)
	prometheus.MustRegister(RequestDuration)
	prometheus.MustRegister(AuditEventsLogged)
	prometheus.MustRegister(ActiveSessions)
}
