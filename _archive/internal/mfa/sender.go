package mfa

import (
	"go.uber.org/zap"
)

// LogSender is a development OTP sender that logs codes to the console.
// In production, replace with SMTPSender or TwilioSender.
type LogSender struct {
	method string
	logger *zap.Logger
}

// NewLogSender creates a log-based OTP sender for development.
func NewLogSender(method string, log *zap.Logger) *LogSender {
	return &LogSender{
		method: method,
		logger: log,
	}
}

// Send logs the OTP code instead of actually delivering it.
func (s *LogSender) Send(recipient, code string) error {
	s.logger.Info("OTP code generated (development mode)",
		zap.String("method", s.method),
		zap.String("recipient", recipient),
		zap.String("code", "***REDACTED***"),
	)
	return nil
}

// Method returns the delivery method name.
func (s *LogSender) Method() string {
	return s.method
}
