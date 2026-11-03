package logger

import (
	"go.uber.org/zap"
)

// Logger abstracts the underlying structured logger and scopes it by domain
type Logger struct {
	base *zap.Logger
}

func New(base *zap.Logger) *Logger {
	return &Logger{base: base}
}

func (l *Logger) Authentication() *zap.Logger {
	return l.base.With(zap.String("domain", "authentication"))
}

func (l *Logger) Security() *zap.Logger {
	return l.base.With(zap.String("domain", "security"))
}

func (l *Logger) Audit() *zap.Logger {
	return l.base.With(zap.String("domain", "audit"))
}

func (l *Logger) System() *zap.Logger {
	return l.base.With(zap.String("domain", "system"))
}
