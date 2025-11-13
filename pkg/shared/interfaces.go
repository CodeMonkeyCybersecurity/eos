package shared

import (
	"context"

	"go.uber.org/zap"
)

// Logger interface to avoid dependency on specific logging implementations
type Logger interface {
	Info(msg string, fields ...zap.Field)
	Debug(msg string, fields ...zap.Field)
	Warn(msg string, fields ...zap.Field)
	Error(msg string, fields ...zap.Field)
}

// ContextProvider interface to avoid dependency on eos_io.RuntimeContext
type ContextProvider interface {
	Context() context.Context
}
