package chatbackup

import (
	"context"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// newSilentLogger creates a no-op logger for tests that don't need output.
func newSilentLogger() otelzap.LoggerWithCtx {
	return otelzap.New(zap.NewNop()).Ctx(context.Background())
}
