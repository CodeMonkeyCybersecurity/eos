// pkg/testutil/context.go

package testutil

import (
	"context"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

// TestContext creates a test-friendly RuntimeContext
func TestContext(t *testing.T) *eos_io.RuntimeContext {
	// Create a test logger
	logger := zaptest.NewLogger(t)

	// Create context with logger
	ctx := context.Background()

	// Create otelzap logger
	otelLogger := otelzap.New(logger)

	// Store logger in context using otelzap's method
	ctx = otelzap.CtxWithLogger(ctx, otelLogger)

	// Create runtime context
	rc := &eos_io.RuntimeContext{
		Ctx: ctx,
		Attributes: map[string]string{
			"test": "true",
		},
	}

	return rc
}

// TestContextWithOptions creates a test RuntimeContext with custom options
func TestContextWithOptions(t *testing.T, opts ...zap.Option) *eos_io.RuntimeContext {
	// Create a test logger with options
	logger := zaptest.NewLogger(t, opts...)

	// Create context with logger
	ctx := context.Background()

	// Create otelzap logger
	otelLogger := otelzap.New(logger)

	// Store logger in context
	ctx = otelzap.CtxWithLogger(ctx, otelLogger)

	// Create runtime context
	rc := &eos_io.RuntimeContext{
		Ctx: ctx,
		Attributes: map[string]string{
			"test": "true",
		},
	}

	return rc
}

// TestLogger creates a test-friendly otelzap logger
func TestLogger(t *testing.T) otelzap.LoggerWithCtx {
	logger := zaptest.NewLogger(t)
	otelLogger := otelzap.New(logger)
	ctx := otelzap.CtxWithLogger(context.Background(), otelLogger)
	return otelzap.Ctx(ctx)
}

// NopContext creates a RuntimeContext with a no-op logger for benchmarks
func NopContext() *eos_io.RuntimeContext {
	logger := zap.NewNop()
	otelLogger := otelzap.New(logger)
	ctx := otelzap.CtxWithLogger(context.Background(), otelLogger)

	return &eos_io.RuntimeContext{
		Ctx: ctx,
		Attributes: map[string]string{
			"test": "true",
		},
	}
}