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

	// Set as global logger for otelzap.Ctx to work
	zap.ReplaceGlobals(logger)

	// Create runtime context with plain context
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
		Log: logger,
		Attributes: map[string]string{
			"test": "true",
		},
	}

	return rc
}

// TestContextWithOptions creates a test RuntimeContext with custom options
func TestContextWithOptions(t *testing.T, opts ...zaptest.LoggerOption) *eos_io.RuntimeContext {
	// Create a test logger with options
	logger := zaptest.NewLogger(t, opts...)

	// Set as global logger
	zap.ReplaceGlobals(logger)

	// Create runtime context
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
		Log: logger,
		Attributes: map[string]string{
			"test": "true",
		},
	}

	return rc
}

// TestLogger creates a test-friendly otelzap logger
func TestLogger(t *testing.T) otelzap.LoggerWithCtx {
	logger := zaptest.NewLogger(t)
	zap.ReplaceGlobals(logger)
	otelLogger := otelzap.New(logger)
	return otelLogger.Ctx(context.Background())
}

// NopContext creates a RuntimeContext with a no-op logger for benchmarks
func NopContext() *eos_io.RuntimeContext {
	logger := zap.NewNop()
	zap.ReplaceGlobals(logger)

	return &eos_io.RuntimeContext{
		Ctx: context.Background(),
		Log: logger,
		Attributes: map[string]string{
			"test": "true",
		},
	}
}