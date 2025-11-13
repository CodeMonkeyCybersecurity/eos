package serviceutil

import (
	"context"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// RuntimeContextAdapter adapts eos_io.RuntimeContext to shared.ContextProvider interface
type RuntimeContextAdapter struct {
	rc *eos_io.RuntimeContext
}

func (rca *RuntimeContextAdapter) Context() context.Context {
	return rca.rc.Ctx
}

// OtelzapLoggerAdapter adapts otelzap.LoggerWithCtx to shared.Logger interface
type OtelzapLoggerAdapter struct {
	logger otelzap.LoggerWithCtx
}

func (ola *OtelzapLoggerAdapter) Info(msg string, fields ...zap.Field) {
	ola.logger.Info(msg, fields...)
}

func (ola *OtelzapLoggerAdapter) Debug(msg string, fields ...zap.Field) {
	ola.logger.Debug(msg, fields...)
}

func (ola *OtelzapLoggerAdapter) Warn(msg string, fields ...zap.Field) {
	ola.logger.Warn(msg, fields...)
}

func (ola *OtelzapLoggerAdapter) Error(msg string, fields ...zap.Field) {
	ola.logger.Error(msg, fields...)
}

// NewServiceManager creates a SystemdServiceManager from RuntimeContext
// This provides backward compatibility for existing code
func NewServiceManager(rc *eos_io.RuntimeContext) *shared.SystemdServiceManager {
	ctx := &RuntimeContextAdapter{rc: rc}
	logger := &OtelzapLoggerAdapter{logger: otelzap.Ctx(rc.Ctx)}
	return shared.NewSystemdServiceManager(ctx, logger)
}

// NewConfigManager creates a ConfigManager from RuntimeContext
func NewConfigManager(rc *eos_io.RuntimeContext) *shared.ConfigManager {
	logger := &OtelzapLoggerAdapter{logger: otelzap.Ctx(rc.Ctx)}
	return shared.NewConfigManager(logger)
}
