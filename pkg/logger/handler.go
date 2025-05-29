// pkg/logger/handler.go

package logger

import (
	"errors"
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

func Init(rc *eos_io.RuntimeContext, cfg zap.Config) {
	for _, path := range cfg.OutputPaths {
		if path != "stdout" && path != "stderr" {
			if err := EnsureLogPermissions(path); err != nil {
				fmt.Fprintln(os.Stderr, "⚠️ Log permission error:", err)
				InitFallback()
				return
			}
		}
	}

	builtLogger, err := cfg.Build()
	if err != nil {
		fmt.Fprintln(os.Stderr, "⚠️ Failed to build logger config, falling back:", err)
		InitFallback()
		return
	}

	zap.ReplaceGlobals(builtLogger)
	otelzap.Ctx(rc.Ctx).Info("Logger initialized", zap.String("log_level", cfg.Level.String()))
}

func Sync(rc *eos_io.RuntimeContext, strict ...bool) error {
	logger := otelzap.Ctx(rc.Ctx).Logger() // Get underlying *zap.Logger
	err := logger.Sync()                   // Sync returns error

	if err == nil || (!StrictEnabled(strict) && IsIgnorableSyncError(err)) {
		return nil
	}
	otelzap.Ctx(rc.Ctx).Error("Failed to sync logger", zap.Error(err))
	return err
}

func IsIgnorableSyncError(err error) bool {
	var pathErr *os.PathError
	return errors.As(err, &pathErr) || err.Error() == "sync /dev/stdout: invalid argument"
}

func StrictEnabled(flags []bool) bool {
	return len(flags) > 0 && flags[0]
}

func LogErrAndWrap(rc *eos_io.RuntimeContext, msg string, err error) error {
	otelzap.Ctx(rc.Ctx).Error(msg, zap.Error(err))
	return fmt.Errorf("%s: %w", msg, err)
}
