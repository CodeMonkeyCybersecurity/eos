// pkg/logger/handler.go

package logger

import (
	"errors"
	"fmt"
	"os"

	"go.uber.org/zap"
)

func Init(cfg zap.Config) {
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
	zap.L().Info("Logger initialized", zap.String("log_level", cfg.Level.String()))
}

func Sync(strict ...bool) error {
	err := zap.L().Sync()
	if err == nil || (!StrictEnabled(strict) && IsIgnorableSyncError(err)) {
		return nil
	}
	zap.L().Error("Failed to sync logger", zap.Error(err))
	return err
}
func IsIgnorableSyncError(err error) bool {
	var pathErr *os.PathError
	return errors.As(err, &pathErr) || err.Error() == "sync /dev/stdout: invalid argument"
}

func StrictEnabled(flags []bool) bool {
	return len(flags) > 0 && flags[0]
}

func LogErrAndWrap(msg string, err error) error {
	zap.L().Error(msg, zap.Error(err))
	return fmt.Errorf("%s: %w", msg, err)
}
