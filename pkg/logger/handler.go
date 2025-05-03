/* pkg/logger/handler.go */

package logger

import (
	"errors"
	"fmt"
	"os"

	"go.uber.org/zap"
)

var log *zap.Logger

func Initialize(cfg zap.Config) {
	if log != nil {
		return
	}

	for _, path := range cfg.OutputPaths {
		if path != "stdout" && path != "stderr" {
			if err := EnsureLogPermissions(path); err != nil {
				fmt.Fprintln(os.Stderr, "⚠️ Log permission error:", err)
				panic(err)
			}
		}
	}

	var err error
	log, err = cfg.Build()
	if err != nil {
		log, _ = zap.NewProduction() // fallback to stdout-only logger
	}

	zap.ReplaceGlobals(log)
	log.Info("Logger initialized", zap.String("log_level", cfg.Level.String()))
}

// InitFallback sets up an in-memory console logger and replaces globals.
func InitFallback() {
	log = NewFallbackLogger()
	zap.ReplaceGlobals(log)
}

func Logger() *zap.Logger {
	return GetLogger()
}

func GetLogger() *zap.Logger {
	if log == nil {
		log = NewFallbackLogger()
		zap.ReplaceGlobals(log)
	}
	return log
}

func Sync(strict ...bool) error {
	if log == nil {
		return nil
	}
	err := log.Sync()
	if err == nil || (!StrictEnabled(strict) && IsIgnorableSyncError(err)) {
		return nil
	}
	log.Error("Failed to sync logger", zap.Error(err))
	return err
}

func IsIgnorableSyncError(err error) bool {
	var pathErr *os.PathError
	return errors.As(err, &pathErr) || err.Error() == "sync /dev/stdout: invalid argument"
}

func StrictEnabled(flags []bool) bool {
	return len(flags) > 0 && flags[0]
}

func LogErrAndWrap(log *zap.Logger, msg string, err error) error {
	log.Error(msg, zap.Error(err))
	return fmt.Errorf("%s: %w", msg, err)
}
