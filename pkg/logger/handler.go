package logger

import (
	"errors"
	"fmt"
	"os"

	"go.uber.org/zap"
)

var log *zap.Logger

func initializeWithConfig(cfg zap.Config) {
	if log != nil {
		return
	}

	for _, path := range cfg.OutputPaths {
		if path != "stdout" && path != "stderr" {
			if err := ensureLogPermissions(path); err != nil {
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

func getLogger() *zap.Logger {
	if log == nil {
		log = newFallbackLogger()
		zap.ReplaceGlobals(log)
	}
	return log
}

func L() *zap.Logger {
	return GetLogger()
}

func sync(strict ...bool) error {
	if log == nil {
		return nil
	}
	err := log.Sync()
	if err == nil || (!strictEnabled(strict) && isIgnorableSyncError(err)) {
		return nil
	}
	log.Error("Failed to sync logger", zap.Error(err))
	return err
}

func isIgnorableSyncError(err error) bool {
	var pathErr *os.PathError
	return errors.As(err, &pathErr) || err.Error() == "sync /dev/stdout: invalid argument"
}

func strictEnabled(flags []bool) bool {
	return len(flags) > 0 && flags[0]
}
