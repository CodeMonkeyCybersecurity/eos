package logger

import (
	"fmt"
	"os"

	"go.uber.org/zap"
)

func Initialize(cfg zap.Config) {
	for _, path := range cfg.OutputPaths {
		if path != "stdout" && path != "stderr" {
			if err := EnsureLogPermissions(path); err != nil {
				fmt.Fprintln(os.Stderr, "⚠️ Log permission error:", err)
				panic(err)
			}
		}
	}

	logger, err := cfg.Build()
	if err != nil {
		logger, _ = zap.NewProduction()
	}

	zap.ReplaceGlobals(logger)
	SetLogger(logger)

	logger.Info("Logger initialized", zap.String("log_level", cfg.Level.String()))
}

func InitFallback() {
	fallback := NewFallbackLogger()
	zap.ReplaceGlobals(fallback)
	SetLogger(fallback)
}

func GetLogger() *zap.Logger {
	l := L()
	if l == nil {
		fallback := NewFallbackLogger()
		zap.ReplaceGlobals(fallback)
		SetLogger(fallback)
		return fallback
	}
	return l
}

func StrictEnabled(flags []bool) bool {
	return len(flags) > 0 && flags[0]
}

func LogErrAndWrap(log *zap.Logger, msg string, err error) error {
	log.Error(msg, zap.Error(err))
	return fmt.Errorf("%s: %w", msg, err)
}
