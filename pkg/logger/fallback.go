package logger

import (
	"errors"
	"fmt"
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func newFallbackLogger() *zap.Logger {
	cfg := defaultConsoleEncoderConfig()

	core := zapcore.NewCore(
		zapcore.NewConsoleEncoder(cfg),
		zapcore.AddSync(os.Stdout),
		parseLogLevel(os.Getenv("LOG_LEVEL")),
	)

	logger := zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))
	logger.Info("Logger fallback initialized")
	return logger
}

func initializeWithFallback(logPath string) error {
	if logPath == "" {
		return errors.New("no writable log path found")
	}
	if err := ensureLogPermissions(logPath); err != nil {
		return fmt.Errorf("unable to prepare log path: %w", err)
	}

	cfg := defaultConsoleEncoderConfig()
	jsonCfg := zap.NewProductionEncoderConfig()
	jsonCfg.EncodeTime = zapcore.ISO8601TimeEncoder
	jsonCfg.EncodeLevel = zapcore.CapitalLevelEncoder

	core := zapcore.NewTee(
		zapcore.NewCore(zapcore.NewConsoleEncoder(cfg), zapcore.Lock(os.Stdout), zap.InfoLevel),
		zapcore.NewCore(zapcore.NewJSONEncoder(jsonCfg), getLogFileWriter(logPath), zap.InfoLevel),
	)

	log = zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))
	zap.ReplaceGlobals(log)
	return nil
}

func defaultConsoleEncoderConfig() zapcore.EncoderConfig {
	cfg := zap.NewProductionEncoderConfig()
	cfg.TimeKey = "T"
	cfg.LevelKey = "L"
	cfg.NameKey = "N"
	cfg.CallerKey = "C"
	cfg.MessageKey = "M"
	cfg.EncodeTime = zapcore.ISO8601TimeEncoder
	cfg.EncodeLevel = zapcore.CapitalColorLevelEncoder
	return cfg
}
