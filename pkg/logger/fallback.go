/* pkg/logger/fallback.go */

package logger

import (
	"fmt"
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func NewFallbackLogger() *zap.Logger {
	cfg := DefaultConsoleEncoderConfig()

	core := zapcore.NewCore(
		zapcore.NewConsoleEncoder(cfg),
		zapcore.AddSync(os.Stdout),
		ParseLogLevel(os.Getenv("LOG_LEVEL")),
	)

	logger := zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))
	logger.Info("Logger fallback initialized")
	return logger
}

func InitializeWithFallback() {
	path, err := FindWritableLogPath()
	if err != nil {
		fmt.Fprintln(os.Stderr, "⚠️  No writable log path found. Logging to console only.")
		log = NewFallbackLogger()
		zap.ReplaceGlobals(log)
		return
	}

	cfg := DefaultConsoleEncoderConfig()
	jsonCfg := zap.NewProductionEncoderConfig()
	jsonCfg.EncodeTime = zapcore.ISO8601TimeEncoder
	jsonCfg.EncodeLevel = zapcore.CapitalLevelEncoder

	writer, err := GetLogFileWriter(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "⚠️  Could not write to log file, falling back to stdout:", err)
		writer = zapcore.AddSync(os.Stdout)
	}

	core := zapcore.NewTee(
		zapcore.NewCore(zapcore.NewConsoleEncoder(cfg), zapcore.Lock(os.Stdout), zap.InfoLevel),
		zapcore.NewCore(zapcore.NewJSONEncoder(jsonCfg), writer, zap.InfoLevel),
	)

	log = zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))
	zap.ReplaceGlobals(log)
	log.Info("Logger fallback initialized",
		zap.String("log_level", os.Getenv("LOG_LEVEL")),
		zap.String("log_path", path),
	)
}

func DefaultConsoleEncoderConfig() zapcore.EncoderConfig {
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
