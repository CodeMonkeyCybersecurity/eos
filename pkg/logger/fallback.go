// pkg/logger/fallback.go

package logger

import (
	"fmt"
	"os"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func InitFallback() {
	path, err := FindWritableLogPath()
	if err != nil {
		fmt.Fprintln(os.Stderr, " No writable log path found. Logging to console only.")

		cfg := DefaultConsoleEncoderConfig()
		fallbackCore := zapcore.NewCore(
			zapcore.NewConsoleEncoder(cfg),
			zapcore.AddSync(os.Stdout),
			ParseLogLevel(os.Getenv("LOG_LEVEL")),
		)

		fallbackLogger := zap.New(fallbackCore, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))
		zap.ReplaceGlobals(fallbackLogger)
		otelzap.ReplaceGlobals(otelzap.New(fallbackLogger))
		fallbackLogger.Info("Logger fallback initialized")
		return
	}

	cfg := DefaultConsoleEncoderConfig()
	jsonCfg := zap.NewProductionEncoderConfig()
	jsonCfg.EncodeTime = zapcore.ISO8601TimeEncoder
	jsonCfg.EncodeLevel = zapcore.CapitalLevelEncoder

	writer, err := GetLogFileWriter(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, " Could not write to log file, falling back to stdout:", err)
		writer = zapcore.AddSync(os.Stdout)
	}

	core := zapcore.NewTee(
		zapcore.NewCore(zapcore.NewConsoleEncoder(cfg), zapcore.Lock(os.Stdout), zap.InfoLevel),
		zapcore.NewCore(zapcore.NewJSONEncoder(jsonCfg), writer, zap.InfoLevel),
	)

	combinedLogger := zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))
	zap.ReplaceGlobals(combinedLogger)

	// Also replace the otelzap global logger
	otelzap.ReplaceGlobals(otelzap.New(combinedLogger))

	combinedLogger.Info("Logger fallback initialized",
		zap.String("log_level", os.Getenv("LOG_LEVEL")),
		zap.String("log_path", path),
	)
}

func DefaultConsoleEncoderConfig() zapcore.EncoderConfig {
	cfg := zap.NewProductionEncoderConfig()
	cfg.TimeKey = "" // Disable time in console output for clarity
	cfg.LevelKey = "level"
	cfg.NameKey = "logger"
	cfg.CallerKey = ""   // Disable caller in console output for clarity
	cfg.FunctionKey = "" // Disable function in console output
	cfg.MessageKey = "msg"
	cfg.StacktraceKey = "" // Disable stacktrace in console output
	cfg.LineEnding = zapcore.DefaultLineEnding
	cfg.EncodeLevel = zapcore.CapitalColorLevelEncoder
	cfg.EncodeTime = zapcore.ISO8601TimeEncoder
	cfg.EncodeDuration = zapcore.StringDurationEncoder
	cfg.EncodeCaller = zapcore.ShortCallerEncoder
	cfg.ConsoleSeparator = " "
	return cfg
}
