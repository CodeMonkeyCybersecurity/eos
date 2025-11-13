// pkg/logger/config.go

package logger

import (
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// DefaultConfig returns a production-ready Zap config with sensible defaults.
func DefaultConfig(rc *eos_io.RuntimeContext) zap.Config {
	logPath := ResolveLogPath(rc)
	if logPath == "" {
		logPath = "./eos.log"
	}

	encoderCfg := zap.NewProductionEncoderConfig()
	encoderCfg.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderCfg.EncodeLevel = zapcore.CapitalLevelEncoder

	return zap.Config{
		Level:            zap.NewAtomicLevelAt(ParseLogLevel(os.Getenv("LOG_LEVEL"))),
		Development:      os.Getenv("ENV") == "development",
		Encoding:         "json",
		OutputPaths:      []string{"stdout", logPath},
		ErrorOutputPaths: []string{"stderr"},
		EncoderConfig:    encoderCfg,
	}
}

// ParseLogLevel maps string env input to zapcore.Level safely.
func ParseLogLevel(level string) zapcore.Level {
	level = strings.ToUpper(strings.TrimSpace(level))

	switch level {
	case "TRACE", "DEBUG":
		return zapcore.DebugLevel
	case "WARN":
		return zapcore.WarnLevel
	case "ERROR":
		return zapcore.ErrorLevel
	case "FATAL":
		return zapcore.FatalLevel
	case "DPANIC":
		return zapcore.DPanicLevel
	default:
		return zapcore.InfoLevel
	}
}
