/* pkg/logger/config.go */

package logger

import (
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// DefaultConfig returns a sane default Zap config.
func defaultConfig() zap.Config {
	logPath := ResolveLogPath()
	if logPath == "" {
		logPath = "./eos.log"
	}

	return zap.Config{
		Level:            zap.NewAtomicLevelAt(parseLogLevel(os.Getenv("LOG_LEVEL"))),
		Development:      os.Getenv("ENV") == "development",
		Encoding:         "json",
		OutputPaths:      []string{"stdout", logPath},
		ErrorOutputPaths: []string{"stderr"},
		EncoderConfig:    zap.NewDevelopmentEncoderConfig(),
	}
}

func parseLogLevel(level string) zapcore.Level {
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
