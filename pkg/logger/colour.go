// pkg/logger/colour.go

package logger

import (
	zapcore "go.uber.org/zap/zapcore"
)

func ColouredLevel(level zapcore.Level) string {
	switch level {
	case zapcore.DebugLevel:
		return "\033[90mDEBUG\033[0m" // Gray
	case zapcore.InfoLevel:
		return "\033[32mINFO\033[0m" // Green
	case zapcore.WarnLevel:
		return "\033[33mWARN\033[0m" // Yellow
	case zapcore.ErrorLevel:
		return "\033[31mERROR\033[0m" // Red
	case zapcore.DPanicLevel, zapcore.PanicLevel, zapcore.FatalLevel:
		return "\033[1;31mFATAL\033[0m" // Bold Red
	default:
		return level.CapitalString()
	}
}
