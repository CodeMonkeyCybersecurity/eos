// pkg/logger/logger.go
package logger

import (
	"os"
	"path/filepath"

	"go.uber.org/zap"
)

var Log *zap.Logger

// DefaultConfig returns a standard zap.Config object with custom settings.
func DefaultConfig() zap.Config {
	level := zap.InfoLevel
	switch os.Getenv("LOG_LEVEL") {
	case "trace":
		level = zap.DebugLevel
	case "debug":
		level = zap.DebugLevel
	case "dpanic":
		level = zap.DPanicLevel
	case "warn":
		level = zap.WarnLevel
	case "error":
		level = zap.ErrorLevel
	case "fatal":
		level = zap.FatalLevel
	}

	return zap.Config{
		Level:            zap.NewAtomicLevelAt(level),
		Development:      true,
		Encoding:         "json",
		OutputPaths:      []string{"stdout", "/var/log/cyberMonkey/eos.log"},
		ErrorOutputPaths: []string{"stderr"},
		EncoderConfig:    zap.NewDevelopmentEncoderConfig(),
	}
}

// EnsureLogPermissions ensures correct permissions for log directory & file.
func EnsureLogPermissions(logFilePath string) error {
	dir := filepath.Dir(logFilePath)

	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return err
	}

	if _, err := os.Stat(logFilePath); os.IsNotExist(err) {
		file, err := os.Create(logFilePath)
		if err != nil {
			return err
		}
		file.Close()
	}

	return os.Chmod(logFilePath, 0600)
}

// InitializeWithConfig initializes the logger with a given config.
func InitializeWithConfig(cfg zap.Config) {
	if Log != nil {
		return
	}

	for _, path := range cfg.OutputPaths {
		if path != "stdout" && path != "stderr" {
			if err := EnsureLogPermissions(path); err != nil {
				println("Permission error:", err.Error())
				panic("Failed to ensure permissions for log file: " + err.Error())
			}
		}
	}

	var err error
	Log, err = cfg.Build()
	if err != nil {
		cfg.OutputPaths = []string{"stdout"}
		Log, err = cfg.Build()
		if err != nil {
			panic("Failed to initialize logger with fallback config: " + err.Error())
		}
	}
	zap.ReplaceGlobals(Log)
	Log.Info("Logger successfully initialized", zap.String("log_level", cfg.Level.String()))
}

// Initialize initializes the logger with the default configuration.
func Initialize() {
	InitializeWithConfig(DefaultConfig())
}

// GetLogger returns the global logger instance.
func GetLogger() *zap.Logger {
	if Log == nil {
		Initialize()
	}
	return Log
}

// Info logs an informational message.
func Info(msg string, fields ...zap.Field) {
	GetLogger().Info(msg, fields...)
}

// Warn logs a warning message.
func Warn(msg string, fields ...zap.Field) {
	GetLogger().Warn(msg, fields...)
}

// Error logs an error message.
func Error(msg string, fields ...zap.Field) {
	GetLogger().Error(msg, fields...)
}

// Debug logs a debug message.
func Debug(msg string, fields ...zap.Field) {
	GetLogger().Debug(msg, fields...)
}

// Fatal logs a fatal error and exits.
func Fatal(msg string, fields ...zap.Field) {
	GetLogger().Fatal(msg, fields...)
}

// Panic logs a message and panics.
func Panic(msg string, fields ...zap.Field) {
	GetLogger().Panic(msg, fields...)
}

// Sync flushes any buffered log entries and safely ignores stdout sync errors.
func Sync() error {
	if Log == nil {
		Initialize() // Ensure logger is initialized
	}
	if Log != nil {
		if err := Log.Sync(); err != nil {
			if _, ok := err.(*os.PathError); !ok && err.Error() != "sync /dev/stdout: invalid argument" {
				Log.Error("Failed to sync logger", zap.Error(err))
			}
			return err
		}
	}
	return nil
}

// L returns the globally configured logger instance.
// It's a shorthand for logger.GetLogger() used across packages.
func L() *zap.Logger {
	return GetLogger()
}
