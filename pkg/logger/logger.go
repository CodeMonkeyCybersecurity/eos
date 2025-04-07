// pkg/logger/logger.go
package logger

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/term"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var log *zap.Logger

func GetLogFileWriter(logPath string) zapcore.WriteSyncer {
	file, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠️ Could not open log file %s: %v\n", logPath, err)
		return zapcore.AddSync(os.Stdout)
	}
	return zapcore.AddSync(file)
}

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

	isDev := os.Getenv("ENV") == "development"
	// Use ResolveLogPath to get the appropriate log file path for the OS.
	logPath := ResolveLogPath()
	if logPath == "" {
		// If no candidate path is available, fallback to the current directory.
		logPath = "./eos.log"
	}

	return zap.Config{
		Level:            zap.NewAtomicLevelAt(level),
		Development:      isDev,
		Encoding:         "json",
		OutputPaths:      []string{"stdout", logPath},
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
	if log != nil {
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
	log, err = cfg.Build()
	if err != nil {
		cfg.OutputPaths = []string{"stdout"}
		log, err = cfg.Build()
		if err != nil {
			panic("Failed to initialize logger with fallback config: " + err.Error())
		}
	}
	zap.ReplaceGlobals(log)
	log.Info("Logger successfully initialized", zap.String("log_level", cfg.Level.String()))
}

// Initialize initializes the logger with the default configuration.
func Initialize() {
	if log != nil {
		return
	}
	log = NewLogger()
	zap.ReplaceGlobals(log)
}

// GetLogger returns the global logger instance.
func GetLogger() *zap.Logger {
	if log == nil {
		Initialize()
	}
	return log
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
	if log == nil {
		Initialize() // Ensure logger is initialized
	}
	if log != nil {
		if err := log.Sync(); err != nil {
			if _, ok := err.(*os.PathError); !ok && err.Error() != "sync /dev/stdout: invalid argument" {
				log.Error("Failed to sync logger", zap.Error(err))
			}
			return err
		}
	}
	return nil
}

// ResolveLogPath determines the best default log file path based on the OS.
func ResolveLogPath() string {
	for _, path := range PlatformLogPaths() {
		dir := filepath.Dir(path)
		if err := os.MkdirAll(dir, 0700); err != nil {
			continue
		}
		file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err == nil {
			file.Close()
			return path
		}
	}
	return ""
}

// InitializeWithFallback sets up the Zap logger and returns any error encountered.
func InitializeWithFallback(logPath string) error {
	if logPath == "" {
		return errors.New("no writable log path found")
	}

	cfg := zap.NewProductionEncoderConfig()
	cfg.EncodeTime = zapcore.ISO8601TimeEncoder

	core := zapcore.NewTee(
		zapcore.NewCore(zapcore.NewConsoleEncoder(cfg), zapcore.Lock(os.Stdout), zap.InfoLevel),
		zapcore.NewCore(zapcore.NewJSONEncoder(cfg), GetLogFileWriter(logPath), zap.InfoLevel),
	)

	log = zap.New(core, zap.AddCaller(), zap.AddStacktrace(zap.ErrorLevel))
	zap.ReplaceGlobals(log)

	return nil
}

func NewLogger() *zap.Logger {
	isTerminal := term.IsTerminal(int(os.Stdout.Fd()))

	level := zapcore.InfoLevel
	switch os.Getenv("LOG_LEVEL") {
	case "trace", "debug":
		level = zapcore.DebugLevel
	case "warn":
		level = zapcore.WarnLevel
	case "error":
		level = zapcore.ErrorLevel
	case "fatal":
		level = zapcore.FatalLevel
	}

	encoderCfg := zap.NewProductionEncoderConfig()
	encoderCfg.TimeKey = "T"
	encoderCfg.LevelKey = "L"
	encoderCfg.NameKey = "N"
	encoderCfg.CallerKey = "C"
	encoderCfg.MessageKey = "M"
	encoderCfg.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderCfg.EncodeLevel = func(level zapcore.Level, enc zapcore.PrimitiveArrayEncoder) {
		if isTerminal {
			enc.AppendString(ColouredLevel(level))
		} else {
			enc.AppendString(level.CapitalString())
		}
	}

	core := zapcore.NewCore(
		zapcore.NewConsoleEncoder(encoderCfg),
		zapcore.AddSync(os.Stdout),
		level,
	)

	logger := zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))
	logger.Info("Logger successfully initialized", zap.String("log_level", level.CapitalString()))
	return logger
}

// L returns the globally configured logger instance.
// It's a shorthand for logger.GetLogger() used across packages.
func L() *zap.Logger {
	return GetLogger()
}
