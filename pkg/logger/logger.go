package logger

import (
	"os"
	"path/filepath"

	"go.uber.org/zap"
)

var log *zap.Logger

// DefaultConfig returns a standard zap.Config object with custom settings.
func DefaultConfig() zap.Config {
	return zap.Config{
		Level:            zap.NewAtomicLevelAt(zap.InfoLevel),                // Default log level: Info
		Development:      true,                                               // Development mode by default
		Encoding:         "json",                                             // JSON log format
		OutputPaths:      []string{"stdout", "/var/log/cyberMonkey/eos.log"}, // Log to console and file
		ErrorOutputPaths: []string{"stderr"},                                 // Log errors to stderr
		//EncoderConfig: zap.EncoderConfig{
			TimeKey:    "time",
			LevelKey:   "level",
			MessageKey: "msg",
			CallerKey:  "caller",
			//EncodeLevel:  zap.LowercaseLevelEncoder, // e.g., "info"
			//EncodeTime:   zap.ISO8601TimeEncoder,    // e.g., "2024-12-27T15:04:05Z"
			//EncodeCaller: zap.ShortCallerEncoder,    // e.g., "file:line"
		},
	}
}

// InitializeWithConfig initializes the logger with a custom zap.Config.
func InitializeWithConfig(cfg zap.Config) {
	// Ensure log directory exists
	for _, path := range cfg.OutputPaths {
		if path != "stdout" && path != "stderr" {
			dir := filepath.Dir(path)
			if _, err := os.Stat(dir); os.IsNotExist(err) {
				if err := os.MkdirAll(dir, 0755); err != nil {
					panic("failed to create log directory: " + err.Error())
				}
			}
		}
	}

	var err error
	log, err = cfg.Build()
	if err != nil {
		panic("failed to initialize logger with custom config: " + err.Error())
	}
}

// Initialize initializes the logger with the default configuration.
func Initialize() {
	InitializeWithConfig(DefaultConfig())
}

// GetLogger returns the global logger instance.
func GetLogger() *zap.Logger {
	if log == nil {
		Initialize()
	}
	return log
}

// LogCommandExecution logs when a command is executed
func LogCommandExecution(cmdName string, args []string) {
	log := GetLogger()
	log.Info("Command executed", zap.String("command", cmdName), zap.Strings("args", args))
}

// Sync flushes any buffered log entries. Should be called before the application exits.
func Sync() {
	if log != nil {
		err := log.Sync()
		if err != nil {
			log.Error("Failed to sync logger", zap.Error(err))
		}
	}
}
