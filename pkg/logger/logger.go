// pkg/logger/logger.go
package logger

import (
	"os"
	"path/filepath"
	"strconv"

	"go.uber.org/zap"
)

var Log *zap.Logger

// DefaultConfig returns a standard zap.Config object with custom settings.
func DefaultConfig() zap.Config {
	return zap.Config{
		Level:            zap.NewAtomicLevelAt(zap.InfoLevel),                // Default log level: Info
		Development:      true,                                               // Development mode by default
		Encoding:         "json",                                             // JSON log format
		OutputPaths:      []string{"stdout", "/var/log/cyberMonkey/eos.log"}, // Log to console and file
		ErrorOutputPaths: []string{"stderr"},                                 // Log errors to stderr
		EncoderConfig:    zap.NewDevelopmentEncoderConfig(),                  // Use pre-configured development encoder

	}
}

// EnsureLogPermissions ensures the correct permissions for the log directory and file.
func EnsureLogPermissions(logFilePath string) error {
	dir := filepath.Dir(logFilePath)

	// Ensure the directory exists
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err // Return the error if directory creation fails
		}
	} else {
		// Set stricter permissions for the directory
		if err := os.Chmod(dir, 0700); err != nil {
			return err // Return the error if permission setting fails
		}
	}


	// Ensure the log file exists
	if _, err := os.Stat(logFilePath); os.IsNotExist(err) {
		file, err := os.Create(logFilePath)
		if err != nil {
			return err // Return the error if file creation fails
		}
		file.Close()
	}

	// Set permissions for the log file (read/write for owner only)
	if err := os.Chmod(logFilePath, 0600); err != nil {
		return err // Return the error if permission setting fails
	}

	return nil
}

// stringToInt converts a string to an integer. Panics if conversion fails.
func stringToInt(s string) int {
	value, err := strconv.Atoi(s)
	if err != nil {
		panic("failed to convert string to int: " + err.Error())
	}
	return value
}

// InitializeWithConfig initializes the logger with a custom zap.Config.
func InitializeWithConfig(cfg zap.Config) {
	// Ensure permissions for each log output path
	for _, path := range cfg.OutputPaths {
		if path != "stdout" && path != "stderr" {
			if err := EnsureLogPermissions(path); err != nil {
				// Log the error to stdout before panicking
				println("Permission error:", err.Error())
				panic("failed to ensure permissions for log file: " + err.Error())
			}
		}
	}

	var err error
	Log, err = cfg.Build()
	if err != nil {
		// Fallback to console-only logging if file logging fails
		cfg.OutputPaths = []string{"stdout"}
		Log, err = cfg.Build()
		if err != nil {
			panic("failed to initialize logger with fallback config: " + err.Error())
		}
	}
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

// LogCommandExecution logs when a command is executed
func LogCommandExecution(cmdName string, args []string) {
	Log := GetLogger()
	Log.Info("Command executed", zap.String("command", cmdName), zap.Strings("args", args))
}

// Sync flushes any buffered log entries. Should be called before the application exits.
func Sync() {
	if Log != nil {
		err := Log.Sync()
		if err != nil && err.Error() != "sync /dev/stdout: invalid argument" { // failed to sync logger kept getting logged for no reason and its sometthing to do with the stout function itself , no this code, so i just said ignore it
			Log.Error("Failed to sync logger", zap.Error(err))
		}
	}
}
