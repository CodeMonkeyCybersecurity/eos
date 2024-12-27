package logger

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"

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
		//TimeKey:    "time",
		//LevelKey:   "level",
		//MessageKey: "msg",
		//CallerKey:  "caller",
		//EncodeLevel:  zap.LowercaseLevelEncoder, // e.g., "info"
		//EncodeTime:   zap.ISO8601TimeEncoder,    // e.g., "2024-12-27T15:04:05Z"
		//EncodeCaller: zap.ShortCallerEncoder,    // e.g., "file:line"
		//},
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

	// Set ownership to eos_user
	if err := setOwnershipToEosUser(dir); err != nil {
		return err // Return the error if ownership setting fails
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

	// Set ownership of the log file to eos_user
	if err := setOwnershipToEosUser(logFilePath); err != nil {
		return err // Return the error if ownership setting fails
	}

	return nil
}

// setOwnershipToEosUser sets the ownership of the given path to eos_user.
func setOwnershipToEosUser(path string) error {
	eosUser, err := user.Lookup("eos_user")
	if err != nil {
		return err // Return the error if eos_user lookup fails
	}

	uid := stringToInt(eosUser.Uid)
	gid := stringToInt(eosUser.Gid)

	return os.Chown(path, uid, gid) // Change ownership to eos_user
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
	log, err = cfg.Build()
	if err != nil {
		// Fallback to console-only logging if file logging fails
		cfg.OutputPaths = []string{"stdout"}
		log, err = cfg.Build()
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
