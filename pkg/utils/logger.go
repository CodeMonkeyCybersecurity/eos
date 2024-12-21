// pkg/utils/logger.go
package utils

import (
	"fmt"
	"log"
	"os"
)

// Logger provides methods for structured logging
type Logger struct {
	logger *log.Logger
}

// NewLogger creates a new logger instance
func NewLogger(logFile string) (*Logger, error) {
	file, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}
	return &Logger{
		logger: log.New(file, "", log.Ldate|log.Ltime),
	}, nil
}

// Info logs an informational message
func (l *Logger) Info(message string) {
	l.logger.Printf("[INFO] %s\n", message)
}

// Warn logs a warning message
func (l *Logger) Warn(message string) {
	l.logger.Printf("[WARN] %s\n", message)
}

// Error logs an error message
func (l *Logger) Error(message string) {
	l.logger.Printf("[ERROR] %s\n", message)
}
