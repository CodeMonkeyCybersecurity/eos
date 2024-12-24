// pkg/utils/logger.go
package utils

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"time"

	"eos/config"

	_ "github.com/lib/pq"
)

// Logger provides methods for logging to both a file and a PostgreSQL database
type Logger struct {
	db          *sql.DB
	logger      *log.Logger
	terminalMin LogLevel
	colorize    bool // Enable or disable colorization
}

type Config struct {
	Database struct {
		Name      string   `yaml:"name"`
		User      string   `yaml:"user"`
		Host      string   `yaml:"host"`
		Port      string   `yaml:"port"`
		Version   string   `yaml:"version"`
		SocketDir string   `yaml:"socketDir"`
		Tables    []string `yaml:"tables"`
	} `yaml:"database"`
	Logging struct {
		Level string `yaml:"level"`
		File  string `yaml:"file"`
	} `yaml:"logging"`
}

var (
	globalLogger *Logger
	once         sync.Once
)

// InitializeLogger sets up the global logger instance
func InitializeLogger(configPath string, logFilePath string, terminalMin LogLevel, colorize bool) error {
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Build connection string from the loaded configuration
	connStr := fmt.Sprintf(
		"host=%s port=%s user=%s dbname=%s",
		cfg.Database.Host,
		cfg.Database.Port,
		cfg.Database.User,
		cfg.Database.Name,
	)

	// Open the database connection
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	// Ensure the connection is alive
	if err := db.Ping(); err != nil {
		return fmt.Errorf("failed to ping database: %w", err)
	}

	// Initialize the logger
	var initErr error
	once.Do(func() {
		globalLogger, initErr = NewLogger(db, logFilePath, terminalMin, colorize)
	})
	return initErr
}

// GetLogger returns the global logger instance
func GetLogger() *Logger {
	if globalLogger == nil {
		log.Fatalf("Logger not initialized. Call InitializeLogger first.")
	}
	return globalLogger
}

// NewLogger initializes a new Logger with file and database logging
func NewLogger(db *sql.DB, logFilePath string, terminalMin LogLevel, colorize bool) (*Logger, error) {
	// Open log file
	file, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}

	// Create a standard logger for file logging
	fileLogger := log.New(file, "", log.Ldate|log.Ltime)

	// Initialize Logger
	return &Logger{
		db:          db,
		logger:      fileLogger,
		terminalMin: terminalMin,
		colorize:    colorize,
	}, nil
}

// LogLevel represents different logging levels
type LogLevel string

const (
	DebugLevel    LogLevel = "DEBUG"
	InfoLevel     LogLevel = "INFO"
	WarnLevel     LogLevel = "WARN"
	ErrorLevel    LogLevel = "ERROR"
	CriticalLevel LogLevel = "CRITICAL"
	FatalLevel    LogLevel = "FATAL"
)

// logPriority maps log levels to their priority
var logPriority = map[LogLevel]int{
	DebugLevel:    0,
	InfoLevel:     1,
	WarnLevel:     2,
	ErrorLevel:    3,
	CriticalLevel: 4,
	FatalLevel:    5,
}

// colorMap maps log levels to ANSI color codes
var colorMap = map[LogLevel]string{
	DebugLevel:    "\033[0;36m", // Cyan
	InfoLevel:     "\033[0;32m", // Green
	WarnLevel:     "\033[0;33m", // Yellow
	ErrorLevel:    "\033[0;31m", // Red
	CriticalLevel: "\033[0;35m", // Magenta
	FatalLevel:    "\033[1;31m", // Bright Red
}

// resetColor resets the terminal color
const resetColor = "\033[0m"

// applyColor applies ANSI color codes to the message if colorization is enabled
func (l *Logger) applyColor(level LogLevel, message string) string {
	// Retrieve metadata
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	hostname, _ := os.Hostname()
	pid := strconv.Itoa(os.Getpid())

	// Retrieve the current user
	user := "unknown"
	if u, err := exec.Command("whoami").Output(); err == nil {
		user = string(u)
		user = user[:len(user)-1] // Remove the trailing newline
	}

	// Format the message with metadata
	formattedMessage := fmt.Sprintf("[%s] [%s] [PID:%s] %s", timestamp, hostname, pid, message)

	// Add color if enabled
	if l.colorize {
		return fmt.Sprintf("%s[%s] %s%s", colorMap[level], level, formattedMessage, resetColor)
	}
	return fmt.Sprintf("[%s] %s", level, formattedMessage)
}

// logToFile logs a message to the file with optional colorization
func (l *Logger) logToFile(level LogLevel, message string) {
	coloredMessage := l.applyColor(level, message)
	l.logger.Println(coloredMessage)
}

// logToDatabase logs a message to the PostgreSQL database
func (l *Logger) logToDatabase(level LogLevel, message string) error {
	if l.db == nil {
		return fmt.Errorf("database connection is nil")
	}

	// Check if the database connection is alive
	if err := l.db.Ping(); err != nil {
		l.logger.Printf("[ERROR] Database connection lost: %v", err)
		return err
	}

	query := `INSERT INTO logs (timestamp, level, message) VALUES ($1, $2, $3)`
	_, err := l.db.Exec(query, time.Now(), level, message)
	return err
}

// shouldLogToTerminal determines if a message should be logged to the terminal
func (l *Logger) shouldLogToTerminal(level LogLevel) bool {
	return logPriority[level] >= logPriority[l.terminalMin]
}

// Log logs a message to both the file and the database
func (l *Logger) Log(level LogLevel, message string) {
	// Log to file
	l.logToFile(level, message)
	if err := l.logToDatabase(level, message); err != nil {
		l.logger.Printf("[ERROR] Failed to log to database: %v", err)
	}
	// Log to terminal if the level meets the minimum requirement
	if l.shouldLogToTerminal(level) {
		color := colorMap[level]
		fmt.Printf("%s[%s] %s%s\n", color, level, message, resetColor)
	}
}

// Debug logs a debug message
func (l *Logger) Debug(message string) {
	l.Log(DebugLevel, message)
}

// Info logs an informational message
func (l *Logger) Info(message string) {
	l.Log(InfoLevel, message)
}

// Warn logs a warning message
func (l *Logger) Warn(message string) {
	l.Log(WarnLevel, message)
}

// Error logs an error message
func (l *Logger) Error(message string) {
	l.Log(ErrorLevel, message)
}

// Critical logs a critical message
func (l *Logger) Critical(message string) {
	l.Log(CriticalLevel, message)
}

// Fatal logs a fatal message and exits the application
func (l *Logger) Fatal(message string) {
	l.Log(FatalLevel, message)
	os.Exit(1)
}
