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

	"gopkg.in/yaml.v3"
	_ "github.com/lib/pq"
)

// LogLevel defines the severity levels for logging
type LogLevel string

const (
	Debug    LogLevel = "Debug"
	Info     LogLevel = "Info"
	Warn     LogLevel = "Warn"
	Error    LogLevel = "Error"
	Critical LogLevel = "Critical"
	Fatal    LogLevel = "Fatal"
)

// Logger provides methods for logging to both a file and a PostgreSQL database
type Logger struct {
	db          *sql.DB
	logger      *log.Logger
	terminalMin LogLevel
	colourize    bool // Enable or disable colourization
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
	Reset struct {
		Reset    string `yaml:"Reset"`	
	} `yaml:"reset"`
}

var (
	globalLogger *Logger
	once         sync.Once
)

var logPriority = map[LogLevel]int{
    "Debug":    0,
    "Info":     1,
    "Warn":     2,
    "Error":    3,
    "Critical": 4,
    "Fatal":    5,
}

// InitializeLogger sets up the global logger instance
func InitializeLogger(configPath string, logFilePath string, terminalMin LogLevel, colourize bool) error {
	yamlFilePath := "config/default.yaml"
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Database
	// Connection string
	connStr := fmt.Sprintf("host=%s dbname=%s user=%s port=%s sslmode=disable", config.Database.SocketDir, config.Database.Name, config.Database.User, config.Database.Port)
	// Open a connection
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Failed to open a connection: %v", err)
	}
	// Initialize the logger
	once.Do(func() {
		globalLogger, err = NewLogger(db, logFilePath, terminalMin, colourize)
	})
	return err
}

// GetLogger returns the global logger instance
func GetLogger() *Logger {
	if globalLogger == nil {
		log.Fatalf("Logger not initialized. Call InitializeLogger first.")
	}
	return globalLogger
}

// NewLogger initializes a new Logger with file and database logging
func NewLogger(db *sql.DB, logFilePath string, terminalMin LogLevel, colourize bool) (*Logger, error) {
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
		colourize:    colourize,
	}, nil
}

// resetcolour resets the terminal colour
const resetColour = "\033[0m"

// applyColour applies ANSI colour codes to the message if colourization is enabled
func (l *Logger) applyColour(level LogLevel, message string) string {
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

	// Add colour if enabled
	if l.colourize {
		return fmt.Sprintf("%s[%s] %s%s", colourMap[level], level, formattedMessage)
	}
	return fmt.Sprintf("[%s] %s", level, formattedMessage)
}

// logToFile logs a message to the file with optional colourization
func (l *Logger) logToFile(level LogLevel, message string) {
	colouredMessage := l.applyColour(level, message)
	l.logger.Println(colouredMessage)
}

// logToDatabase logs a message to the database
func (l *Logger) logToDatabase(level LogLevel, message string) error {
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
		colour := colourMap[level]
		fmt.Printf("%s[%s] %s%s\n", colour, level, message)
	}
}

// Debug logs a debug message
func (l *Logger) Debug(message string) {
	l.Log(Debug, message)
}

// Info logs an informational message
func (l *Logger) Info(message string) {
	l.Log(Info, message)
}

// Warn logs a warning message
func (l *Logger) Warn(message string) {
	l.Log(Warn, message)
}

// Error logs an error message
func (l *Logger) Error(message string) {
	l.Log(Error, message)
}

// Critical logs a critical message
func (l *Logger) Critical(message string) {
	l.Log(Critical, message)
}

// Fatal logs a fatal message and exits the application
func (l *Logger) Fatal(message string) {
	l.Log(Fatal, message)
	os.Exit(1)
}



	// Insert log entry into the 'logs' table
	// insertQuery := "INSERT INTO logs (timestamp, level, message) VALUES ($1, $2, $3)"
	// _, err = db.Exec(insertQuery, time.Now(), config.Logging.Level, "Test log entry")
	// if err != nil {
	// 	log.Fatalf("Failed to insert log entry: %v", err)
	// }

