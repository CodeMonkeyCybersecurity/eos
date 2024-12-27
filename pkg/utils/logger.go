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

	"gopkg.in/yaml.v3"
	_ "github.com/lib/pq"
)

// Config represents the structure of the YAML configuration
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
	LogLevel map[LogLevel]struct {
		LogPriority string `yaml:"logPriority"`
		ColourMap   string `yaml:"colourMap"`
	} `yaml:"logLevel"`
	Reset struct {
		Colour string `yaml:"colour"`
	} `yaml:"reset"`
}

// LogLevel defines the severity levels for logging
type LogLevel string

// load the yaml file and populate the config struct
func LoadConfig(filePath string) (*Config, error) {
	// Open the YAML file
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file: %w", err)
	}
	defer file.Close()

	// Parse the YAML file
	var cfg Config
	decoder := yaml.NewDecoder(file)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("failed to decode config file: %w", err)
	}

	return &cfg, nil
}

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
	resetColour string // Dynamically set reset color
}

var (
	globalLogger *Logger
	once         sync.Once
)

// Update the global logPriority and colourMap variables based on the YAML file:
var (
	logPriority = make(map[LogLevel]int)
	colourMap   = make(map[LogLevel]string)
)

func InitializeLoggerFromConfig(configPath string) error {
    cfg, err := LoadConfig(configPath)
    if err != nil {
        return fmt.Errorf("failed to load config for logger: %w", err)
    }

    // Populate logPriority and colourMap
    for level, properties := range cfg.LogLevel {
        priority, err := strconv.Atoi(properties.LogPriority)
        if err != nil {
            return fmt.Errorf("invalid log priority for level %s: %w", level, err)
        }
        logPriority[LogLevel(level)] = priority
        colourMap[LogLevel(level)] = properties.ColourMap
    }

    return nil
}

// InitializeLogger sets up the global logger instance
func InitializeLogger(configPath, logFilePath string, terminalMin LogLevel, colourize bool) error {
	// Load configuration
	cfg, err := LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
		
	// Initialize logPriority and colourMap
	if err := InitializeLoggerFromConfig(configPath); err != nil {
		return fmt.Errorf("Failed to initialize logger config: %w", err)
	}

	// Database connection string
	connStr := fmt.Sprintf("host=%s dbname=%s user=%s sslmode=disable", cfg.Database.SocketDir, cfg.Database.Name, cfg.Database.User)
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return fmt.Errorf("Failed to open a database connection: %v", err)
	}

	// Fallback for reset colour
	resetColour := cfg.Reset.Colour
	if resetColour == "" {
		resetColour = "\033[0m"
	}

	// Initialize the logger
	var initErr error
	once.Do(func() {
		globalLogger, initErr = NewLogger(db, logFilePath, terminalMin, colourize, resetColour)
	})
	if initErr != nil {
		return initErr
	}

	return nil
}

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
		return fmt.Sprintf("%s[%s] %s%s", colourMap[level], level, formattedMessage, l.resetColour)
	}
	return fmt.Sprintf("[%s] %s", level, formattedMessage)
}
				  
// GetLogger returns the global logger instance
func GetLogger() *Logger {
	if globalLogger == nil {
		log.Fatalf("Logger not initialized. Call InitializeLogger first.")
	}
	return globalLogger
}

// NewLogger initializes a new Logger with file and database logging
func NewLogger(db *sql.DB, logFilePath string, terminalMin LogLevel, colourize bool, resetColour string) (*Logger, error) {
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
		resetColour: resetColour, // Store the reset color
	}, nil
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
