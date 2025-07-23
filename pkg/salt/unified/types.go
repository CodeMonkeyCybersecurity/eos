// package unified provides a centralized, idempotent Salt client interface for EOS
// This package consolidates all Salt API detection, authentication, and execution patterns
// found throughout the codebase into a single, consistent interface.
package unified

import (
	"fmt"
	"time"

	"go.uber.org/zap"
)

// ExecutionMode represents the mode of Salt execution
type ExecutionMode int

const (
	// ModeAPI indicates Salt API is available and being used
	ModeAPI ExecutionMode = iota
	// ModeLocal indicates salt-call (masterless) mode is being used
	ModeLocal
	// ModeUnavailable indicates Salt is not available at all
	ModeUnavailable
)

func (m ExecutionMode) String() string {
	switch m {
	case ModeAPI:
		return "api"
	case ModeLocal:
		return "local"
	case ModeUnavailable:
		return "unavailable"
	default:
		return "unknown"
	}
}

// ClientConfig provides comprehensive configuration for the unified Salt client
type ClientConfig struct {
	// API Configuration
	APIURL             string        `env:"SALT_API_URL" default:"https://localhost:8000"`
	Username           string        `env:"SALT_API_USER" default:"eos-service"`
	Password           string        `env:"SALT_API_PASSWORD"`
	EAuth              string        `env:"SALT_API_EAUTH" default:"pam"`
	
	// Behavior Configuration
	PreferAPI          bool          `env:"SALT_PREFER_API" default:"true"`
	FallbackToLocal    bool          `env:"SALT_FALLBACK_LOCAL" default:"true"`
	Timeout            time.Duration `env:"SALT_API_TIMEOUT" default:"5m"`
	MaxRetries         int           `env:"SALT_API_MAX_RETRIES" default:"3"`
	InsecureSkipVerify bool          `env:"SALT_API_INSECURE" default:"false"`
	
	// Paths and Files
	ConfigPath         string        `env:"SALT_CONFIG_PATH" default:"/etc/salt/master.d/api.conf"`
	CredentialsPath    string        `env:"SALT_CREDENTIALS_PATH" default:"/etc/salt/api-credentials"`
	
	// Logging
	Logger             *zap.Logger
}

// Command represents a Salt command to execute
type Command struct {
	// Target specification
	Target     string                 // Target minions (or "local" for salt-call)
	TargetType string                 // Target type (glob, pcre, etc.)
	
	// Function specification
	Function   string                 // Salt function to execute
	Args       []interface{}          // Function arguments
	Kwargs     map[string]interface{} // Function keyword arguments
	
	// Execution options
	Timeout    time.Duration          // Command timeout
	Async      bool                   // Execute asynchronously
}

// StateCommand represents a Salt state application command
type StateCommand struct {
	// Target specification
	Target     string                 // Target minions (or "local" for salt-call)
	
	// State specification
	State      string                 // State name to apply
	Pillar     map[string]interface{} // Pillar data
	
	// Execution options
	Test       bool                   // Test mode (don't actually apply)
	Timeout    time.Duration          // State timeout
	
	// Progress reporting
	ProgressCallback func(StateProgress) // Called for progress updates
}

// CommandResult represents the result of a Salt command execution
type CommandResult struct {
	// Execution metadata
	Success    bool                   // Whether command succeeded
	Mode       ExecutionMode          // Which execution mode was used
	Duration   time.Duration          // How long it took
	
	// Result data
	Raw        map[string]interface{} // Raw response from Salt
	Output     string                 // Formatted output
	Errors     []string               // Any errors encountered
	
	// Job information (API mode only)
	JobID      string                 // Job ID for async commands
}

// StateResult represents the result of a Salt state application
type StateResult struct {
	// Execution metadata
	Success    bool                   // Whether state application succeeded
	Mode       ExecutionMode          // Which execution mode was used
	Duration   time.Duration          // How long it took
	
	// State results
	States     map[string]StateInfo   // Results for each state
	Summary    StateSummary           // Overall summary
	Output     string                 // Formatted output
	Errors     []string               // Any errors encountered
	
	// Progress information
	Total      int                    // Total states processed
	Succeeded  int                    // Number of successful states
	Failed     int                    // Number of failed states
	Changed    int                    // Number of states that made changes
}

// StateInfo represents information about a single state execution
type StateInfo struct {
	Name        string                 // State name
	Result      bool                   // State result (success/failure)
	Changes     map[string]interface{} // Changes made by the state
	Comment     string                 // State comment/message
	Duration    time.Duration          // Time taken for this state
}

// StateSummary provides a summary of state execution
type StateSummary struct {
	Total       int    // Total states
	Succeeded   int    // Successful states
	Failed      int    // Failed states
	Changed     int    // States that made changes
	Unchanged   int    // States that made no changes
}

// StateProgress represents progress information during state execution
type StateProgress struct {
	// Progress tracking
	Current     int    // Current state number
	Total       int    // Total states to execute
	
	// Current state information
	State       string // Current state name
	Message     string // Progress message
	Success     bool   // Whether current state succeeded
	Completed   bool   // Whether current state is completed
	
	// Timing
	StartTime   time.Time
	Duration    time.Duration
}

// AvailabilityCheck represents the result of checking Salt availability
type AvailabilityCheck struct {
	// Binary availability
	SaltBinaryAvailable    bool   // Is 'salt' binary available
	SaltCallAvailable     bool   // Is 'salt-call' binary available
	
	// Package installation
	SaltPackageInstalled  bool   // Is salt-master/salt-minion installed
	SaltAPIPackageInstalled bool // Is salt-api package installed
	
	// Service status
	SaltMasterRunning     bool   // Is salt-master service running
	SaltMinionRunning     bool   // Is salt-minion service running  
	SaltAPIRunning        bool   // Is salt-api service running
	
	// Configuration
	ConfigFileExists      bool   // Does API config file exist
	CredentialsAvailable  bool   // Are API credentials available
	
	// Connectivity
	APIConnectable        bool   // Can we connect to Salt API
	APIAuthenticated      bool   // Can we authenticate to Salt API
	
	// Overall assessment
	RecommendedMode       ExecutionMode // Which mode should be used
	Issues                []string      // Any issues found
}

// AuthenticationInfo represents Salt API authentication details
type AuthenticationInfo struct {
	// Credentials
	Username    string    // API username
	Password    string    // API password (not logged)
	EAuth       string    // Authentication method
	
	// Token information
	Token       string    // Current auth token (not logged)
	TokenExpiry time.Time // When token expires
	
	// Status
	Authenticated bool     // Whether currently authenticated
	LastAuth      time.Time // When we last authenticated
}

// ClientStatus represents the overall status of the Salt client
type ClientStatus struct {
	// Configuration
	Config          ClientConfig      // Current configuration
	
	// Availability
	Availability    AvailabilityCheck // Availability check results
	
	// Authentication
	Auth            AuthenticationInfo // Authentication status
	
	// Current state
	CurrentMode     ExecutionMode     // Currently active mode
	Initialized     bool              // Whether client is initialized
	Healthy         bool              // Whether client is healthy
	
	// Statistics
	CommandsExecuted int              // Number of commands executed
	StatesApplied    int              // Number of states applied
	LastActivity     time.Time        // Last activity timestamp
}

// Error types for better error handling
type ErrorType int

const (
	ErrorTypeNetwork ErrorType = iota      // Network/connectivity errors
	ErrorTypeAuth                          // Authentication errors
	ErrorTypeConfig                        // Configuration errors
	ErrorTypeCommand                       // Command execution errors
	ErrorTypeState                         // State application errors
	ErrorTypeTimeout                       // Timeout errors
	ErrorTypeUnavailable                   // Salt unavailable errors
)

func (e ErrorType) String() string {
	switch e {
	case ErrorTypeNetwork:
		return "network"
	case ErrorTypeAuth:
		return "authentication"
	case ErrorTypeConfig:
		return "configuration"
	case ErrorTypeCommand:
		return "command"
	case ErrorTypeState:
		return "state"
	case ErrorTypeTimeout:
		return "timeout"
	case ErrorTypeUnavailable:
		return "unavailable"
	default:
		return "unknown"
	}
}

// SaltError represents a Salt-specific error with additional context
type SaltError struct {
	Type      ErrorType              // Type of error
	Message   string                 // Error message
	Details   map[string]interface{} // Additional error details
	Cause     error                  // Underlying error
	Mode      ExecutionMode          // Mode when error occurred
	Retryable bool                   // Whether error is retryable
}

func (e *SaltError) Error() string {
	return fmt.Sprintf("salt %s error: %s", e.Type, e.Message)
}

func (e *SaltError) Unwrap() error {
	return e.Cause
}

// Constants for common configuration values
const (
	// Default timeout values
	DefaultCommandTimeout = 30 * time.Second
	DefaultStateTimeout   = 10 * time.Minute
	DefaultAPITimeout     = 5 * time.Minute
	
	// Default retry values
	DefaultMaxRetries     = 3
	DefaultRetryDelay     = 2 * time.Second
	
	// Default paths
	DefaultAPIConfigPath     = "/etc/salt/master.d/api.conf"
	DefaultCredentialsPath   = "/etc/salt/api-credentials"
	DefaultMasterConfigPath  = "/etc/salt/master"
	DefaultMinionConfigPath  = "/etc/salt/minion"
	
	// Default network values
	DefaultAPIURL         = "https://localhost:8000"
	DefaultAPIUser        = "eos-service"
	DefaultEAuth          = "pam"
	
	// Salt binary paths
	SaltBinaryName        = "salt"
	SaltCallBinaryName    = "salt-call"
	SaltAPIBinaryName     = "salt-api"
	SaltMasterBinaryName  = "salt-master"
	SaltMinionBinaryName  = "salt-minion"
)