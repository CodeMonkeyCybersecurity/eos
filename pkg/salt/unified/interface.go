package unified

import (
	"context"
	"time"
)

// UnifiedSaltClient is the main interface for all Salt interactions in EOS
// This interface consolidates all the different Salt client patterns found
// throughout the codebase into a single, consistent API.
type UnifiedSaltClient interface {
	// Client Lifecycle Management
	Initialize(ctx context.Context, config ClientConfig) error
	Close() error
	HealthCheck(ctx context.Context) error
	GetStatus(ctx context.Context) (*ClientStatus, error)
	
	// Availability and Mode Detection
	CheckAvailability(ctx context.Context) (*AvailabilityCheck, error)
	GetExecutionMode() ExecutionMode
	IsAPIAvailable(ctx context.Context) bool
	IsSaltInstalled(ctx context.Context) bool
	
	// Idempotent Setup Methods
	EnsureSaltInstalled(ctx context.Context) error
	EnsureSaltAPIConfigured(ctx context.Context) error
	EnsureSaltAPIRunning(ctx context.Context) error
	EnsureCredentialsConfigured(ctx context.Context) error
	
	// Authentication Management
	Authenticate(ctx context.Context) error
	RefreshToken(ctx context.Context) error
	IsAuthenticated(ctx context.Context) bool
	GetAuthInfo(ctx context.Context) (*AuthenticationInfo, error)
	
	// Command Execution
	ExecuteCommand(ctx context.Context, cmd Command) (*CommandResult, error)
	ExecuteCommandWithRetry(ctx context.Context, cmd Command, maxRetries int) (*CommandResult, error)
	
	// State Management
	ExecuteState(ctx context.Context, state StateCommand) (*StateResult, error)
	ExecuteStateWithRetry(ctx context.Context, state StateCommand, maxRetries int) (*StateResult, error)
	TestState(ctx context.Context, state StateCommand) (*StateResult, error)
	
	// Convenience Methods (high-level operations)
	Ping(ctx context.Context, target string) (bool, error)
	GetGrains(ctx context.Context, target string, grains []string) (map[string]interface{}, error)
	RunShellCommand(ctx context.Context, target string, command string) (string, error)
	ApplyState(ctx context.Context, target string, state string, pillar map[string]interface{}) (*StateResult, error)
	CheckServiceStatus(ctx context.Context, target string, serviceName string) (map[string]interface{}, error)
	
	// Event and Job Management (API mode only)
	GetJobStatus(ctx context.Context, jobID string) (*CommandResult, error)
	WaitForJob(ctx context.Context, jobID string, timeout time.Duration) (*CommandResult, error)
	StreamEvents(ctx context.Context, eventTypes []string) (<-chan Event, error)
	
	// Configuration Management
	UpdateConfig(ctx context.Context, newConfig ClientConfig) error
	GetConfig() ClientConfig
	ValidateConfig(ctx context.Context, config ClientConfig) error
}

// Factory function interface for creating clients
type ClientFactory interface {
	NewClient(config ClientConfig) (UnifiedSaltClient, error)
	NewClientFromEnv() (UnifiedSaltClient, error)
	NewClientWithDefaults() (UnifiedSaltClient, error)
}

// Event represents a Salt event (API mode only)
type Event struct {
	Tag       string                 // Event tag
	Data      map[string]interface{} // Event data
	Timestamp time.Time             // When event occurred
}

// MockClient interface for testing
type MockClient interface {
	UnifiedSaltClient
	
	// Mock control methods
	SetAPIAvailable(available bool)
	SetSaltInstalled(installed bool)
	SetAuthenticationResult(success bool, err error)
	SetCommandResult(result *CommandResult, err error)
	SetStateResult(result *StateResult, err error)
	
	// Verification methods
	GetLastCommand() *Command
	GetLastState() *StateCommand
	GetCallCount(method string) int
	Reset()
}