// Package managers provides a unified framework for resource management across Eos
//
// This package consolidates the 37+ different Manager patterns found throughout
// the codebase into a consistent, secure, and maintainable framework.
package managers

import (
	"context"
	"time"
)

// ResourceManager defines the core interface that all resource managers must implement
// This follows the Assess → Intervene → Evaluate pattern documented in CLAUDE.md
type ResourceManager[T any] interface {
	// Core CRUD operations
	Create(ctx context.Context, resource T) (*OperationResult, error)
	Read(ctx context.Context, id string) (T, error)
	Update(ctx context.Context, resource T) (*OperationResult, error)
	Delete(ctx context.Context, id string) (*OperationResult, error)
	List(ctx context.Context, options *ListOptions) ([]T, error)

	// Lifecycle management
	Start(ctx context.Context, id string) (*OperationResult, error)
	Stop(ctx context.Context, id string) (*OperationResult, error)
	Restart(ctx context.Context, id string) (*OperationResult, error)

	// Health and status
	GetStatus(ctx context.Context, id string) (*ResourceStatus, error)
	HealthCheck(ctx context.Context, id string) (*HealthCheckResult, error)

	// Validation and configuration
	Validate(ctx context.Context, resource T) error
	Configure(ctx context.Context, id string, config map[string]interface{}) (*OperationResult, error)
}

// OperationResult represents the result of a management operation
type OperationResult struct {
	Success   bool          `json:"success"`
	Message   string        `json:"message"`
	Duration  time.Duration `json:"duration"`
	DryRun    bool          `json:"dry_run"`
	Error     string        `json:"error,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
	Timestamp time.Time     `json:"timestamp"`
}

// ResourceStatus represents the current status of a managed resource
type ResourceStatus struct {
	ID            string                 `json:"id"`
	State         ResourceState          `json:"state"`
	Health        HealthState            `json:"health"`
	LastUpdate    time.Time              `json:"last_update"`
	Configuration map[string]interface{} `json:"configuration,omitempty"`
	Metrics       map[string]interface{} `json:"metrics,omitempty"`
	Errors        []string               `json:"errors,omitempty"`
}

// ResourceState represents the operational state of a resource
type ResourceState string

const (
	StateUnknown  ResourceState = "unknown"
	StateCreating ResourceState = "creating"
	StateActive   ResourceState = "active"
	StateInactive ResourceState = "inactive"
	StateFailed   ResourceState = "failed"
	StateDeleting ResourceState = "deleting"
	StateDeleted  ResourceState = "deleted"
)

// HealthState represents the health status of a resource
type HealthState string

const (
	HealthUnknown   HealthState = "unknown"
	HealthHealthy   HealthState = "healthy"
	HealthUnhealthy HealthState = "unhealthy"
	HealthDegraded  HealthState = "degraded"
	HealthCritical  HealthState = "critical"
)

// HealthCheckResult represents the result of a health check operation
type HealthCheckResult struct {
	Overall    HealthState               `json:"overall"`
	Checks     map[string]CheckResult    `json:"checks"`
	Duration   time.Duration             `json:"duration"`
	Timestamp  time.Time                 `json:"timestamp"`
	Errors     []string                  `json:"errors,omitempty"`
	Warnings   []string                  `json:"warnings,omitempty"`
}

// CheckResult represents the result of an individual health check
type CheckResult struct {
	Name     string      `json:"name"`
	Status   HealthState `json:"status"`
	Message  string      `json:"message"`
	Duration time.Duration `json:"duration"`
	Value    interface{} `json:"value,omitempty"`
}

// ListOptions provides options for listing operations
type ListOptions struct {
	Limit   int               `json:"limit,omitempty"`
	Offset  int               `json:"offset,omitempty"`
	Filter  map[string]string `json:"filter,omitempty"`
	Sort    string            `json:"sort,omitempty"`
	Fields  []string          `json:"fields,omitempty"`
}

// BaseManager provides common functionality for all resource managers
// All concrete managers should embed this struct to inherit standard behavior
type BaseManager struct {
	name   string
	config *ManagerConfig
}

// ManagerConfig provides configuration options for managers
type ManagerConfig struct {
	DryRun      bool          `json:"dry_run"`
	Timeout     time.Duration `json:"timeout"`
	RetryCount  int           `json:"retry_count"`
	RetryDelay  time.Duration `json:"retry_delay"`
	LogLevel    string        `json:"log_level"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// NewBaseManager creates a new base manager with the given configuration
func NewBaseManager(name string, config *ManagerConfig) *BaseManager {
	if config == nil {
		config = DefaultManagerConfig()
	}
	
	return &BaseManager{
		name:   name,
		config: config,
	}
}

// DefaultManagerConfig returns default configuration for managers
func DefaultManagerConfig() *ManagerConfig {
	return &ManagerConfig{
		DryRun:     false,
		Timeout:    time.Minute * 5,
		RetryCount: 3,
		RetryDelay: time.Second * 2,
		LogLevel:   "info",
		Metadata:   make(map[string]interface{}),
	}
}

// GetName returns the manager name
func (bm *BaseManager) GetName() string {
	return bm.name
}

// GetConfig returns the manager configuration
func (bm *BaseManager) GetConfig() *ManagerConfig {
	return bm.config
}

// CreateOperationResult creates a standardized operation result
func (bm *BaseManager) CreateOperationResult(success bool, message string, duration time.Duration, err error) *OperationResult {
	result := &OperationResult{
		Success:   success,
		Message:   message,
		Duration:  duration,
		DryRun:    bm.config.DryRun,
		Timestamp: time.Now(),
		Metadata:  make(map[string]interface{}),
	}
	
	if err != nil {
		result.Error = err.Error()
		result.Success = false
	}
	
	return result
}

// ExecuteWithTimeout executes a function with the configured timeout
func (bm *BaseManager) ExecuteWithTimeout(ctx context.Context, operation func(context.Context) error) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, bm.config.Timeout)
	defer cancel()
	
	return operation(timeoutCtx)
}