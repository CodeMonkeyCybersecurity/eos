package strategy

import (
	"context"
	"fmt"
	"time"
)

// DeploymentStrategy defines available deployment strategies
type DeploymentStrategy string

const (
	DirectStrategy     DeploymentStrategy = "direct"      // Current approach for dev/test
	SaltStrategy       DeploymentStrategy = "salt"        // Salt-based configuration management
	SaltNomadStrategy  DeploymentStrategy = "salt-nomad"  // Salt + Nomad orchestration
	FullStackStrategy  DeploymentStrategy = "full"        // Full Salt→Terraform→Nomad stack
)

// Component represents a deployable component
type Component struct {
	Name        string                 `json:"name"`
	Type        ComponentType          `json:"type"`
	Strategy    DeploymentStrategy     `json:"strategy"`
	Config      map[string]interface{} `json:"config"`
	Version     string                 `json:"version"`
	Environment string                 `json:"environment"`
}

// ComponentType defines the type of component
type ComponentType string

const (
	ServiceType        ComponentType = "service"
	DatabaseType       ComponentType = "database"
	StorageType        ComponentType = "storage"
	InfrastructureType ComponentType = "infrastructure"
)

// Deployer interface for all deployment strategies
type Deployer interface {
	// Core deployment operations
	Deploy(ctx context.Context, component *Component) (*DeploymentResult, error)
	Validate(ctx context.Context, component *Component) error
	Rollback(ctx context.Context, deployment *DeploymentResult) error
	GetStatus(ctx context.Context, component *Component) (*DeploymentStatus, error)
	
	// Strategy-specific operations
	GetStrategy() DeploymentStrategy
	SupportsComponent(componentType ComponentType) bool
}

// DeploymentResult contains deployment outcome information
type DeploymentResult struct {
	ID            string                 `json:"id"`
	Component     string                 `json:"component"`
	Strategy      DeploymentStrategy     `json:"strategy"`
	Status        string                 `json:"status"`
	StartTime     time.Time              `json:"start_time"`
	EndTime       *time.Time             `json:"end_time,omitempty"`
	Outputs       map[string]interface{} `json:"outputs,omitempty"`
	Error         string                 `json:"error,omitempty"`
	RollbackInfo  *RollbackInfo          `json:"rollback_info,omitempty"`
}

// DeploymentStatus represents the current status of a deployment
type DeploymentStatus struct {
	Component   string                 `json:"component"`
	Status      string                 `json:"status"`
	Healthy     bool                   `json:"healthy"`
	LastChecked time.Time              `json:"last_checked"`
	Details     map[string]interface{} `json:"details,omitempty"`
}

// RollbackInfo contains information needed for rollback
type RollbackInfo struct {
	PreviousVersion string                 `json:"previous_version"`
	StateBackup     map[string]interface{} `json:"state_backup"`
	Strategy        DeploymentStrategy     `json:"strategy"`
	BackupPath      string                 `json:"backup_path,omitempty"`
	Timestamp       time.Time              `json:"timestamp"`
}

// ValidationError represents a validation failure
type ValidationError struct {
	Component string `json:"component"`
	Field     string `json:"field"`
	Message   string `json:"message"`
}

func (ve *ValidationError) Error() string {
	return fmt.Sprintf("validation failed for %s.%s: %s", ve.Component, ve.Field, ve.Message)
}

// DeploymentPlan represents a multi-component deployment plan
type DeploymentPlan struct {
	ID           string              `json:"id"`
	Components   []Component         `json:"components"`
	Order        []string            `json:"order"`        // Deployment order
	Dependencies map[string][]string `json:"dependencies"` // Component dependencies
	Strategy     DeploymentStrategy  `json:"strategy"`     // Overall strategy
}

// StrategyCapabilities defines what a strategy can handle
type StrategyCapabilities struct {
	SupportsRollback    bool `json:"supports_rollback"`
	SupportsValidation  bool `json:"supports_validation"`
	SupportsDryRun      bool `json:"supports_dry_run"`
	SupportsHealthCheck bool `json:"supports_health_check"`
	RequiresSalt        bool `json:"requires_salt"`
	RequiresTerraform   bool `json:"requires_terraform"`
	RequiresNomad       bool `json:"requires_nomad"`
}

// GetCapabilities returns the capabilities of a deployment strategy
func GetCapabilities(strategy DeploymentStrategy) StrategyCapabilities {
	switch strategy {
	case DirectStrategy:
		return StrategyCapabilities{
			SupportsRollback:    false, // Limited rollback
			SupportsValidation:  true,
			SupportsDryRun:      true,
			SupportsHealthCheck: true,
			RequiresSalt:        false,
			RequiresTerraform:   false,
			RequiresNomad:       false,
		}
	case SaltStrategy:
		return StrategyCapabilities{
			SupportsRollback:    true,
			SupportsValidation:  true,
			SupportsDryRun:      true,
			SupportsHealthCheck: true,
			RequiresSalt:        true,
			RequiresTerraform:   false,
			RequiresNomad:       false,
		}
	case SaltNomadStrategy:
		return StrategyCapabilities{
			SupportsRollback:    true,
			SupportsValidation:  true,
			SupportsDryRun:      true,
			SupportsHealthCheck: true,
			RequiresSalt:        true,
			RequiresTerraform:   false,
			RequiresNomad:       true,
		}
	case FullStackStrategy:
		return StrategyCapabilities{
			SupportsRollback:    true,
			SupportsValidation:  true,
			SupportsDryRun:      true,
			SupportsHealthCheck: true,
			RequiresSalt:        true,
			RequiresTerraform:   true,
			RequiresNomad:       true,
		}
	default:
		return StrategyCapabilities{}
	}
}

// GetDefaultStrategy returns the default strategy for a component type
func GetDefaultStrategy(componentType ComponentType, environment string) DeploymentStrategy {
	// Development environments use direct deployment
	if environment == "dev" || environment == "test" {
		return DirectStrategy
	}
	
	// Production environments use more sophisticated strategies
	switch componentType {
	case InfrastructureType:
		// Infrastructure services like Consul/Vault use Salt
		return SaltStrategy
		
	case ServiceType:
		// Application services use Salt+Nomad
		return SaltNomadStrategy
		
	case DatabaseType:
		// Databases use Salt for configuration
		return SaltStrategy
		
	case StorageType:
		// Storage uses Salt for system-level management
		return SaltStrategy
		
	default:
		return DirectStrategy
	}
}