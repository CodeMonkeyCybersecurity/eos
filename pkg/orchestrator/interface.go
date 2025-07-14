// pkg/orchestrator/interface.go
package orchestrator

import (
	"context"
	"time"
)

// Component represents a deployable component in the orchestration pipeline
type Component struct {
	Name        string                 `json:"name"`
	Type        ComponentType          `json:"type"`
	Version     string                 `json:"version"`
	Config      interface{}            `json:"config"`
	Labels      map[string]string      `json:"labels"`
	Annotations map[string]string      `json:"annotations"`
	Dependencies []string              `json:"dependencies"`
}

// ComponentType defines the type of component being deployed
type ComponentType string

const (
	ServiceType ComponentType = "service"
	JobType     ComponentType = "job"
	ConfigType  ComponentType = "config"
)

// Deployment represents a deployed component with its current state
type Deployment struct {
	ID          string            `json:"id"`
	Component   Component         `json:"component"`
	Status      DeploymentStatus  `json:"status"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	Outputs     map[string]string `json:"outputs"`
	Error       string            `json:"error,omitempty"`
}

// DeploymentStatus represents the current status of a deployment
type DeploymentStatus string

const (
	StatusPending   DeploymentStatus = "pending"
	StatusDeploying DeploymentStatus = "deploying"
	StatusHealthy   DeploymentStatus = "healthy"
	StatusUnhealthy DeploymentStatus = "unhealthy"
	StatusFailed    DeploymentStatus = "failed"
	StatusRollingBack DeploymentStatus = "rolling_back"
)

// Status provides detailed status information about a component
type Status struct {
	Healthy      bool              `json:"healthy"`
	Message      string            `json:"message"`
	LastChecked  time.Time         `json:"last_checked"`
	Details      map[string]interface{} `json:"details"`
}

// Orchestrator defines the interface for deployment orchestration
type Orchestrator interface {
	// Deploy deploys a component through the orchestration pipeline
	Deploy(ctx context.Context, component Component) (*Deployment, error)
	
	// Update updates an existing deployment
	Update(ctx context.Context, deployment *Deployment) error
	
	// Validate validates a component configuration without deploying
	Validate(ctx context.Context, component Component) error
	
	// Rollback rolls back a deployment to a previous state
	Rollback(ctx context.Context, deployment *Deployment) error
	
	// GetStatus returns the current status of a deployment
	GetStatus(ctx context.Context, deploymentID string) (*Status, error)
	
	// Destroy removes a deployed component
	Destroy(ctx context.Context, deploymentID string) error
	
	// List returns all deployments
	List(ctx context.Context) ([]*Deployment, error)
}

// StateGenerator generates configuration states for different orchestration tools
type StateGenerator interface {
	// GenerateState generates the state configuration for a component
	GenerateState(component Component) (interface{}, error)
	
	// ValidateState validates the generated state
	ValidateState(state interface{}) error
	
	// PreviewState returns a human-readable preview of the state
	PreviewState(state interface{}) (string, error)
}

// Pipeline represents the complete orchestration pipeline
type Pipeline interface {
	// Deploy runs a component through the entire pipeline
	Deploy(ctx context.Context, component Component) (*Deployment, error)
	
	// WaitForHealthy waits for a deployment to become healthy
	WaitForHealthy(ctx context.Context, deployment *Deployment, timeout time.Duration) error
	
	// GetLogs retrieves logs for a deployment
	GetLogs(ctx context.Context, deploymentID string, options LogOptions) ([]LogEntry, error)
	
	// PreviewSalt returns the generated Salt states without applying
	PreviewSalt(component Component) (string, error)
	
	// PreviewTerraform returns the generated Terraform configuration without applying
	PreviewTerraform(component Component) (string, error)
	
	// PreviewNomad returns the generated Nomad job specification without applying
	PreviewNomad(component Component) (string, error)
}

// LogOptions defines options for log retrieval
type LogOptions struct {
	Since     time.Time `json:"since"`
	Until     time.Time `json:"until"`
	Limit     int       `json:"limit"`
	Follow    bool      `json:"follow"`
	Container string    `json:"container"`
}

// LogEntry represents a single log entry
type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Level     string    `json:"level"`
	Message   string    `json:"message"`
	Source    string    `json:"source"`
	Fields    map[string]interface{} `json:"fields"`
}

// StateStore manages the persistent state of deployments
type StateStore interface {
	// SaveDeployment saves a deployment state
	SaveDeployment(deployment *Deployment) error
	
	// GetDeployment retrieves a deployment by ID
	GetDeployment(id string) (*Deployment, error)
	
	// ListDeployments lists all deployments with optional filtering
	ListDeployments(filter DeploymentFilter) ([]*Deployment, error)
	
	// UpdateDeploymentStatus updates the status of a deployment
	UpdateDeploymentStatus(id string, status DeploymentStatus) error
	
	// DeleteDeployment removes a deployment from the store
	DeleteDeployment(id string) error
}

// DeploymentFilter defines filtering options for listing deployments
type DeploymentFilter struct {
	ComponentName string            `json:"component_name,omitempty"`
	Status        DeploymentStatus  `json:"status,omitempty"`
	Labels        map[string]string `json:"labels,omitempty"`
	Since         time.Time         `json:"since,omitempty"`
	Until         time.Time         `json:"until,omitempty"`
}

// Ports defines port configuration for a service
type Ports struct {
	HTTP int `json:"http"`
	HTTPS int `json:"https,omitempty"`
	DNS  int `json:"dns,omitempty"`
	RPC  int `json:"rpc,omitempty"`
	Custom map[string]int `json:"custom,omitempty"`
}

// ConsulConfig defines configuration specific to Consul deployment
type ConsulConfig struct {
	Datacenter      string `json:"datacenter"`
	BootstrapExpect int    `json:"bootstrap_expect"`
	UIEnabled       bool   `json:"ui_enabled"`
	Ports           Ports  `json:"ports"`
	VaultIntegration bool  `json:"vault_integration"`
	VaultAddr       string `json:"vault_addr,omitempty"`
	VaultToken      string `json:"vault_token,omitempty"`
	ServerMode      bool   `json:"server_mode"`
	EncryptionKey   string `json:"encryption_key"`
	TLSEnabled      bool   `json:"tls_enabled"`
}

// DesiredState represents the desired state for reconciliation
type DesiredState struct {
	Components []Component `json:"components"`
	Metadata   map[string]string `json:"metadata"`
	Version    string `json:"version"`
}