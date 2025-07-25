package helen

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/nomad/api"
	vault "github.com/hashicorp/vault/api"
)

// Config holds the configuration for Helen nginx deployment
type Config struct {
	// Basic configuration
	ProjectName string `yaml:"project_name" json:"project_name"`
	Port        int    `yaml:"port" json:"port"`
	Host        string `yaml:"host" json:"host"`

	// Paths and directories
	PublicHTMLPath string `yaml:"public_html_path" json:"public_html_path"`
	WorkDir        string `yaml:"work_dir" json:"work_dir"`

	// Service configuration
	NomadAddr  string `yaml:"nomad_addr" json:"nomad_addr"`
	VaultAddr  string `yaml:"vault_addr" json:"vault_addr"`
	VaultToken string `yaml:"vault_token" json:"vault_token"`

	// Deployment configuration
	Namespace   string   `yaml:"namespace" json:"namespace"`
	Datacenters []string `yaml:"datacenters" json:"datacenters"`

	// Resource limits
	Resources ResourceConfig `yaml:"resources" json:"resources"`
	
	// Hecate integration
	Domain string `yaml:"domain" json:"domain"`
}

// ResourceConfig defines resource allocation for Helen services
type ResourceConfig struct {
	Nginx PodResourceLimits `yaml:"nginx" json:"nginx"`
}

// PodResourceLimits defines CPU and memory limits
type PodResourceLimits struct {
	CPU    int `yaml:"cpu" json:"cpu"`       // MHz
	Memory int `yaml:"memory" json:"memory"` // MB
}

// DeploymentStatus represents the status of a deployment step
type DeploymentStatus struct {
	Step      string                 `json:"step"`
	Success   bool                   `json:"success"`
	Message   string                 `json:"message"`
	Timestamp time.Time              `json:"timestamp"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

// Manager handles Helen deployment operations
type Manager struct {
	config      *Config
	nomadClient *api.Client
	vaultClient *vault.Client
	statusChan  chan DeploymentStatus
}

// SecretConfig holds vault secret configuration for Helen
type SecretConfig struct {
	ProjectName    string `json:"project_name"`
	DeploymentTime string `json:"deployment_time"`
	ContainerPort  int    `json:"container_port"`
	HostPort       int    `json:"host_port"`
	PublicHTMLPath string `json:"public_html_path"`
}

// DeploymentStep represents a single deployment step
type DeploymentStep struct {
	Name          string
	Description   string
	AssessFunc    func(ctx context.Context, mgr *Manager) error
	InterventFunc func(ctx context.Context, mgr *Manager) error
	EvaluateFunc  func(ctx context.Context, mgr *Manager) error
}

// NomadJobConfig holds Nomad job configuration
type NomadJobConfig struct {
	JobID       string
	Namespace   string
	Datacenters []string
	Port        int
	Resources   ResourceConfig
}

// HealthCheckConfig defines health check configuration
type HealthCheckConfig struct {
	Enabled  bool          `yaml:"enabled" json:"enabled"`
	Path     string        `yaml:"path" json:"path"`
	Interval time.Duration `yaml:"interval" json:"interval"`
	Timeout  time.Duration `yaml:"timeout" json:"timeout"`
	Retries  int           `yaml:"retries" json:"retries"`
}

// ServiceCheck represents a service health check
type ServiceCheck struct {
	Name      string            `json:"name"`
	Type      string            `json:"type"`
	Path      string            `json:"path,omitempty"`
	Interval  time.Duration     `json:"interval"`
	Timeout   time.Duration     `json:"timeout"`
	PortLabel string            `json:"port_label,omitempty"`
	Method    string            `json:"method,omitempty"`
	Headers   map[string]string `json:"headers,omitempty"`
}

// HelenTaskConfig defines configuration for the nginx task
type HelenTaskConfig struct {
	Name        string
	Image       string
	Ports       []string
	Environment map[string]string
	Resources   PodResourceLimits
	Vault       *api.Vault
	Templates   []*api.Template
	Volumes     []string
	Constraints []*api.Constraint
	Services    []*api.Service
}

// ErrorType defines types of deployment errors
type ErrorType int

const (
	ErrorTypePrerequisite ErrorType = iota
	ErrorTypeVault
	ErrorTypeNomad
	ErrorTypeValidation
	ErrorTypeTimeout
	ErrorTypeUnknown
)

// DeploymentError represents a deployment error with context
type DeploymentError struct {
	Type    ErrorType
	Step    string
	Message string
	Cause   error
	Details map[string]interface{}
}

func (e *DeploymentError) Error() string {
	if e.Cause != nil {
		return e.Message + ": " + e.Cause.Error()
	}
	return e.Message
}

// DefaultConfig returns a default Helen configuration
func DefaultConfig() *Config {
	return &Config{
		ProjectName:    "helen",
		Port:           8009, // From shared/ports.go
		Host:           "0.0.0.0",
		PublicHTMLPath: "./public",
		WorkDir:        "/tmp/helen-deploy",
		NomadAddr:      "http://localhost:4646",
		VaultAddr:      "http://localhost:8179", // Use Eos standard port
		Namespace:      "helen",
		Datacenters:    []string{"dc1"},
		Resources: ResourceConfig{
			Nginx: PodResourceLimits{CPU: 500, Memory: 128},
		},
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.Port <= 0 || c.Port > 65535 {
		return &DeploymentError{
			Type:    ErrorTypeValidation,
			Step:    "config_validation",
			Message: "invalid port number",
			Details: map[string]interface{}{"port": c.Port},
		}
	}

	if c.Host == "" {
		return &DeploymentError{
			Type:    ErrorTypeValidation,
			Step:    "config_validation",
			Message: "host cannot be empty",
		}
	}

	if c.PublicHTMLPath == "" {
		return &DeploymentError{
			Type:    ErrorTypeValidation,
			Step:    "config_validation",
			Message: "public HTML path cannot be empty",
		}
	}

	if c.NomadAddr == "" {
		return &DeploymentError{
			Type:    ErrorTypeValidation,
			Step:    "config_validation",
			Message: "nomad address cannot be empty",
		}
	}

	if c.VaultAddr == "" {
		return &DeploymentError{
			Type:    ErrorTypeValidation,
			Step:    "config_validation",
			Message: "vault address cannot be empty",
		}
	}

	return nil
}

// GetServiceName returns the Consul service name based on configuration
func (c *Config) GetServiceName() string {
	if c.ProjectName != "" {
		return fmt.Sprintf("%s-%s", c.ProjectName, c.Namespace)
	}
	return fmt.Sprintf("helen-%s", c.Namespace)
}

// GetJobName returns the Nomad job name based on configuration
func (c *Config) GetJobName() string {
	return c.GetServiceName()
}

// DeploymentInfo represents information about a Helen deployment
type DeploymentInfo struct {
	Namespace string         `json:"namespace"`
	Status    string         `json:"status"`
	Healthy   bool           `json:"healthy"`
	Port      int            `json:"port"`
	Services  []ServiceInfo  `json:"services"`
	Resources ResourceConfig `json:"resources"`
	CreatedAt string         `json:"created_at"`
	UpdatedAt string         `json:"updated_at"`
	URL       string         `json:"url"`
	Version   string         `json:"version"`
	HTMLPath  string         `json:"html_path"`
}

// ServiceInfo represents information about a service
type ServiceInfo struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Healthy bool   `json:"healthy"`
	Port    int    `json:"port"`
	Image   string `json:"image"`
}

// HealthStatus represents the health status of a deployment
type HealthStatus struct {
	Namespace     string              `json:"namespace"`
	OverallStatus string              `json:"overall_status"`
	Healthy       bool                `json:"healthy"`
	Services      []ServiceHealthInfo `json:"services"`
	LastCheck     string              `json:"last_check"`
	CheckDuration string              `json:"check_duration"`
	WebsiteCheck  bool                `json:"website_check"`
}

// ServiceHealthInfo represents health information for a service
type ServiceHealthInfo struct {
	Name          string `json:"name"`
	Status        string `json:"status"`
	Healthy       bool   `json:"healthy"`
	ChecksPassing int    `json:"checks_passing"`
	ChecksTotal   int    `json:"checks_total"`
	LastCheck     string `json:"last_check"`
	Message       string `json:"message,omitempty"`
}

// DeploymentMode represents the deployment type
type DeploymentMode string

const (
	ModeStatic DeploymentMode = "static"
	ModeGhost  DeploymentMode = "ghost"
)

// HealthCheck represents a service health check configuration
type HealthCheck struct {
	Path     string `json:"path"`
	Interval string `json:"interval"`
	Timeout  string `json:"timeout"`
	Retries  int    `json:"retries"`
}

// ServiceRegistration represents Consul service registration
type ServiceRegistration struct {
	Name        string            `json:"name"`
	Port        int               `json:"port"`
	Tags        []string          `json:"tags"`
	Meta        map[string]string `json:"meta"`
	HealthCheck *HealthCheck      `json:"health_check"`
}


// UpdateStrategy defines how services are updated
type UpdateStrategy struct {
	MaxParallel     int    `json:"max_parallel"`
	MinHealthyTime  string `json:"min_healthy_time"`
	HealthyDeadline string `json:"healthy_deadline"`
	AutoRevert      bool   `json:"auto_revert"`
	AutoPromote     bool   `json:"auto_promote"`
	Canary          int    `json:"canary"`
}

// Constraint represents a Nomad job constraint
type Constraint struct {
	Attribute string `json:"attribute"`
	Operator  string `json:"operator"`
	Value     string `json:"value"`
}

// Volume represents a persistent volume configuration
type Volume struct {
	Name      string `json:"name"`
	Type      string `json:"type"`
	Source    string `json:"source"`
	ReadOnly  bool   `json:"read_only"`
	MountPath string `json:"mount_path"`
}

// Network represents network configuration
type Network struct {
	Mode  string        `json:"mode"`
	Ports []PortMapping `json:"ports"`
}

// PortMapping represents port configuration
type PortMapping struct {
	Label  string `json:"label"`
	To     int    `json:"to"`
	Static int    `json:"static,omitempty"`
}

// BackupConfig represents backup configuration
type BackupConfig struct {
	Enabled      bool   `json:"enabled"`
	Schedule     string `json:"schedule"`
	Retention    int    `json:"retention_days"`
	BackupPath   string `json:"backup_path"`
	IncludeDB    bool   `json:"include_db"`
	IncludeMedia bool   `json:"include_media"`
}

// WebhookConfig represents CI/CD webhook configuration
type WebhookConfig struct {
	Enabled  bool              `json:"enabled"`
	Endpoint string            `json:"endpoint"`
	Secret   string            `json:"secret"`
	Events   []string          `json:"events"`
	Actions  map[string]string `json:"actions"`
}

