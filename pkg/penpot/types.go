package penpot

import (
	"context"
	"time"

	"github.com/hashicorp/nomad/api"
	vault "github.com/hashicorp/vault/api"
)

// Config holds the configuration for Penpot deployment
type Config struct {
	// Network configuration
	Port      int    `yaml:"port" json:"port"`
	Host      string `yaml:"host" json:"host"`
	PublicURI string `yaml:"public_uri" json:"public_uri"`

	// Service configuration
	DatabasePort int `yaml:"database_port" json:"database_port"`
	RedisPort    int `yaml:"redis_port" json:"redis_port"`

	// External service addresses
	NomadAddr  string `yaml:"nomad_addr" json:"nomad_addr"`
	VaultAddr  string `yaml:"vault_addr" json:"vault_addr"`
	VaultToken string `yaml:"vault_token" json:"vault_token"`

	// Deployment configuration
	Namespace   string   `yaml:"namespace" json:"namespace"`
	Datacenters []string `yaml:"datacenters" json:"datacenters"`
	WorkDir     string   `yaml:"work_dir" json:"work_dir"`

	// Feature flags
	EnableRegistration bool `yaml:"enable_registration" json:"enable_registration"`
	EnableLogin        bool `yaml:"enable_login" json:"enable_login"`
	DisableEmailVerif  bool `yaml:"disable_email_verification" json:"disable_email_verification"`

	// Resource limits
	Resources ResourceConfig `yaml:"resources" json:"resources"`
}

// ResourceConfig defines resource allocation for each service
type ResourceConfig struct {
	Frontend PenpotResourceLimits `yaml:"frontend" json:"frontend"`
	Backend  PenpotResourceLimits `yaml:"backend" json:"backend"`
	Exporter PenpotResourceLimits `yaml:"exporter" json:"exporter"`
	Database PenpotResourceLimits `yaml:"database" json:"database"`
	Redis    PenpotResourceLimits `yaml:"redis" json:"redis"`
}

// PenpotResourceLimits defines CPU and memory limits
type PenpotResourceLimits struct {
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

// Manager handles Penpot deployment operations
type Manager struct {
	config      *Config
	nomadClient *api.Client
	vaultClient *vault.Client
	statusChan  chan DeploymentStatus
}

// SecretConfig holds vault secret configuration
type SecretConfig struct {
	DatabasePassword string `json:"database_password"`
	SecretKey        string `json:"secret_key"`
	DatabaseURI      string `json:"database_uri"`
	RedisURI         string `json:"redis_uri"`
	PublicURI        string `json:"public_uri"`
}

// PostgresSecretConfig holds postgres-specific secrets
type PostgresSecretConfig struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Database string `json:"database"`
}

// DeploymentStep represents a single deployment step
type DeploymentStep struct {
	Name          string
	Description   string
	AssessFunc    func(ctx context.Context, mgr *Manager) error
	InterventFunc func(ctx context.Context, mgr *Manager) error
	EvaluateFunc  func(ctx context.Context, mgr *Manager) error
}

// TerraformConfig holds Terraform configuration
type TerraformConfig struct {
	NomadAddr  string
	VaultAddr  string
	VaultToken string
	Namespace  string
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

// PenpotFeatureFlags defines Penpot feature configuration
type PenpotFeatureFlags struct {
	EnableRegistration       bool `yaml:"enable_registration" json:"enable_registration"`
	EnableLogin              bool `yaml:"enable_login" json:"enable_login"`
	DisableEmailVerification bool `yaml:"disable_email_verification" json:"disable_email_verification"`
	EnableEmailAuth          bool `yaml:"enable_email_auth" json:"enable_email_auth"`
	EnableDemoUsers          bool `yaml:"enable_demo_users" json:"enable_demo_users"`
	EnableTelemetry          bool `yaml:"enable_telemetry" json:"enable_telemetry"`
}

// PenpotTaskConfig defines configuration for individual Nomad tasks
type PenpotTaskConfig struct {
	Name        string
	Image       string
	Ports       []string
	Environment map[string]string
	Resources   PenpotResourceLimits
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
	ErrorTypeTerraform
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

// DefaultConfig returns a default Penpot configuration
func DefaultConfig() *Config {
	return &Config{
		Port:               8239,
		Host:               "0.0.0.0",
		DatabasePort:       5432,
		RedisPort:          6379,
		NomadAddr:          "http://localhost:4646",
		VaultAddr:          "http://localhost:8200",
		Namespace:          "penpot",
		Datacenters:        []string{"dc1"},
		WorkDir:            "/tmp/penpot-deploy",
		EnableRegistration: true,
		EnableLogin:        true,
		DisableEmailVerif:  true,
		Resources: ResourceConfig{
			Frontend: PenpotResourceLimits{CPU: 500, Memory: 512},
			Backend:  PenpotResourceLimits{CPU: 1000, Memory: 2048},
			Exporter: PenpotResourceLimits{CPU: 500, Memory: 512},
			Database: PenpotResourceLimits{CPU: 500, Memory: 512},
			Redis:    PenpotResourceLimits{CPU: 200, Memory: 256},
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
