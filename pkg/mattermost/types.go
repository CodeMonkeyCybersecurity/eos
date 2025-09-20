// pkg/mattermost/types.go

package mattermost

import (
	"context"
	"time"

	"github.com/hashicorp/nomad/api"
	vault "github.com/hashicorp/vault/api"
)

// Config holds the configuration for Mattermost deployment
type Config struct {
	// Database configuration
	PostgresUser     string `yaml:"postgres_user" json:"postgres_user"`
	PostgresPassword string `yaml:"postgres_password" json:"postgres_password"`
	PostgresDB       string `yaml:"postgres_db" json:"postgres_db"`
	PostgresHost     string `yaml:"postgres_host" json:"postgres_host"`
	PostgresPort     int    `yaml:"postgres_port" json:"postgres_port"`

	// Network configuration
	Port     int    `yaml:"port" json:"port"`
	Host     string `yaml:"host" json:"host"`
	Domain   string `yaml:"domain" json:"domain"`
	Protocol string `yaml:"protocol" json:"protocol"`

	// Deployment configuration
	Datacenter  string `yaml:"datacenter" json:"datacenter"`
	Environment string `yaml:"environment" json:"environment"`
	DataPath    string `yaml:"data_path" json:"data_path"`
	Replicas    int    `yaml:"replicas" json:"replicas"`

	// Resource limits
	CPU    int `yaml:"cpu" json:"cpu"`       // MHz
	Memory int `yaml:"memory" json:"memory"` // MB

	// External service addresses
	NomadAddr  string `yaml:"nomad_addr" json:"nomad_addr"`
	VaultAddr  string `yaml:"vault_addr" json:"vault_addr"`
	VaultToken string `yaml:"vault_token" json:"vault_token"`

	// Security keys
	FilePublicKey  string `yaml:"file_public_key" json:"file_public_key"`
	FilePrivateKey string `yaml:"file_private_key" json:"file_private_key"`
	Invite         string `yaml:"invite_" json:"invite_"`

	// Support configuration
	SupportEmail string `yaml:"support_email" json:"support_email"`

	// Security
	Timezone string `yaml:"timezone" json:"timezone"`
}

// DeploymentStatus represents the status of a deployment step
type DeploymentStatus struct {
	Step      string                 `json:"step"`
	Success   bool                   `json:"success"`
	Message   string                 `json:"message"`
	Timestamp time.Time              `json:"timestamp"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

// Manager handles Mattermost deployment operations
type Manager struct {
	config      *Config
	nomadClient *api.Client
	vaultClient *vault.Client
	statusChan  chan DeploymentStatus
}

// DeploymentStep represents a single deployment step
type DeploymentStep struct {
	Name          string
	Description   string
	AssessFunc    func(ctx context.Context, mgr *Manager) error
	InterventFunc func(ctx context.Context, mgr *Manager) error
	EvaluateFunc  func(ctx context.Context, mgr *Manager) error
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

// DefaultConfig returns a default Mattermost configuration
func DefaultConfig() *Config {
	return &Config{
		Port:         8065,
		Host:         "0.0.0.0",
		Protocol:     "https",
		PostgresDB:   "mattermost",
		PostgresHost: "postgres",
		PostgresPort: 5432,
		NomadAddr:    "http://localhost:4646",
		VaultAddr:    "http://localhost:8200",
		Datacenter:   "dc1",
		Environment:  "development",
		DataPath:     "/opt/mattermost/data",
		Replicas:     1,
		CPU:          1000,
		Memory:       2048,
		SupportEmail: "support@example.com",
		Timezone:     "UTC",
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

	if c.Domain == "" {
		return &DeploymentError{
			Type:    ErrorTypeValidation,
			Step:    "config_validation",
			Message: "domain cannot be empty",
		}
	}

	if c.FilePublicKey == "" {
		return &DeploymentError{
			Type:    ErrorTypeValidation,
			Step:    "config_validation",
			Message: "file public key cannot be empty",
		}
	}

	if c.Replicas < 1 {
		return &DeploymentError{
			Type:    ErrorTypeValidation,
			Step:    "config_validation",
			Message: "replica count must be at least 1",
			Details: map[string]interface{}{"replicas": c.Replicas},
		}
	}

	return nil
}

// DirNames lists the required subdirectories for Mattermost volumes.
var DirNames = []string{
	"config", "data", "logs", "plugins", "client/plugins", "bleve-indexes",
}

// DefaultEnvUpdates holds the standard .env key/value overrides
// for our internal Mattermost deployment (legacy Docker Compose support).
var DefaultEnvUpdates = map[string]string{
	"DOMAIN":                          "localhost",
	"PORT":                            "8017",
	"MM_SUPPORTSETTINGS_SUPPORTEMAIL": "support@cybermonkey.net.au",
}
