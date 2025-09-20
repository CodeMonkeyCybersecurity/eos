package n8n

import (
	"context"
	"time"

	"github.com/hashicorp/nomad/api"
	vault "github.com/hashicorp/vault/api"
)

// Config holds the configuration for n8n deployment
type Config struct {
	// Authentication
	AdminPassword     string `yaml:"admin_password" json:"admin_password"`
	BasicAuthEnabled  bool   `yaml:"basic_auth_enabled" json:"basic_auth_enabled"`
	BasicAuthUser     string `yaml:"basic_auth_user" json:"basic_auth_user"`
	BasicAuthPassword string `yaml:"basic_auth_password" json:"basic_auth_password"`
	EncryptionKey     string `yaml:"encryption_key" json:"encryption_key"`
	JWTSecret         string `yaml:"jwt_secret" json:"jwt_secret"`

	// Database configuration
	PostgresUser     string `yaml:"postgres_user" json:"postgres_user"`
	PostgresPassword string `yaml:"postgres_password" json:"postgres_password"`
	PostgresDB       string `yaml:"postgres_db" json:"postgres_db"`
	PostgresHost     string `yaml:"postgres_host" json:"postgres_host"`
	PostgresPort     int    `yaml:"postgres_port" json:"postgres_port"`

	// Redis configuration
	RedisHost string `yaml:"redis_host" json:"redis_host"`
	RedisPort int    `yaml:"redis_port" json:"redis_port"`

	// Network configuration
	Port     int    `yaml:"port" json:"port"`
	Host     string `yaml:"host" json:"host"`
	Domain   string `yaml:"domain" json:"domain"`
	Protocol string `yaml:"protocol" json:"protocol"`

	// Deployment configuration
	Datacenter  string `yaml:"datacenter" json:"datacenter"`
	Environment string `yaml:"environment" json:"environment"`
	DataPath    string `yaml:"data_path" json:"data_path"`
	Workers     int    `yaml:"workers" json:"workers"`

	// Resource limits
	CPU    int `yaml:"cpu" json:"cpu"`       // MHz
	Memory int `yaml:"memory" json:"memory"` // MB

	// External service addresses
	NomadAddr  string `yaml:"nomad_addr" json:"nomad_addr"`
	VaultAddr  string `yaml:"vault_addr" json:"vault_addr"`
	VaultToken string `yaml:"vault_token" json:"vault_token"`

	// Email configuration (optional)
	SMTPHost   string `yaml:"smtp_host" json:"smtp_host"`
	SMTPPort   int    `yaml:"smtp_port" json:"smtp_port"`
	SMTPUser   string `yaml:"smtp_user" json:"smtp_user"`
	SMTPPass   string `yaml:"smtp_pass" json:"smtp_pass"`
	SMTPSender string `yaml:"smtp_sender" json:"smtp_sender"`

	// Feature flags
	EnableUserManagement bool `yaml:"enable_user_management" json:"enable_user_management"`
	EnablePublicAPI      bool `yaml:"enable_public_api" json:"enable_public_api"`
	EnableTelemetry      bool `yaml:"enable_telemetry" json:"enable_telemetry"`

	// Security
	SecureCookies bool   `yaml:"secure_cookies" json:"secure_cookies"`
	Timezone      string `yaml:"timezone" json:"timezone"`
}

// DeploymentStatus represents the status of a deployment step
type DeploymentStatus struct {
	Step      string                 `json:"step"`
	Success   bool                   `json:"success"`
	Message   string                 `json:"message"`
	Timestamp time.Time              `json:"timestamp"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

// Manager handles n8n deployment operations
type Manager struct {
	config      *Config
	nomadClient *api.Client
	vaultClient *vault.Client
	statusChan  chan DeploymentStatus
}

// SecretConfig holds vault secret configuration
type SecretConfig struct {
	AdminPassword     string `json:"admin_password"`
	BasicAuthPassword string `json:"basic_auth_password"`
	EncryptionKey     string `json:"encryption_key"`
	JWTSecret         string `json:"jwt_secret"`
	PostgresPassword  string `json:"postgres_password"`
	PostgresUser      string `json:"postgres_user"`
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

// DefaultConfig returns a default n8n configuration
func DefaultConfig() *Config {
	return &Config{
		Port:                 8147,
		Host:                 "0.0.0.0",
		Protocol:             "https",
		PostgresDB:           "n8n",
		PostgresHost:         "postgres",
		PostgresPort:         5432,
		RedisHost:            "redis",
		RedisPort:            6379,
		NomadAddr:            "http://localhost:4646",
		VaultAddr:            "http://localhost:8200",
		Datacenter:           "dc1",
		Environment:          "development",
		DataPath:             "/opt/n8n/data",
		Workers:              1,
		CPU:                  1000,
		Memory:               2048,
		EnableUserManagement: true,
		EnablePublicAPI:      true,
		EnableTelemetry:      false,
		SecureCookies:        true,
		Timezone:             "UTC",
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

	if c.EncryptionKey == "" {
		return &DeploymentError{
			Type:    ErrorTypeValidation,
			Step:    "config_validation",
			Message: "encryption key cannot be empty",
		}
	}

	if c.AdminPassword == "" {
		return &DeploymentError{
			Type:    ErrorTypeValidation,
			Step:    "config_validation",
			Message: "admin password cannot be empty",
		}
	}

	if c.Workers < 1 {
		return &DeploymentError{
			Type:    ErrorTypeValidation,
			Step:    "config_validation",
			Message: "worker count must be at least 1",
			Details: map[string]interface{}{"workers": c.Workers},
		}
	}

	return nil
}

// ToData converts the config to  data format for
func (c *Config) ToData() map[string]interface{} {
	return map[string]interface{}{
		"admin_password":         c.AdminPassword,
		"basic_auth_user":        c.BasicAuthUser,
		"basic_auth_password":    c.BasicAuthPassword,
		"encryption_key":         c.EncryptionKey,
		"jwt_secret":             c.JWTSecret,
		"postgres_user":          c.PostgresUser,
		"postgres_password":      c.PostgresPassword,
		"postgres_db":            c.PostgresDB,
		"postgres_host":          c.PostgresHost,
		"postgres_port":          c.PostgresPort,
		"redis_host":             c.RedisHost,
		"redis_port":             c.RedisPort,
		"port":                   c.Port,
		"host":                   c.Host,
		"domain":                 c.Domain,
		"protocol":               c.Protocol,
		"datacenter":             c.Datacenter,
		"environment":            c.Environment,
		"data_path":              c.DataPath,
		"workers":                c.Workers,
		"cpu":                    c.CPU,
		"memory":                 c.Memory,
		"smtp_host":              c.SMTPHost,
		"smtp_port":              c.SMTPPort,
		"smtp_user":              c.SMTPUser,
		"smtp_pass":              c.SMTPPass,
		"smtp_sender":            c.SMTPSender,
		"enable_user_management": c.EnableUserManagement,
		"enable_public_api":      c.EnablePublicAPI,
		"enable_telemetry":       c.EnableTelemetry,
		"secure_cookies":         c.SecureCookies,
		"timezone":               c.Timezone,
	}
}
