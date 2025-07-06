// pkg/system_config/types.go
package system_config

import (
	"time"
)

// ConfigurationManager interface defines the common operations for system configuration
type ConfigurationManager interface {
	// Validate checks if the configuration can be applied safely
	Validate() error
	
	// Backup creates a backup of current configuration before changes
	Backup() (*ConfigurationBackup, error)
	
	// Apply applies the configuration changes
	Apply() (*ConfigurationResult, error)
	
	// Rollback reverts to a previous configuration state
	Rollback(backup *ConfigurationBackup) error
	
	// Status returns the current configuration status
	Status() (*ConfigurationStatus, error)
	
	// GetType returns the configuration type identifier
	GetType() ConfigurationType
}

// ConfigurationType represents different types of system configurations
type ConfigurationType string

const (
	ConfigTypeSystemTools   ConfigurationType = "system-tools"
	ConfigTypeMFA          ConfigurationType = "mfa"
	ConfigTypeXRDP         ConfigurationType = "xrdp"
	ConfigTypeDropbear     ConfigurationType = "dropbear"
	ConfigTypeGnome        ConfigurationType = "gnome"
	ConfigTypeSSHKey       ConfigurationType = "ssh-key"
	ConfigTypeHosts        ConfigurationType = "hosts"
	ConfigTypeCloudInit    ConfigurationType = "cloud-init"
	ConfigTypeRepository   ConfigurationType = "repository"
	ConfigTypePath         ConfigurationType = "path"
	ConfigTypePartition    ConfigurationType = "partition"
)

// ConfigurationOptions contains common configuration options
type ConfigurationOptions struct {
	Type         ConfigurationType     `json:"type"`
	DryRun       bool                  `json:"dry_run"`
	Force        bool                  `json:"force"`
	Interactive  bool                  `json:"interactive"`
	Backup       bool                  `json:"backup"`
	Validate     bool                  `json:"validate"`
	Config       map[string]string     `json:"config,omitempty"`
	Environment  map[string]string     `json:"environment,omitempty"`
	Files        []FileConfiguration   `json:"files,omitempty"`
	Services     []ServiceConfiguration `json:"services,omitempty"`
	Packages     []PackageConfiguration `json:"packages,omitempty"`
}

// FileConfiguration represents a file that needs to be configured
type FileConfiguration struct {
	Path        string            `json:"path"`
	Content     string            `json:"content,omitempty"`
	Template    string            `json:"template,omitempty"`
	Variables   map[string]string `json:"variables,omitempty"`
	Mode        string            `json:"mode,omitempty"`
	Owner       string            `json:"owner,omitempty"`
	Group       string            `json:"group,omitempty"`
	Backup      bool              `json:"backup"`
	CreateDirs  bool              `json:"create_dirs"`
}

// ServiceConfiguration represents a service that needs to be configured
type ServiceConfiguration struct {
	Name    string `json:"name"`
	Enable  bool   `json:"enable"`
	Start   bool   `json:"start"`
	Restart bool   `json:"restart"`
}

// PackageConfiguration represents a package that needs to be managed
type PackageConfiguration struct {
	Name     string `json:"name"`
	Action   string `json:"action"` // install, remove, upgrade
	Version  string `json:"version,omitempty"`
	Required bool   `json:"required"`
}

// ConfigurationBackup represents a backup of system configuration
type ConfigurationBackup struct {
	ID          string                    `json:"id"`
	Type        ConfigurationType         `json:"type"`
	Timestamp   time.Time                 `json:"timestamp"`
	Files       map[string]string         `json:"files"`        // path -> backup content
	Services    map[string]ServiceState   `json:"services"`     // service -> original state
	Packages    map[string]PackageState   `json:"packages"`     // package -> original state
	Environment map[string]string         `json:"environment"`  // env vars that were changed
	Metadata    map[string]interface{}    `json:"metadata"`
}

// ServiceState represents the state of a service
type ServiceState struct {
	Enabled bool `json:"enabled"`
	Active  bool `json:"active"`
}

// PackageState represents the state of a package
type PackageState struct {
	Installed bool   `json:"installed"`
	Version   string `json:"version,omitempty"`
}

// ConfigurationResult represents the result of a configuration operation
type ConfigurationResult struct {
	Success      bool                   `json:"success"`
	Type         ConfigurationType      `json:"type"`
	Message      string                 `json:"message"`
	Error        string                 `json:"error,omitempty"`
	Duration     time.Duration          `json:"duration"`
	Steps        []ConfigurationStep    `json:"steps,omitempty"`
	Changes      []ConfigurationChange  `json:"changes,omitempty"`
	Backup       *ConfigurationBackup   `json:"backup,omitempty"`
	Warnings     []string               `json:"warnings,omitempty"`
	Timestamp    time.Time              `json:"timestamp"`
}

// ConfigurationStep represents a step in the configuration process
type ConfigurationStep struct {
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Status      string        `json:"status"`
	Duration    time.Duration `json:"duration,omitempty"`
	Error       string        `json:"error,omitempty"`
	Output      string        `json:"output,omitempty"`
}

// ConfigurationChange represents a change made during configuration
type ConfigurationChange struct {
	Type        string      `json:"type"`        // file, service, package, environment
	Target      string      `json:"target"`      // specific item changed
	Action      string      `json:"action"`      // created, modified, deleted, started, stopped
	OldValue    interface{} `json:"old_value,omitempty"`
	NewValue    interface{} `json:"new_value,omitempty"`
	Description string      `json:"description"`
}

// ConfigurationStatus represents the current status of a configuration
type ConfigurationStatus struct {
	Type           ConfigurationType         `json:"type"`
	Configured     bool                      `json:"configured"`
	LastModified   time.Time                 `json:"last_modified,omitempty"`
	Version        string                    `json:"version,omitempty"`
	Health         ConfigurationHealth       `json:"health"`
	Dependencies   []DependencyStatus        `json:"dependencies,omitempty"`
	Files          []FileStatus              `json:"files,omitempty"`
	Services       []ServiceStatus           `json:"services,omitempty"`
	Packages       []PackageStatus           `json:"packages,omitempty"`
	Metadata       map[string]interface{}    `json:"metadata,omitempty"`
}

// ConfigurationHealth represents the health status of a configuration
type ConfigurationHealth struct {
	Status      string              `json:"status"`      // healthy, degraded, failed, unknown
	Checks      []HealthCheck       `json:"checks,omitempty"`
	LastCheck   time.Time           `json:"last_check,omitempty"`
	Issues      []HealthIssue       `json:"issues,omitempty"`
}

// HealthCheck represents an individual health check
type HealthCheck struct {
	Name    string `json:"name"`
	Status  string `json:"status"`  // passed, failed, warning
	Message string `json:"message,omitempty"`
}

// HealthIssue represents a health issue found during checks
type HealthIssue struct {
	Severity    string `json:"severity"`    // critical, warning, info
	Description string `json:"description"`
	Remediation string `json:"remediation,omitempty"`
}

// DependencyStatus represents the status of a configuration dependency
type DependencyStatus struct {
	Name      string `json:"name"`
	Type      string `json:"type"`      // package, service, file, command
	Required  bool   `json:"required"`
	Available bool   `json:"available"`
	Version   string `json:"version,omitempty"`
	Error     string `json:"error,omitempty"`
}

// FileStatus represents the status of a configuration file
type FileStatus struct {
	Path     string    `json:"path"`
	Exists   bool      `json:"exists"`
	Mode     string    `json:"mode,omitempty"`
	Owner    string    `json:"owner,omitempty"`
	Group    string    `json:"group,omitempty"`
	Size     int64     `json:"size,omitempty"`
	Modified time.Time `json:"modified,omitempty"`
	Checksum string    `json:"checksum,omitempty"`
}

// ServiceStatus represents the status of a service
type ServiceStatus struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	Active  bool   `json:"active"`
	Status  string `json:"status,omitempty"`
}

// PackageStatus represents the status of a package
type PackageStatus struct {
	Name      string `json:"name"`
	Installed bool   `json:"installed"`
	Version   string `json:"version,omitempty"`
	Available string `json:"available,omitempty"`
}

// ValidationError represents a configuration validation error
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Code    string `json:"code"`
}

// ValidationResult represents the result of configuration validation
type ValidationResult struct {
	Valid   bool              `json:"valid"`
	Errors  []ValidationError `json:"errors,omitempty"`
	Warnings []ValidationError `json:"warnings,omitempty"`
}

// SystemToolsConfig represents configuration for system tools setup
type SystemToolsConfig struct {
	UpdateSystem    bool     `json:"update_system"`
	InstallPackages bool     `json:"install_packages"`
	Packages        []string `json:"packages,omitempty"`
	InstallNpm      bool     `json:"install_npm"`
	InstallZx       bool     `json:"install_zx"`
	ConfigureUFW    bool     `json:"configure_ufw"`
	SetupSensors    bool     `json:"setup_sensors"`
	Interactive     bool     `json:"interactive"`
}

// MFAConfig represents configuration for multi-factor authentication
type MFAConfig struct {
	User           string `json:"user"`
	SecretKey      string `json:"secret_key,omitempty"`
	WindowSize     int    `json:"window_size"`
	OathFile       string `json:"oath_file"`
	ConfigurePAM   bool   `json:"configure_pam"`
	ConfigureSSH   bool   `json:"configure_ssh"`
	BackupConfigs  bool   `json:"backup_configs"`
	TestMode       bool   `json:"test_mode"`
}

// XRDPConfig represents configuration for XRDP setup
type XRDPConfig struct {
	InstallDesktop bool   `json:"install_desktop"`
	DesktopEnv     string `json:"desktop_env"`     // xfce4, gnome, kde
	ConfigureFirewall bool `json:"configure_firewall"`
	AllowedIPs     []string `json:"allowed_ips,omitempty"`
	Port           int    `json:"port"`
	MaxSessions    int    `json:"max_sessions"`
	ConfigFile     string `json:"config_file,omitempty"`
}

// SSHKeyConfig represents configuration for SSH key generation
type SSHKeyConfig struct {
	Email      string `json:"email"`
	KeyType    string `json:"key_type"`    // rsa, ecdsa, ed25519
	KeyLength  int    `json:"key_length,omitempty"`
	FilePath   string `json:"file_path"`
	Passphrase string `json:"passphrase,omitempty"`
	Comment    string `json:"comment,omitempty"`
	Overwrite  bool   `json:"overwrite"`
}