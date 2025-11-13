// Package servicestatus provides a unified interface for checking service status.
//
// This package standardizes how Eos reports on service health, configuration,
// and integration status across all managed services (Consul, Vault, Nomad, etc.).
//
// Design Goals:
//   - Consistent output format across all services
//   - Reusable status checking logic
//   - Support for multiple output formats (text, JSON, YAML)
//   - Centralized health aggregation
//   - Easy to extend for new services
//
// Example usage:
//
//	provider := servicestatus.NewConsulStatusProvider()
//	status, err := provider.GetStatus(rc)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println(status.Display(servicestatus.FormatText))
//
// Code Monkey Cybersecurity - "Cybersecurity. With humans."
package servicestatus

import (
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// StatusProvider defines the interface all service status providers must implement
type StatusProvider interface {
	// ServiceName returns the name of the service (e.g., "Consul", "Vault")
	ServiceName() string

	// GetStatus retrieves the current comprehensive status of the service
	GetStatus(rc *eos_io.RuntimeContext) (*ServiceStatus, error)

	// QuickCheck performs a fast health check (< 1 second)
	QuickCheck(rc *eos_io.RuntimeContext) (HealthStatus, error)
}

// ServiceStatus represents the comprehensive status of a service
type ServiceStatus struct {
	// Basic information
	Name    string
	Version string

	// Installation
	Installation InstallationInfo

	// Service status
	Service ServiceInfo

	// Configuration
	Configuration ConfigurationInfo

	// Health
	Health HealthInfo

	// Network and connectivity
	Network NetworkInfo

	// Integrations with other services
	Integrations []IntegrationInfo

	// Cluster information (if applicable)
	Cluster *ClusterInfo

	// Metadata
	CheckedAt time.Time
	CheckedBy string // hostname
}

// InstallationInfo contains information about service installation
type InstallationInfo struct {
	Installed  bool
	BinaryPath string
	Version    string
	InstallDir string
	ConfigDir  string
	DataDir    string
}

// ServiceInfo contains systemd service information
type ServiceInfo struct {
	Running       bool
	Status        string // active, inactive, failed, etc.
	Enabled       bool   // systemd enabled at boot
	Uptime        time.Duration
	PID           int
	MemoryUsage   uint64 // bytes
	RestartCount  int
	LastRestart   time.Time
	FailureReason string // if failed
}

// ConfigurationInfo contains configuration validation results
type ConfigurationInfo struct {
	Valid      bool
	ConfigPath string
	Errors     []string
	Warnings   []string
	Details    map[string]string // service-specific config details
}

// HealthInfo contains health check results
type HealthInfo struct {
	Status       HealthStatus
	Message      string
	Checks       []HealthCheck
	LastHealthy  time.Time
	IsSealed     *bool // for Vault
	IsLeader     *bool // for cluster services
	ResponseTime time.Duration
}

// HealthStatus represents the overall health state
type HealthStatus string

const (
	HealthStatusHealthy   HealthStatus = "healthy"
	HealthStatusDegraded  HealthStatus = "degraded"
	HealthStatusUnhealthy HealthStatus = "unhealthy"
	HealthStatusUnknown   HealthStatus = "unknown"
)

// HealthCheck represents an individual health check
type HealthCheck struct {
	Name    string
	Status  HealthStatus
	Message string
	Details map[string]interface{}
}

// NetworkInfo contains network and endpoint information
type NetworkInfo struct {
	Endpoints     []Endpoint
	ListenAddr    string
	AdvertiseAddr string
}

// Endpoint represents a network endpoint
type Endpoint struct {
	Name     string // e.g., "HTTP API", "DNS", "gRPC"
	Protocol string // http, https, tcp, udp
	Address  string
	Port     int
	Healthy  bool
}

// IntegrationInfo describes integration with another service
type IntegrationInfo struct {
	ServiceName string
	Type        IntegrationType
	Connected   bool
	Healthy     bool
	Details     string
	Required    bool // Is this integration required for operation?
}

// IntegrationType describes the type of integration
type IntegrationType string

const (
	IntegrationTypeStorageBackend   IntegrationType = "storage_backend"
	IntegrationTypeServiceDiscovery IntegrationType = "service_discovery"
	IntegrationTypeSecretStore      IntegrationType = "secret_store"
	IntegrationTypeConfigStore      IntegrationType = "config_store"
	IntegrationTypeAuthProvider     IntegrationType = "auth_provider"
	IntegrationTypeClient           IntegrationType = "client"
)

// ClusterInfo contains cluster-specific information
type ClusterInfo struct {
	Mode          string // server, client, standalone
	NodeName      string
	Datacenter    string
	Leader        string
	Peers         []string
	Members       []ClusterMember
	Healthy       bool
	QuorumSize    int
	VotingMembers int
}

// ClusterMember represents a member of a cluster
type ClusterMember struct {
	Name    string
	Address string
	Role    string // server, client, voter, etc.
	Status  string // alive, failed, left
	Leader  bool
}

// OutputFormat specifies the format for status output
type OutputFormat string

const (
	FormatText  OutputFormat = "text"
	FormatJSON  OutputFormat = "json"
	FormatYAML  OutputFormat = "yaml"
	FormatShort OutputFormat = "short" // One-line summary
)

// Display formats the service status for output
func (s *ServiceStatus) Display(format OutputFormat) string {
	switch format {
	case FormatJSON:
		return s.displayJSON()
	case FormatYAML:
		return s.displayYAML()
	case FormatShort:
		return s.displayShort()
	default:
		return s.displayText()
	}
}

// IsHealthy returns true if the service is fully healthy
func (s *ServiceStatus) IsHealthy() bool {
	return s.Installation.Installed &&
		s.Service.Running &&
		s.Configuration.Valid &&
		s.Health.Status == HealthStatusHealthy
}

// HasWarnings returns true if there are any warnings
func (s *ServiceStatus) HasWarnings() bool {
	return len(s.Configuration.Warnings) > 0 ||
		s.Health.Status == HealthStatusDegraded
}

// HasErrors returns true if there are any errors
func (s *ServiceStatus) HasErrors() bool {
	return !s.Installation.Installed ||
		!s.Service.Running ||
		!s.Configuration.Valid ||
		s.Health.Status == HealthStatusUnhealthy ||
		len(s.Configuration.Errors) > 0
}
