// pkg/consul/agent/types.go
//
// Core types for Consul agent deployment across multiple platforms.
// This package centralizes agent deployment logic for cloud-init, Docker, and native systemd.
//
// Last Updated: 2025-01-24

package agent

import (
	"time"
)

// DeploymentTarget specifies the platform where the Consul agent will be deployed
type DeploymentTarget string

const (
	// TargetCloudInit deploys agent via cloud-init (KVM guests, cloud VMs)
	TargetCloudInit DeploymentTarget = "cloudinit"

	// TargetDocker deploys agent as Docker Compose sidecar
	TargetDocker DeploymentTarget = "docker"

	// TargetSystemd deploys agent as native systemd service
	TargetSystemd DeploymentTarget = "systemd"
)

// AgentMode defines how the Consul agent operates
type AgentMode string

const (
	// ModeServer runs agent in server mode (participates in consensus)
	ModeServer AgentMode = "server"

	// ModeClient runs agent in client mode (joins existing cluster)
	ModeClient AgentMode = "client"

	// ModeDev runs agent in development mode (single-node, no persistence)
	ModeDev AgentMode = "dev"
)

// AgentConfig holds comprehensive configuration for Consul agent deployment
type AgentConfig struct {
	// ========================================================================
	// Identity
	// ========================================================================

	// NodeName is the unique name for this Consul node
	// Required. Must be unique across the datacenter.
	NodeName string

	// Datacenter is the Consul datacenter this agent belongs to
	// Required. Examples: "dc1", "us-east-1", "production"
	Datacenter string

	// Environment is the deployment environment
	// Examples: "production", "staging", "development"
	Environment string

	// ========================================================================
	// Cluster Membership
	// ========================================================================

	// Mode determines if agent is server, client, or dev
	// Default: ModeClient
	Mode AgentMode

	// RetryJoin is the list of server addresses to join
	// For client mode: required, list of server IPs/hostnames
	// For server mode: optional, other server addresses
	// Format: ["10.0.1.10:8301", "10.0.1.11:8301"]
	RetryJoin []string

	// BindAddress is the network interface address to bind
	// Auto-detected if empty (uses private interface)
	BindAddress string

	// AdvertiseAddr is the address advertised to cluster
	// Defaults to BindAddress if empty
	AdvertiseAddr string

	// BootstrapExpect is expected number of servers (server mode only)
	// Only set for server mode. Must be 3 or 5 for production.
	BootstrapExpect int

	// ========================================================================
	// Features
	// ========================================================================

	// EnableUI enables the Consul web UI
	// Default: false (true for dev mode)
	EnableUI bool

	// EnableConnect enables Consul Connect service mesh
	// Default: false
	EnableConnect bool

	// EnableTLS enables TLS encryption for agent communication
	// Default: false (true for production recommended)
	EnableTLS bool

	// EnableACL enables ACL system for authentication/authorization
	// Default: false (true for production required)
	EnableACL bool

	// ========================================================================
	// Integration
	// ========================================================================

	// VaultIntegration enables Vault secret backend integration
	// When true, agent uses Vault for:
	// - ACL tokens
	// - TLS certificates
	// - Gossip encryption keys
	VaultIntegration bool

	// ========================================================================
	// Service Registration
	// ========================================================================

	// Services is the list of services to auto-register with this agent
	// These services will be registered immediately after agent starts
	Services []ServiceDefinition

	// ========================================================================
	// Metadata
	// ========================================================================

	// Tags for service discovery filtering
	// Examples: ["kvm-guest", "production", "web-tier"]
	Tags []string

	// Meta provides additional key-value metadata
	// Examples: {"version": "1.0.0", "owner": "platform-team"}
	Meta map[string]string

	// ========================================================================
	// Operational Configuration
	// ========================================================================

	// LogLevel controls logging verbosity
	// Valid: "TRACE", "DEBUG", "INFO", "WARN", "ERROR"
	// Default: "INFO"
	LogLevel string

	// DataDir overrides the default data directory
	// Default: uses consul.ConsulOptDir constant
	DataDir string

	// ConfigDir overrides the default configuration directory
	// Default: uses consul.ConsulConfigDir constant
	ConfigDir string

	// ========================================================================
	// Deployment Options
	// ========================================================================

	// DryRun mode - generate configs but don't deploy
	// Useful for validation and testing
	DryRun bool
}

// ServiceDefinition defines a service to register with Consul
type ServiceDefinition struct {
	// ID is the unique service instance ID
	// Example: "web-01", "postgres-primary"
	ID string

	// Name is the logical service name (multiple instances can share)
	// Example: "web", "database", "cache"
	Name string

	// Port is the service port number
	Port int

	// Address is the service IP address (optional, defaults to agent address)
	Address string

	// Tags for service filtering and routing
	// Examples: ["primary", "v2", "us-east"]
	Tags []string

	// Meta provides service-level metadata
	Meta map[string]string

	// Checks are health checks for this service
	Checks []HealthCheck

	// Weights for load balancing
	Weights *ServiceWeights
}

// HealthCheck defines a health check for a service
type HealthCheck struct {
	// ID is the unique check identifier
	ID string

	// Name is the human-readable check name
	Name string

	// Type specifies the check type
	// Valid: "http", "https", "tcp", "script", "grpc", "ttl"
	Type string

	// Endpoint is the check endpoint
	// - For http/https: Full URL (http://localhost:8080/health)
	// - For tcp: Address:port (localhost:5432)
	// - For grpc: Address:port (localhost:9090)
	// - For script: Command path
	Endpoint string

	// Interval between checks
	// Format: "10s", "1m", "5m"
	Interval string

	// Timeout for check to complete
	// Format: "5s", "30s"
	Timeout string

	// SuccessBeforePassing consecutive passes before marking healthy
	// Default: 0 (immediate)
	SuccessBeforePassing int

	// FailuresBeforeCritical consecutive failures before marking critical
	// Default: 0 (immediate)
	FailuresBeforeCritical int

	// TLSSkipVerify skips TLS certificate verification (https checks only)
	// Default: false
	TLSSkipVerify bool
}

// ServiceWeights defines load balancing weights
type ServiceWeights struct {
	// Passing is the weight when service is healthy
	// Default: 1
	Passing int

	// Warning is the weight when service has warnings
	// Default: 1
	Warning int
}

// DeploymentResult contains the outcome of agent deployment
type DeploymentResult struct {
	// Success indicates if deployment succeeded
	Success bool

	// AgentID is the deployed agent's unique identifier
	AgentID string

	// AgentAddress is the agent's network address
	// Format: "http://localhost:8500" or "http://10.0.1.10:8500"
	AgentAddress string

	// ContainerID is the Docker container ID (Docker target only)
	ContainerID string

	// ConfigPath is the path to agent configuration file
	ConfigPath string

	// DataPath is the path to agent data directory
	DataPath string

	// Message contains a human-readable status message
	Message string

	// Warnings are non-fatal issues encountered during deployment
	Warnings []string

	// Duration is how long deployment took
	Duration time.Duration
}

// ACLBootstrapResult contains ACL bootstrap outcome
type ACLBootstrapResult struct {
	// BootstrapToken is the master token (SecretID)
	BootstrapToken string

	// AgentToken is the token for this specific agent
	AgentToken string

	// PolicyID is the agent policy ID
	PolicyID string

	// Bootstrapped indicates if this was a new bootstrap or reuse
	Bootstrapped bool
}

// HealthStatus represents agent health state
type HealthStatus string

const (
	// HealthPassing indicates agent is healthy
	HealthPassing HealthStatus = "passing"

	// HealthWarning indicates agent has warnings
	HealthWarning HealthStatus = "warning"

	// HealthCritical indicates agent is unhealthy
	HealthCritical HealthStatus = "critical"

	// HealthUnknown indicates health state is unknown
	HealthUnknown HealthStatus = "unknown"
)

// AgentStatus represents current agent state
type AgentStatus struct {
	// Running indicates if agent process is running
	Running bool

	// Health is the agent's health status
	Health HealthStatus

	// Leader indicates if this agent is the cluster leader (server mode only)
	Leader bool

	// MemberCount is the number of cluster members visible
	MemberCount int

	// ServiceCount is the number of registered services
	ServiceCount int

	// Version is the Consul agent version
	Version string

	// Uptime is how long the agent has been running
	Uptime time.Duration
}

// CloudInitConfig holds cloud-init specific configuration
type CloudInitConfig struct {
	// BaseConfig is the core agent configuration
	AgentConfig

	// MergeWithBase indicates if this should merge with existing cloud-init
	// or be standalone
	MergeWithBase bool

	// UserDataPath is where to write user-data (optional)
	UserDataPath string

	// MetaDataPath is where to write meta-data (optional)
	MetaDataPath string

	// ISOPath is where to generate cloud-init ISO (optional)
	ISOPath string
}

// DockerConfig holds Docker-specific configuration
type DockerConfig struct {
	// BaseConfig is the core agent configuration
	AgentConfig

	// ComposeFile is the path to docker-compose.yml to modify/create
	ComposeFile string

	// ServiceName is the Docker service name
	// Default: "consul-agent"
	ServiceName string

	// NetworkMode is the Docker network mode
	// Default: "host" (required for Consul gossip protocol)
	NetworkMode string

	// Image is the Docker image to use
	// Default: "hashicorp/consul:{ConsulDefaultVersion}"
	Image string

	// Volumes are additional volume mounts
	Volumes []string

	// Environment variables to set
	Environment map[string]string
}

// SystemdConfig holds systemd-specific configuration
type SystemdConfig struct {
	// BaseConfig is the core agent configuration
	AgentConfig

	// ServiceName is the systemd service name
	// Default: "consul"
	ServiceName string

	// User is the user to run as
	// Default: consul.ConsulUser
	User string

	// Group is the group to run as
	// Default: consul.ConsulGroup
	Group string

	// AutoStart enables agent on boot
	// Default: true
	AutoStart bool

	// Restart policy
	// Default: "on-failure"
	Restart string
}
