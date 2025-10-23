// pkg/nomad/types.go

package nomad

import (
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
)

// Config represents Nomad configuration
type Config struct {
	// Basic configuration
	Version    string `json:"version" yaml:"version"`
	Datacenter string `json:"datacenter" yaml:"datacenter"`
	Region     string `json:"region" yaml:"region"`
	NodeRole   string `json:"node_role" yaml:"node_role"`

	// UI and API
	EnableUI bool `json:"enable_ui" yaml:"enable_ui"`
	HTTPPort int  `json:"http_port" yaml:"http_port"`
	RPCPort  int  `json:"rpc_port" yaml:"rpc_port"`
	SerfPort int  `json:"serf_port" yaml:"serf_port"`

	// Integration settings
	ConsulIntegration bool   `json:"consul_integration" yaml:"consul_integration"`
	VaultIntegration  bool   `json:"vault_integration" yaml:"vault_integration"`
	ConsulAddress     string `json:"consul_address" yaml:"consul_address"`
	VaultAddress      string `json:"vault_address" yaml:"vault_address"`

	// Security settings
	EnableTLS    bool   `json:"enable_tls" yaml:"enable_tls"`
	EnableACL    bool   `json:"enable_acl" yaml:"enable_acl"`
	EnableGossip bool   `json:"enable_gossip" yaml:"enable_gossip"`
	CAFile       string `json:"ca_file" yaml:"ca_file"`
	CertFile     string `json:"cert_file" yaml:"cert_file"`
	KeyFile      string `json:"key_file" yaml:"key_file"`

	// Paths
	DataDir   string `json:"data_dir" yaml:"data_dir"`
	ConfigDir string `json:"config_dir" yaml:"config_dir"`
	LogLevel  string `json:"log_level" yaml:"log_level"`

	// Resource limits
	ServerBootstrapExpect int            `json:"server_bootstrap_expect" yaml:"server_bootstrap_expect"`
	ClientReserved        ClientReserved `json:"client_reserved" yaml:"client_reserved"`

	// Networking
	NetworkInterface string `json:"network_interface" yaml:"network_interface"`
	BindAddr         string `json:"bind_addr" yaml:"bind_addr"`
	AdvertiseAddr    string `json:"advertise_addr" yaml:"advertise_addr"`

	// Plugin configuration
	DockerEnabled  bool `json:"docker_enabled" yaml:"docker_enabled"`
	ExecEnabled    bool `json:"exec_enabled" yaml:"exec_enabled"`
	RawExecEnabled bool `json:"raw_exec_enabled" yaml:"raw_exec_enabled"`

	// Telemetry
	EnableTelemetry bool            `json:"enable_telemetry" yaml:"enable_telemetry"`
	TelemetryConfig TelemetryConfig `json:"telemetry_config" yaml:"telemetry_config"`
}

// ClientReserved represents resources reserved for the client
type ClientReserved struct {
	CPU    int    `json:"cpu" yaml:"cpu"`
	Memory int    `json:"memory" yaml:"memory"`
	Disk   int    `json:"disk" yaml:"disk"`
	Ports  string `json:"ports" yaml:"ports"`
}

// TelemetryConfig represents telemetry configuration
type TelemetryConfig struct {
	PrometheusMetrics        bool          `json:"prometheus_metrics" yaml:"prometheus_metrics"`
	DisableHostname          bool          `json:"disable_hostname" yaml:"disable_hostname"`
	CollectionInterval       time.Duration `json:"collection_interval" yaml:"collection_interval"`
	PublishAllocationMetrics bool          `json:"publish_allocation_metrics" yaml:"publish_allocation_metrics"`
	PublishNodeMetrics       bool          `json:"publish_node_metrics" yaml:"publish_node_metrics"`
}

// NomadStatus represents the status of a Nomad cluster
type NomadStatus struct {
	ClusterID   string       `json:"cluster_id"`
	Leader      string       `json:"leader"`
	Servers     []ServerInfo `json:"servers"`
	Clients     []ClientInfo `json:"clients"`
	Jobs        []JobInfo    `json:"jobs"`
	Allocations []AllocInfo  `json:"allocations"`
	Healthy     bool         `json:"healthy"`
}

// ServerInfo represents information about a Nomad server
type ServerInfo struct {
	Name       string `json:"name"`
	Address    string `json:"address"`
	Port       int    `json:"port"`
	Leader     bool   `json:"leader"`
	Status     string `json:"status"`
	Datacenter string `json:"datacenter"`
	Region     string `json:"region"`
	Version    string `json:"version"`
}

// ClientInfo represents information about a Nomad client
type ClientInfo struct {
	Name        string            `json:"name"`
	Address     string            `json:"address"`
	Status      string            `json:"status"`
	Datacenter  string            `json:"datacenter"`
	NodeClass   string            `json:"node_class"`
	Version     string            `json:"version"`
	Attributes  map[string]string `json:"attributes"`
	Resources   ResourceInfo      `json:"resources"`
	Allocations int               `json:"allocations"`
}

// JobInfo represents information about a Nomad job
type JobInfo struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Type         string    `json:"type"`
	Status       string    `json:"status"`
	Priority     int       `json:"priority"`
	Datacenters  []string  `json:"datacenters"`
	TaskGroups   int       `json:"task_groups"`
	Allocations  int       `json:"allocations"`
	SubmitTime   time.Time `json:"submit_time"`
	LastModified time.Time `json:"last_modified"`
}

// AllocInfo represents information about a Nomad allocation
type AllocInfo struct {
	ID        string       `json:"id"`
	JobID     string       `json:"job_id"`
	TaskGroup string       `json:"task_group"`
	NodeID    string       `json:"node_id"`
	Status    string       `json:"status"`
	Created   time.Time    `json:"created"`
	Modified  time.Time    `json:"modified"`
	Resources ResourceInfo `json:"resources"`
}

// ResourceInfo represents resource information
type ResourceInfo struct {
	CPU      int           `json:"cpu"`
	Memory   int           `json:"memory"`
	Disk     int           `json:"disk"`
	Networks []NetworkInfo `json:"networks"`
}

// NetworkInfo represents network information
type NetworkInfo struct {
	Device string     `json:"device"`
	IP     string     `json:"ip"`
	MBits  int        `json:"mbits"`
	Ports  []PortInfo `json:"ports"`
}

// PortInfo represents port information
type PortInfo struct {
	Label string `json:"label"`
	Value int    `json:"value"`
	To    int    `json:"to"`
}

// Constants for Nomad configuration
const (
	// Default ports
	DefaultHTTPPort = 4646
	DefaultRPCPort  = 4647
	DefaultSerfPort = 4648

	// Default paths
	DefaultDataDir   = "/opt/nomad/data"
	DefaultConfigDir = "/etc/nomad.d"
	DefaultLogLevel  = "INFO"

	// Node roles
	NodeRoleServer = "server"
	NodeRoleClient = "client"
	NodeRoleBoth   = "both"

	// Job types
	JobTypeService = "service"
	JobTypeBatch   = "batch"
	JobTypeSystem  = "system"

	// Allocation states
	AllocStatePending  = "pending"
	AllocStateRunning  = "running"
	AllocStateComplete = "complete"
	AllocStateFailed   = "failed"
	AllocStateLost     = "lost"
)

// GetDefaultConfig returns a default Nomad configuration
func GetDefaultConfig() *Config {
	return &Config{
		Version:    "latest",
		Datacenter: "dc1",
		Region:     "global",
		NodeRole:   NodeRoleBoth,
		EnableUI:   true,
		HTTPPort:   DefaultHTTPPort,
		RPCPort:    DefaultRPCPort,
		SerfPort:   DefaultSerfPort,

		ConsulIntegration: true,
		VaultIntegration:  true,
		ConsulAddress:     fmt.Sprintf("%s:%d", shared.GetInternalHostname(), shared.PortConsul),
		VaultAddress:      fmt.Sprintf("%s:%d", shared.GetInternalHostname(), shared.PortVault),

		EnableTLS:    true,
		EnableACL:    true,
		EnableGossip: true,

		DataDir:   DefaultDataDir,
		ConfigDir: DefaultConfigDir,
		LogLevel:  DefaultLogLevel,

		ServerBootstrapExpect: 1,
		ClientReserved: ClientReserved{
			CPU:    100,
			Memory: 256,
			Disk:   1024,
			Ports:  "22",
		},

		DockerEnabled:  true,
		ExecEnabled:    true,
		RawExecEnabled: false,

		EnableTelemetry: true,
		TelemetryConfig: TelemetryConfig{
			PrometheusMetrics:        true,
			DisableHostname:          false,
			CollectionInterval:       time.Second * 10,
			PublishAllocationMetrics: true,
			PublishNodeMetrics:       true,
		},
	}
}
