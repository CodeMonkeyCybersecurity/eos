// Package consul provides types and utilities for Consul deployment
package consul

import (
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
)

// Config holds the complete Consul configuration (legacy - deprecated)
type Config struct {
	DatacenterName          string
	EnableDebugLogging      bool
	DisableVaultIntegration bool
}

// ConsulConfig represents the comprehensive Consul configuration
type ConsulConfig struct {
	Mode            string   `json:"mode"` // server, agent, dev
	Datacenter      string   `json:"datacenter"`
	NodeName        string   `json:"node_name"`
	BootstrapExpect int      `json:"bootstrap_expect"`
	JoinAddresses   []string `json:"join_addresses"`
	RetryJoin       []string `json:"retry_join"`

	// Networking
	BindAddr      string     `json:"bind_addr"`
	ClientAddr    string     `json:"client_addr"`
	AdvertiseAddr string     `json:"advertise_addr"`
	Ports         PortConfig `json:"ports"`

	// Security
	EnableACL  bool   `json:"enable_acl"`
	EnableTLS  bool   `json:"enable_tls"`
	GossipKey  string `json:"gossip_key"`
	CACert     string `json:"ca_cert"`
	ServerCert string `json:"server_cert"`
	ServerKey  string `json:"server_key"`

	// Features
	EnableUI       bool `json:"enable_ui"`
	ConnectEnabled bool `json:"connect_enabled"`
	MeshGateway    bool `json:"mesh_gateway"`
	IngressGateway bool `json:"ingress_gateway"`

	// Advanced
	Performance PerformanceConfig `json:"performance"`
	Telemetry   TelemetryConfig   `json:"telemetry"`
	Logging     LoggingConfig     `json:"logging"`
}

// PortConfig defines port configuration for Consul
type PortConfig struct {
	DNS     int `json:"dns"`      // 8600 (standard Consul DNS port)
	HTTP    int `json:"http"`     // shared.PortConsul (8161)
	HTTPS   int `json:"https"`    // 8501
	GRPC    int `json:"grpc"`     // 8502
	SerfLAN int `json:"serf_lan"` // 8301
	SerfWAN int `json:"serf_wan"` // 8302
	Server  int `json:"server"`   // 8300
}

// PerformanceConfig defines performance tuning options
type PerformanceConfig struct {
	RaftMultiplier   int  `json:"raft_multiplier"`
	LeaveOnTerm      bool `json:"leave_on_terminate"`
	SkipLeaveOnInt   bool `json:"skip_leave_on_interrupt"`
	RejoinAfterLeave bool `json:"rejoin_after_leave"`
}

// TelemetryConfig defines telemetry options
type TelemetryConfig struct {
	PrometheusRetentionTime string `json:"prometheus_retention_time"`
	DisableHostname         bool   `json:"disable_hostname"`
	StatsdAddr              string `json:"statsd_addr"`
	DogstatsdAddr           string `json:"dogstatsd_addr"`
}

// LoggingConfig defines logging options
type LoggingConfig struct {
	LogLevel     string `json:"log_level"`
	LogFile      string `json:"log_file"`
	LogRotate    bool   `json:"log_rotate"`
	EnableJSON   bool   `json:"enable_json"`
	EnableSyslog bool   `json:"enable_syslog"`
}

// PreflightCheck represents a pre-installation validation check
type PreflightCheck struct {
	Name        string
	Description string
	Critical    bool
	CheckFunc   func(*eos_io.RuntimeContext) error
}

// BootstrapStatus represents the cluster bootstrap status
type BootstrapStatus struct {
	Bootstrapped     bool      `json:"bootstrapped"`
	Leader           string    `json:"leader"`
	Peers            []string  `json:"peers"`
	ACLBootstrapped  bool      `json:"acl_bootstrapped"`
	InitialRootToken string    `json:"initial_root_token"`
	BootstrapTime    time.Time `json:"bootstrap_time"`
}

// ClusterMember represents a Consul cluster member
type ClusterMember struct {
	Name        string            `json:"name"`
	Addr        string            `json:"addr"`
	Port        uint16            `json:"port"`
	Tags        map[string]string `json:"tags"`
	Status      string            `json:"status"`
	ProtocolMin uint8             `json:"protocol_min"`
	ProtocolMax uint8             `json:"protocol_max"`
	ProtocolCur uint8             `json:"protocol_cur"`
	DelegateMin uint8             `json:"delegate_min"`
	DelegateMax uint8             `json:"delegate_max"`
	DelegateCur uint8             `json:"delegate_cur"`
}

// ACLToken represents a Consul ACL token
type ACLToken struct {
	AccessorID  string    `json:"accessor_id"`
	SecretID    string    `json:"secret_id"`
	Description string    `json:"description"`
	Policies    []string  `json:"policies"`
	Local       bool      `json:"local"`
	CreateTime  time.Time `json:"create_time"`
	Hash        string    `json:"hash"`
}

// DefaultPortConfig returns the default Consul port configuration
func DefaultPortConfig() PortConfig {
	return PortConfig{
		DNS:     8600,
		HTTP:    shared.PortConsul, // 8161
		HTTPS:   8501,
		GRPC:    8502,
		SerfLAN: 8301,
		SerfWAN: 8302,
		Server:  8300,
	}
}

// DefaultPerformanceConfig returns the default performance configuration
func DefaultPerformanceConfig() PerformanceConfig {
	return PerformanceConfig{
		RaftMultiplier:   1,
		LeaveOnTerm:      true,
		SkipLeaveOnInt:   false,
		RejoinAfterLeave: true,
	}
}

// DefaultLoggingConfig returns the default logging configuration
func DefaultLoggingConfig() LoggingConfig {
	return LoggingConfig{
		LogLevel:     "INFO",
		LogFile:      "/var/log/consul/consul.log",
		LogRotate:    true,
		EnableJSON:   false,
		EnableSyslog: false,
	}
}
