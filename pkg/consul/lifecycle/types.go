// pkg/consul/lifecycle/types.go
// Type definitions for Consul installation lifecycle

package lifecycle

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
)

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
	UI             bool `json:"ui"` // Alias for EnableUI
	ConnectEnabled bool `json:"connect_enabled"`
	MeshGateway    bool `json:"mesh_gateway"`
	IngressGateway bool `json:"ingress_gateway"`

	// Installation options
	Version          string `json:"version"`
	VaultIntegration bool   `json:"vault_integration"`
	LogLevel         string `json:"log_level"`
	Force            bool   `json:"force"`
	Clean            bool   `json:"clean"`
	UseRepository    bool   `json:"use_repository"`
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

// PreflightCheck represents a pre-installation validation check
type PreflightCheck struct {
	Name        string
	Description string
	Critical    bool
	CheckFunc   func(*eos_io.RuntimeContext) error
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
