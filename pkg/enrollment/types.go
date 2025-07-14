// pkg/enrollment/types.go
package enrollment

import (
	"fmt"
	"time"
)

// EnrollmentConfig holds the configuration for server enrollment
type EnrollmentConfig struct {
	Role           string // "master" or "minion"
	MasterAddress  string // For minions
	Datacenter     string // Geographic location
	NetworkMode    string // "consul-connect" or "wireguard"
	TransitionMode bool   // True if converting from masterless
	AutoDetect     bool   // Auto-detect role based on infrastructure
	DryRun         bool   // Preview changes without applying
}

// SystemInfo contains discovered system information
type SystemInfo struct {
	Hostname      string             `json:"hostname"`
	Platform      string             `json:"platform"`     // linux, darwin, windows
	Architecture  string             `json:"architecture"` // amd64, arm64
	CPUCores      int                `json:"cpu_cores"`
	MemoryGB      int                `json:"memory_gb"`
	DiskSpaceGB   int                `json:"disk_space_gb"`
	NetworkIfaces []NetworkInterface `json:"network_interfaces"`
	Services      []ServiceInfo      `json:"services"`
	SaltMode      string             `json:"salt_mode"` // "masterless", "minion", "master", "none"
	SaltVersion   string             `json:"salt_version"`
	DockerVersion string             `json:"docker_version"`
	KernelVersion string             `json:"kernel_version"`
	Uptime        time.Duration      `json:"uptime"`
	LoadAverage   []float64          `json:"load_average"` // 1, 5, 15 minute averages
}

// NetworkInterface represents a network interface
type NetworkInterface struct {
	Name     string   `json:"name"`
	Type     string   `json:"type"` // ethernet, wireless, loopback
	IPv4     []string `json:"ipv4"`
	IPv6     []string `json:"ipv6"`
	MAC      string   `json:"mac"`
	MTU      int      `json:"mtu"`
	IsUp     bool     `json:"is_up"`
	IsPublic bool     `json:"is_public"` // Has public IP
}

// ServiceInfo represents a running service
type ServiceInfo struct {
	Name        string `json:"name"`
	Status      string `json:"status"` // running, stopped, failed
	Port        int    `json:"port,omitempty"`
	ProcessID   int    `json:"process_id"`
	StartTime   string `json:"start_time"`
	Description string `json:"description"`
}

// MasterInfo contains information about discovered salt masters
type MasterInfo struct {
	Address    string    `json:"address"`
	Datacenter string    `json:"datacenter"`
	Version    string    `json:"version"`
	LastSeen   time.Time `json:"last_seen"`
	Responsive bool      `json:"responsive"`
	Priority   int       `json:"priority"`
	Status     string    `json:"status"`
}

// EnrollmentResult contains the results of enrollment
type EnrollmentResult struct {
	Success        bool          `json:"success"`
	Role           string        `json:"role"`
	MasterAddress  string        `json:"master_address,omitempty"`
	ServicesSetup  []string      `json:"services_setup"`
	ConfigsUpdated []string      `json:"configs_updated"`
	BackupsCreated []string      `json:"backups_created"`
	Duration       time.Duration `json:"duration"`
	Errors         []string      `json:"errors,omitempty"`
}

// SaltConfiguration holds salt-specific configuration
type SaltConfiguration struct {
	Mode         string                 `json:"mode"` // master, minion, masterless
	MasterAddr   string                 `json:"master_addr,omitempty"`
	MinionID     string                 `json:"minion_id"`
	LogLevel     string                 `json:"log_level"`
	FileRoots    []string               `json:"file_roots"`
	PillarRoots  []string               `json:"pillar_roots"`
	Extensions   map[string]string      `json:"extensions"`
	CustomConfig map[string]interface{} `json:"custom_config"`
}

// NetworkConfiguration holds network setup configuration
type NetworkConfiguration struct {
	Mode          string         `json:"mode"` // consul-connect, wireguard, direct
	ConsulAddr    string         `json:"consul_addr,omitempty"`
	ConsulDC      string         `json:"consul_dc,omitempty"`
	WGInterface   string         `json:"wg_interface,omitempty"`
	WGPort        int            `json:"wg_port,omitempty"`
	FirewallRules []FirewallRule `json:"firewall_rules"`
}

// FirewallRule represents a firewall rule to be configured
type FirewallRule struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"` // tcp, udp
	Source   string `json:"source"`   // CIDR or "any"
	Target   string `json:"target"`   // ACCEPT, DROP, REJECT
	Comment  string `json:"comment"`
}

// Constants for enrollment
const (
	// Roles
	RoleMaster = "master"
	RoleMinion = "minion"

	// Network modes
	NetworkModeConsul    = "consul-connect"
	NetworkModeWireGuard = "wireguard"
	NetworkModeDirect    = "direct"

	// Salt modes
	SaltModeMaster     = "master"
	SaltModeMinion     = "minion"
	SaltModeMasterless = "masterless"
	SaltModeNone       = "none"

	// Salt ports
	SaltPublisherPort = 4505
	SaltRequestPort   = 4506

	// Consul ports - deprecated, use shared.Port* constants instead
	// ConsulHTTPPort = 8500 // Use shared.PortConsul (8161) instead
	ConsulDNSPort  = 8600
	ConsulSerfPort = 8301

	// Default directories
	DefaultSaltConfigDir = "/etc/salt"
	DefaultSaltStateDir  = "/srv/salt"
	DefaultSaltPillarDir = "/srv/pillar"

	// Backup suffix
	BackupSuffix = ".eos-backup"
)

// Validation functions
func (c *EnrollmentConfig) Validate() error {
	if c.Role != "" && c.Role != RoleMaster && c.Role != RoleMinion {
		return fmt.Errorf("invalid role: %s, must be 'master' or 'minion'", c.Role)
	}

	if c.Role == RoleMinion && c.MasterAddress == "" && !c.AutoDetect {
		return fmt.Errorf("master address required for minion role")
	}

	if c.NetworkMode != "" && c.NetworkMode != NetworkModeConsul &&
		c.NetworkMode != NetworkModeWireGuard && c.NetworkMode != NetworkModeDirect {
		return fmt.Errorf("invalid network mode: %s", c.NetworkMode)
	}

	return nil
}

func (s *SystemInfo) HasSufficientResources() bool {
	// Minimum requirements: 1GB RAM, 10GB disk, 1 CPU core
	return s.MemoryGB >= 1 && s.DiskSpaceGB >= 10 && s.CPUCores >= 1
}

func (s *SystemInfo) GetPublicInterface() *NetworkInterface {
	for _, iface := range s.NetworkIfaces {
		if iface.IsPublic && iface.IsUp {
			return &iface
		}
	}
	return nil
}

func (s *SystemInfo) IsSaltInstalled() bool {
	return s.SaltVersion != "" && s.SaltMode != SaltModeNone
}

func (s *SystemInfo) IsDockerInstalled() bool {
	return s.DockerVersion != ""
}
