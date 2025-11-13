// pkg/enrollment/types.go
package enrollment

import (
	"time"
)

// EnrollmentConfig holds the configuration for server enrollment
type EnrollmentConfig struct {
	Role           string // "master" or "minion"
	ess            string // For minions
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
	Version       string             `json:"_version"`
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

// MasterInfo contains information about discovered  masters
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

// Configuration holds -specific configuration
type Configuration struct {
	LogLevel     string                 `json:"log_level"`
	FileRoots    []string               `json:"file_roots"`
	Roots        []string               `json:"_roots"`
	Environment  map[string]interface{} `json:"environment"`
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

// Constants for enrollment (HashiCorp migration)
const (
	// Roles
	RoleMaster     = "master"
	RoleAgent      = "agent"      // HashiCorp cluster agent
	RoleMasterless = "standalone" // Standalone HashiCorp deployment

	// Network modes
	NetworkModeConsul    = "consul-connect"
	NetworkModeWireGuard = "wireguard"
	NetworkModeDirect    = "direct"

	// HashiCorp ports (replacing  ports)
	PublisherPort = 4505 // For backward compatibility
	RequestPort   = 4506 // For backward compatibility

	// Backup suffix for configuration files
	BackupSuffix = ".eos-backup"
)

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

func (s *SystemInfo) IsDockerInstalled() bool {
	return s.DockerVersion != ""
}
