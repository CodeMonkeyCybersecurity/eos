package cephfs

import (
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
)

// Config represents the configuration options for CephFS deployment
type Config struct {
	// Core cluster configuration
	ClusterFSID string // Ceph cluster FSID (UUID format)
	AdminHost   string // Admin host for cephadm operations
	SSHUser     string // SSH user for remote operations
	CephImage   string // Ceph container image to use

	// Network configuration
	PublicNetwork  string // Public network CIDR (e.g., 10.0.0.0/24)
	ClusterNetwork string // Cluster network CIDR (e.g., 10.1.0.0/24)

	// Storage configuration
	OSDDevices  []string // Specific OSD devices to use
	ObjectStore string   // Object store type (default: bluestore)

	// Operational settings
	SkipVerify    bool // Skip cluster health verification
	TerraformOnly bool // Only run Terraform deployment
	ForceRedeploy bool // Force redeployment even if cluster exists

	// Performance tuning
	OSDMemoryTarget string // OSD memory target (default: 4G)
	MONCount        int    // Number of MON daemons (default: 3)
	MGRCount        int    // Number of MGR daemons (default: 2)

	Name            string
	MountPoint      string
	MonitorHosts    []string
	SecretFile      string
	User            string
	Pool            string
	DataPool        string
	MetadataPool    string
	ReplicationSize int
	PGNum           int
	MountOptions    []string
}

// GetObjectStore returns the object store type with fallback to default
func (c *Config) GetObjectStore() string {
	if c.ObjectStore == "" {
		return DefaultObjectStore
	}
	return c.ObjectStore
}

// GetOSDMemoryTarget returns the OSD memory target with fallback to default
func (c *Config) GetOSDMemoryTarget() string {
	if c.OSDMemoryTarget == "" {
		return DefaultOSDMemoryTarget
	}
	return c.OSDMemoryTarget
}

// GetMONCount returns the MON count with fallback to default
func (c *Config) GetMONCount() int {
	if c.MONCount == 0 {
		return DefaultMONCount
	}
	return c.MONCount
}

// GetMGRCount returns the MGR count with fallback to default
func (c *Config) GetMGRCount() int {
	if c.MGRCount == 0 {
		return DefaultMGRCount
	}
	return c.MGRCount
}

// DeploymentStatus represents the current deployment status
type DeploymentStatus struct {
	ClusterExists   bool
	ClusterHealthy  bool
	OSDs            []OSDStatus
	MONs            []DaemonStatus
	MGRs            []DaemonStatus
	CephFSAvailable bool
	LastChecked     time.Time
	Version         string
}

// OSDStatus represents the status of an OSD
type OSDStatus struct {
	ID     int     `json:"id"`
	UUID   string  `json:"uuid"`
	Up     bool    `json:"up"`
	In     bool    `json:"in"`
	Device string  `json:"device"`
	Host   string  `json:"host"`
	Weight float64 `json:"weight"`
	Class  string  `json:"class"`
	State  string  `json:"state"`
}

// DaemonStatus represents the status of a Ceph daemon (MON/MGR)
type DaemonStatus struct {
	Name    string    `json:"name"`
	Host    string    `json:"host"`
	Status  string    `json:"status"`
	Version string    `json:"version"`
	Started time.Time `json:"started"`
}



// TerraformConfig represents the Terraform configuration for CephFS
type TerraformConfig struct {
	WorkingDir   string            // Terraform working directory
	Variables    map[string]string // Terraform variables
	StateBackend string            // Terraform state backend
	PlanFile     string            // Terraform plan file path
}

// VerificationResult represents the result of cluster verification
type VerificationResult struct {
	ClusterHealthy bool          `json:"cluster_healthy"`
	AllOSDsUp      bool          `json:"all_osds_up"`
	AllMONsUp      bool          `json:"all_mons_up"`
	AllMGRsUp      bool          `json:"all_mgrs_up"`
	CephFSHealthy  bool          `json:"cephfs_healthy"`
	Errors         []string      `json:"errors"`
	Warnings       []string      `json:"warnings"`
	CheckDuration  time.Duration `json:"check_duration"`
}

// Constants for CephFS configuration
const (
	// Default Ceph image and version
	DefaultCephImage   = "quay.io/ceph/ceph:v18.2.1"
	DefaultCephVersion = "v18.2.1"

	// Default paths
	CephConfigDir = "/etc/ceph"
	CephDataDir   = "/var/lib/ceph"
	CephLogDir    = "/var/log/ceph"
	CephadmPath   = "/usr/local/bin/cephadm"


	// Terraform paths
	TerraformCephDir   = "/opt/eos/terraform/ceph"
	TerraformStateFile = "terraform.tfstate"
	TerraformPlanFile  = "terraform.tfplan"

	// Default configuration values
	DefaultObjectStore     = "bluestore"
	DefaultOSDMemoryTarget = "4G"
	DefaultMONCount        = 3
	DefaultMGRCount        = 2
	DefaultSSHUser         = "root"

	// CephFS specific ports from shared/ports.go
	CephMONPort = 6789
	CephMGRPort = shared.PortConsul // Use next available port: 8161
	CephOSDPort = 6800              // Base port, OSDs use 6800-6900 range
	CephFSPort  = 6810              // CephFS metadata server port

	// Health check timeouts
	DefaultHealthCheckTimeout  = 5 * time.Minute
	DefaultOrchestratorTimeout = 10 * time.Minute
	DefaultDeploymentTimeout   = 30 * time.Minute

	// OSD specifications
	OSDServiceType = "osd"
	OSDServiceID   = "all-available-devices"
	OSDFilterLogic = "AND"

	// Minimum system requirements
	MinimumOSDMemoryMB = 4096 // 4GB minimum per OSD
	MinimumDiskSpaceGB = 10   // 10GB minimum per OSD

	// Default test files for verification
	TestMountPoint  = "/mnt/cephfs-test"
	TestFileName    = "eos-cephfs-test.txt"
	TestFileContent = "EOS CephFS deployment verification test"
)

// CephServiceSpec represents a Ceph service specification
type CephServiceSpec struct {
	ServiceType string            `yaml:"service_type"`
	ServiceID   string            `yaml:"service_id"`
	Placement   CephPlacementSpec `yaml:"placement"`
	Spec        map[string]any    `yaml:"spec"`
}

// CephPlacementSpec represents placement configuration for Ceph services
type CephPlacementSpec struct {
	HostPattern string   `yaml:"host_pattern,omitempty"`
	Hosts       []string `yaml:"hosts,omitempty"`
	Count       int      `yaml:"count,omitempty"`
}

// CephOSDSpec represents OSD specification
type CephOSDSpec struct {
	DataDevices CephDeviceSpec `yaml:"data_devices"`
	FilterLogic string         `yaml:"filter_logic"`
	ObjectStore string         `yaml:"objectstore"`
	Rotational  *bool          `yaml:"rotational,omitempty"`
	Paths       []string       `yaml:"paths,omitempty"`
}

// CephDeviceSpec represents device specification for OSDs
type CephDeviceSpec struct {
	All        bool     `yaml:"all,omitempty"`
	Paths      []string `yaml:"paths,omitempty"`
	Rotational *bool    `yaml:"rotational,omitempty"`
}

// GetCephMGRPort returns the next available port for CephFS MGR
func GetCephMGRPort() int {
	// Use the next available port from shared/ports.go
	return 8263 // Next available prime after shared ports
}



// GetTerraformCephConfigPath returns the path to the Terraform configuration
func GetTerraformCephConfigPath() string {
	return TerraformCephDir + "/main.tf"
}

// IsValidCephImage validates the Ceph image format
func IsValidCephImage(image string) bool {
	// Basic validation for Ceph image format
	// Expected format: registry/repo:tag
	if len(image) == 0 {
		return false
	}

	// Must contain a colon for tag
	if !contains(image, ":") {
		return false
	}

	// Should contain common Ceph registries
	validRegistries := []string{
		"quay.io/ceph/ceph",
		"ceph/ceph",
		"docker.io/ceph/ceph",
	}

	for _, registry := range validRegistries {
		if len(image) >= len(registry) && image[:len(registry)] == registry {
			return true
		}
	}

	return false
}

// contains checks if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s == substr ||
			(len(s) > len(substr) &&
				(s[:len(substr)] == substr ||
					s[len(s)-len(substr):] == substr ||
					indexOf(s, substr) >= 0)))
}

// indexOf returns the index of the first occurrence of substr in s
func indexOf(s, substr string) int {
	if len(substr) == 0 {
		return 0
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// VolumeInfo represents CephFS volume information
type VolumeInfo struct {
	Name          string
	ID            string
	State         string
	CreatedAt     time.Time
	Size          int64
	UsedSize      int64
	AvailableSize int64
	MountPoints   []string
	DataPools     []string
	MetadataPools []string
}

// PerformanceConfig represents CephFS performance tuning options
type PerformanceConfig struct {
	CacheSize      string
	CachePressure  int
	ReadAheadKB    int
	MaxDirtyBytes  int64
	AsyncDirOps    bool
	ClientOSDCache bool
}

// ReplicationConfig represents CephFS replication settings
type ReplicationConfig struct {
	Size      int
	MinSize   int
	CrushRule string
	PGNum     int
	PGPNum    int
}

// MountInfo represents a CephFS mount point
type MountInfo struct {
	Device     string
	MountPoint string
	FileSystem string
	Options    []string
	IsActive   bool
}

const (
	// DefaultReplicationSize is the default number of replicas
	DefaultReplicationSize = 3

	// DefaultPGNum is the default number of placement groups
	DefaultPGNum = 128

	// DefaultCacheSize is the default client cache size
	DefaultCacheSize = "4096M"

	// DefaultReadAheadKB is the default read-ahead size in KB
	DefaultReadAheadKB = 8192
)

// MountOptions provides recommended mount options for different use cases
var MountOptions = map[string][]string{
	"performance": {
		"noatime",
		"nodiratime",
		"rsize=130048",
		"wsize=130048",
		"caps_max=65536",
	},
	"standard": {
		"noatime",
		"_netdev",
	},
	"secure": {
		"noatime",
		"_netdev",
		"secretfile=/etc/ceph/ceph.client.admin.keyring",
	},
}
