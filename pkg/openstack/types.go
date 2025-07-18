package openstack


import (
	"fmt"
	"time"
)

// DeploymentMode represents the OpenStack deployment mode
type DeploymentMode string

const (
	ModeAllInOne   DeploymentMode = "all-in-one"
	ModeController DeploymentMode = "controller"
	ModeCompute    DeploymentMode = "compute"
	ModeStorage    DeploymentMode = "storage"
)

// NetworkType represents the OpenStack network configuration
type NetworkType string

const (
	NetworkProvider NetworkType = "provider"
	NetworkTenant   NetworkType = "tenant"
	NetworkHybrid   NetworkType = "hybrid"
)

// StorageBackend represents the storage backend type
type StorageBackend string

const (
	StorageLVM  StorageBackend = "lvm"
	StorageCeph StorageBackend = "ceph"
	StorageNFS  StorageBackend = "nfs"
)

// Service represents an OpenStack service
type Service string

const (
	ServiceKeystone Service = "keystone"
	ServiceGlance   Service = "glance"
	ServiceNova     Service = "nova"
	ServiceNeutron  Service = "neutron"
	ServiceCinder   Service = "cinder"
	ServiceSwift    Service = "swift"
	ServiceHorizon  Service = "horizon"
	ServiceHeat     Service = "heat"
)

// Config holds the complete OpenStack configuration
type Config struct {
	// Deployment mode
	Mode DeploymentMode

	// Network configuration
	NetworkType       NetworkType
	ProviderInterface string
	ProviderPhysnet   string
	TenantNetwork     string
	ExternalNetwork   string

	// Storage configuration
	StorageBackend     StorageBackend
	CephMonitors       []string
	CephPool           string
	NFSServer          string
	NFSExportPath      string
	LVMVolumeGroup     string

	// Service configuration
	EnabledServices []Service
	EnableDashboard bool
	EnableSSL       bool
	SSLCertPath     string
	SSLKeyPath      string

	// Authentication
	AdminPassword    string
	AdminEmail       string
	AdminProject     string
	ServicePassword  string
	RabbitMQPassword string
	DBPassword       string

	// Endpoints
	PublicEndpoint   string
	InternalEndpoint string
	AdminEndpoint    string

	// Integration
	VaultIntegration  bool
	VaultAddress      string
	VaultToken        string
	ConsulIntegration bool
	ConsulAddress     string

	// Node configuration
	ControllerAddress string
	ManagementNetwork string
	
	// Compute specific
	CPUAllocationRatio float64
	RAMAllocationRatio float64
	DiskAllocationRatio float64
	
	// LDAP/AD Integration
	EnableLDAP               bool
	LDAPServer               string
	LDAPUser                 string
	LDAPPassword             string
	LDAPSuffix               string
	LDAPUseTLS               bool
	LDAPCACert               string
	LDAPUserTreeDN           string
	LDAPUserObjectClass      string
	LDAPUserIDAttribute      string
	LDAPUserNameAttribute    string
	LDAPUserMailAttribute    string
	LDAPUserEnabledAttribute string
	LDAPGroupTreeDN          string
	LDAPGroupObjectClass     string
	LDAPGroupIDAttribute     string
	LDAPGroupNameAttribute   string
	LDAPGroupMemberAttribute string
	LDAPGroupDescAttribute   string
	
	// Operational
	DryRun bool
	Force  bool
	Backup bool
}

// ServiceConfig holds configuration for a specific OpenStack service
type ServiceConfig struct {
	Name        Service
	Enabled     bool
	Endpoint    string
	Port        int
	Database    string
	User        string
	ConfigPath  string
	LogPath     string
	ExtraConfig map[string]interface{}
}

// NodeInfo represents information about an OpenStack node
type NodeInfo struct {
	Hostname       string
	IPAddress      string
	Role           DeploymentMode
	Services       []Service
	CPUCores       int
	MemoryGB       int
	DiskGB         int
	OSVersion      string
	KernelVersion  string
}

// InstallationInfo represents an existing OpenStack installation
type InstallationInfo struct {
	Version     string
	Mode        DeploymentMode
	Services    []ServiceInfo
	Nodes       []NodeInfo
	Endpoints   map[string]string
	InstallDate string
}

// ServiceInfo represents information about an OpenStack service
type ServiceInfo struct {
	Name        string
	Type        string
	Description string
	Endpoint    string
	Status      string
	Version     string
}

// InstallationStatus represents the current installation state
type InstallationStatus struct {
	Installed        bool
	Version          string
	Mode             DeploymentMode
	Services         []ServiceStatus
	Nodes            []NodeInfo
	LastUpdated      time.Time
	HealthStatus     string
}

// ServiceStatus represents the status of an OpenStack service
type ServiceStatus struct {
	Name      Service
	Enabled   bool
	Running   bool
	Healthy   bool
	Endpoints []string
	Version   string
	Message   string
}

// Constants for installation paths and configuration
const (
	// Installation paths
	OpenStackBaseDir    = "/etc/openstack"
	OpenStackConfigDir  = "/etc/openstack/config.d"
	OpenStackLogDir     = "/var/log/openstack"
	OpenStackStateDir   = "/var/lib/openstack"
	OpenStackBackupDir  = "/var/backups/openstack"

	// User and group
	OpenStackUser  = "openstack"
	OpenStackGroup = "openstack"

	// Default ports
	PortKeystone       = 5000
	PortKeystoneAdmin  = 35357
	PortGlance         = 9292
	PortNovaAPI        = 8774
	PortNovaMetadata   = 8775
	PortNovaVNC        = 6080
	PortNeutron        = 9696
	PortCinder         = 8776
	PortSwift          = 8080
	PortHorizon        = 80
	PortHorizonSSL     = 443
	PortHeat           = 8004

	// Database names
	DBKeystone = "keystone"
	DBGlance   = "glance"
	DBNova     = "nova"
	DBNeutron  = "neutron"
	DBCinder   = "cinder"
	DBHeat     = "heat"

	// Default resource allocation ratios
	DefaultCPUAllocationRatio  = 16.0
	DefaultRAMAllocationRatio  = 1.5
	DefaultDiskAllocationRatio = 1.0

	// Timeouts
	ServiceStartTimeout    = 5 * time.Minute
	ServiceStopTimeout     = 2 * time.Minute
	HealthCheckTimeout     = 30 * time.Second
	InstallationTimeout    = 30 * time.Minute
)

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	// Validate deployment mode
	switch c.Mode {
	case ModeAllInOne, ModeController, ModeCompute, ModeStorage:
		// Valid modes
	default:
		return fmt.Errorf("invalid deployment mode: %s", c.Mode)
	}

	// Validate required fields based on mode
	if c.Mode != ModeAllInOne && c.ControllerAddress == "" {
		return fmt.Errorf("controller address required for %s mode", c.Mode)
	}

	// Validate passwords
	if c.AdminPassword == "" {
		return fmt.Errorf("admin password is required")
	}
	if len(c.AdminPassword) < 8 {
		return fmt.Errorf("admin password must be at least 8 characters")
	}

	// Validate network configuration
	if c.NetworkType == NetworkProvider && c.ProviderInterface == "" {
		return fmt.Errorf("provider network interface required for provider network type")
	}

	// Validate storage backend
	switch c.StorageBackend {
	case StorageCeph:
		if len(c.CephMonitors) == 0 {
			return fmt.Errorf("Ceph monitors required for Ceph storage backend")
		}
	case StorageNFS:
		if c.NFSServer == "" || c.NFSExportPath == "" {
			return fmt.Errorf("NFS server and export path required for NFS storage backend")
		}
	}

	// Validate endpoints
	if c.PublicEndpoint == "" {
		return fmt.Errorf("public endpoint is required")
	}

	// Validate SSL configuration
	if c.EnableSSL && (c.SSLCertPath == "" || c.SSLKeyPath == "") {
		return fmt.Errorf("SSL certificate and key paths required when SSL is enabled")
	}

	// Validate resource allocation ratios
	if c.CPUAllocationRatio <= 0 {
		c.CPUAllocationRatio = DefaultCPUAllocationRatio
	}
	if c.RAMAllocationRatio <= 0 {
		c.RAMAllocationRatio = DefaultRAMAllocationRatio
	}

	return nil
}

// GetEnabledServices returns the list of services to enable based on deployment mode
func (c *Config) GetEnabledServices() []Service {
	if len(c.EnabledServices) > 0 {
		return c.EnabledServices
	}

	// Default services based on mode
	switch c.Mode {
	case ModeAllInOne:
		services := []Service{
			ServiceKeystone,
			ServiceGlance,
			ServiceNova,
			ServiceNeutron,
			ServiceCinder,
		}
		if c.EnableDashboard {
			services = append(services, ServiceHorizon)
		}
		return services

	case ModeController:
		services := []Service{
			ServiceKeystone,
			ServiceGlance,
			ServiceNova,
			ServiceNeutron,
			ServiceCinder,
		}
		if c.EnableDashboard {
			services = append(services, ServiceHorizon)
		}
		return services

	case ModeCompute:
		return []Service{ServiceNova, ServiceNeutron}

	case ModeStorage:
		return []Service{ServiceCinder}

	default:
		return []Service{}
	}
}

// IsControllerNode returns true if this is a controller or all-in-one node
func (c *Config) IsControllerNode() bool {
	return c.Mode == ModeController || c.Mode == ModeAllInOne
}