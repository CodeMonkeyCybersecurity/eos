// pkg/wazuh_mssp/types.go
package wazuh_mssp

import (
	"time"
)

// PlatformConfig represents the overall MSSP platform configuration
type PlatformConfig struct {
	Name        string          `json:"platform_name"`
	Environment string          `json:"environment"` // dev, staging, production
	Datacenter  string          `json:"datacenter"`
	Domain      string          `json:"platform_domain"`
	Network     NetworkConfig   `json:"network_config"`
	Storage     StorageConfig   `json:"storage_config"`
	Nomad       NomadConfig     `json:"nomad_config"`
	Temporal    TemporalConfig  `json:"temporal_config"`
	NATS        NATSConfig      `json:"nats_config"`
	CCS         CCSConfig       `json:"ccs_config"`
	Authentik   AuthentikConfig `json:"authentik_config"`
}

// NetworkConfig defines network configuration for the platform
type NetworkConfig struct {
	PlatformCIDR string    `json:"platform_cidr"`
	CustomerCIDR string    `json:"customer_cidr"`
	VLANRange    VLANRange `json:"vlan_range"`
}

// VLANRange defines the VLAN range for customer isolation
type VLANRange struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

// StorageConfig defines storage pool configuration
type StorageConfig struct {
	Pools map[string]StoragePool `json:"pools"`
}

// StoragePool represents a storage pool configuration
type StoragePool struct {
	Path string `json:"path"`
	Size string `json:"size"`
}

// NomadConfig defines Nomad cluster configuration
type NomadConfig struct {
	ServerCount     int            `json:"server_count"`
	ClientCount     int            `json:"client_count"`
	ServerResources ResourceConfig `json:"server_resources"`
	ClientResources ResourceConfig `json:"client_resources"`
}

// TemporalConfig defines Temporal cluster configuration
type TemporalConfig struct {
	ServerCount       int            `json:"server_count"`
	ServerResources   ResourceConfig `json:"server_resources"`
	DatabaseResources ResourceConfig `json:"database_resources"`
	Namespace         string         `json:"namespace"`
}

// NATSConfig defines NATS cluster configuration
type NATSConfig struct {
	ServerCount     int             `json:"server_count"`
	ServerResources ResourceConfig  `json:"server_resources"`
	EnableJetStream bool            `json:"enable_jetstream"`
	JetStreamConfig JetStreamConfig `json:"jetstream_config"`
}

// JetStreamConfig defines NATS JetStream configuration
type JetStreamConfig struct {
	MaxMemory string `json:"max_memory"`
	MaxFile   string `json:"max_file"`
}

// CCSConfig defines Cross-Cluster Search configuration
type CCSConfig struct {
	IndexerResources   ResourceConfig `json:"indexer_resources"`
	DashboardResources ResourceConfig `json:"dashboard_resources"`
}

// AuthentikConfig defines Authentik SSO configuration
type AuthentikConfig struct {
	URL     string `json:"url"`
	Token   string `json:"token"`
	Enabled bool   `json:"enabled"`
}

// ResourceConfig defines resource allocation
type ResourceConfig struct {
	VCPUs  int    `json:"vcpus"`
	Memory string `json:"memory"` // e.g., "4096" (MB)
	Disk   string `json:"disk"`   // e.g., "50G"
}

// CustomerConfig represents a customer configuration
type CustomerConfig struct {
	ID            string                `json:"customer_id"`
	CompanyName   string                `json:"company_name"`
	Subdomain     string                `json:"subdomain"`
	Tier          CustomerTier          `json:"tier"`
	AdminEmail    string                `json:"admin_email"`
	AdminName     string                `json:"admin_name"`
	AuthentikData AuthentikCustomerData `json:"authentik_data"`
	Resources     CustomerResources     `json:"resources"`
	WazuhConfig   WazuhDeploymentConfig `json:"wazuh_config"`
	CreatedAt     time.Time             `json:"created_at"`
	UpdatedAt     time.Time             `json:"updated_at"`
	Status        CustomerStatus        `json:"status"`
}

// CustomerTier represents the customer subscription tier
type CustomerTier string

const (
	TierStarter    CustomerTier = "starter"
	TierPro        CustomerTier = "pro"
	TierEnterprise CustomerTier = "enterprise"
)

// CustomerStatus represents the customer deployment status
type CustomerStatus string

const (
	StatusPending      CustomerStatus = "pending"
	StatusProvisioning CustomerStatus = "provisioning"
	StatusActive       CustomerStatus = "active"
	StatusSuspended    CustomerStatus = "suspended"
	StatusDeleting     CustomerStatus = "deleting"
	StatusDeleted      CustomerStatus = "deleted"
)

// AuthentikCustomerData contains Authentik-specific customer data
type AuthentikCustomerData struct {
	GroupID string `json:"group_id"`
	UserID  string `json:"user_id"`
}

// CustomerResources defines resource allocation per tier
type CustomerResources struct {
	Indexer   ResourceAllocation `json:"indexer"`
	Server    ResourceAllocation `json:"server"`
	Dashboard ResourceAllocation `json:"dashboard"`
}

// ResourceAllocation defines specific resource allocation
type ResourceAllocation struct {
	Count  int    `json:"count"`
	CPU    int    `json:"cpu"`
	Memory int    `json:"memory"` // MB
	Disk   string `json:"disk"`   // e.g., "100G"
}

// WazuhDeploymentConfig contains Wazuh-specific deployment configuration
type WazuhDeploymentConfig struct {
	Version          string `json:"version"`
	IndexerEnabled   bool   `json:"indexer_enabled"`
	ServerEnabled    bool   `json:"server_enabled"`
	DashboardEnabled bool   `json:"dashboard_enabled"`
}

// GetResourcesByTier returns resource allocation based on customer tier
func GetResourcesByTier(tier CustomerTier) CustomerResources {
	switch tier {
	case TierStarter:
		return CustomerResources{
			Indexer: ResourceAllocation{
				Count:  1,
				CPU:    2,
				Memory: 4096,
				Disk:   "100G",
			},
			Server: ResourceAllocation{
				Count:  1,
				CPU:    2,
				Memory: 2048,
				Disk:   "50G",
			},
			Dashboard: ResourceAllocation{
				Count:  1,
				CPU:    1,
				Memory: 1024,
				Disk:   "20G",
			},
		}
	case TierPro:
		return CustomerResources{
			Indexer: ResourceAllocation{
				Count:  3,
				CPU:    4,
				Memory: 8192,
				Disk:   "200G",
			},
			Server: ResourceAllocation{
				Count:  2,
				CPU:    4,
				Memory: 4096,
				Disk:   "100G",
			},
			Dashboard: ResourceAllocation{
				Count:  1,
				CPU:    2,
				Memory: 2048,
				Disk:   "50G",
			},
		}
	case TierEnterprise:
		return CustomerResources{
			Indexer: ResourceAllocation{
				Count:  5,
				CPU:    8,
				Memory: 16384,
				Disk:   "500G",
			},
			Server: ResourceAllocation{
				Count:  3,
				CPU:    8,
				Memory: 8192,
				Disk:   "200G",
			},
			Dashboard: ResourceAllocation{
				Count:  2,
				CPU:    4,
				Memory: 4096,
				Disk:   "100G",
			},
		}
	default:
		return GetResourcesByTier(TierStarter)
	}
}

// ProvisioningRequest represents a customer provisioning request
type ProvisioningRequest struct {
	Customer    CustomerConfig `json:"customer"`
	RequestedBy string         `json:"requested_by"`
	RequestedAt time.Time      `json:"requested_at"`
}

// ScalingRequest represents a customer scaling request
type ScalingRequest struct {
	CustomerID  string       `json:"customer_id"`
	NewTier     CustomerTier `json:"new_tier"`
	RequestedBy string       `json:"requested_by"`
	RequestedAt time.Time    `json:"requested_at"`
}

// BackupRequest represents a customer backup request
type BackupRequest struct {
	CustomerID  string     `json:"customer_id"`
	BackupType  BackupType `json:"backup_type"`
	RequestedBy string     `json:"requested_by"`
	RequestedAt time.Time  `json:"requested_at"`
}

// BackupType represents the type of backup
type BackupType string

const (
	BackupTypeFull        BackupType = "full"
	BackupTypeIncremental BackupType = "incremental"
)

// DeploymentStatus represents the deployment status
type DeploymentStatus struct {
	CustomerID        string                     `json:"customer_id"`
	Status            CustomerStatus             `json:"status"`
	ComponentStatuses map[string]ComponentStatus `json:"component_statuses"`
	LastUpdated       time.Time                  `json:"last_updated"`
}

// ComponentStatus represents individual component status
type ComponentStatus struct {
	Name     string `json:"name"`
	Status   string `json:"status"`
	Health   string `json:"health"`
	Version  string `json:"version"`
	Endpoint string `json:"endpoint,omitempty"`
}

// Constants for common configurations
const (
	DefaultWazuhVersion = "4.13.0" // Updated to current stable version
	DefaultDatacenter   = "dc1"
	DefaultEnvironment  = "production"
	DefaultPlatformCIDR = "10.0.0.0/16"
	DefaultCustomerCIDR = "10.100.0.0/16"
	DefaultVLANStart    = 100
	DefaultVLANEnd      = 999
)

// Validation constants
const (
	MinCustomerIDLength = 5
	MaxCustomerIDLength = 50
	MinSubdomainLength  = 3
	MaxSubdomainLength  = 63
)
