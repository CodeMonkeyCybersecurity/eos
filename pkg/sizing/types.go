package sizing

import (
	"time"
)

// ServiceType represents the type of service being sized
type ServiceType string

const (
	ServiceTypeWebServer      ServiceType = "web_server"
	ServiceTypeDatabase       ServiceType = "database"
	ServiceTypeCache          ServiceType = "cache"
	ServiceTypeQueue          ServiceType = "queue"
	ServiceTypeWorker         ServiceType = "worker"
	ServiceTypeProxy          ServiceType = "proxy"
	ServiceTypeMonitoring     ServiceType = "monitoring"
	ServiceTypeLogging        ServiceType = "logging"
	ServiceTypeStorage        ServiceType = "storage"
	ServiceTypeContainer      ServiceType = "container"
	ServiceTypeOrchestrator   ServiceType = "orchestrator"
	ServiceTypeVault          ServiceType = "vault"
)

// ResourceRequirements defines the resource needs for a service
type ResourceRequirements struct {
	CPU    CPURequirements    `json:"cpu"`
	Memory MemoryRequirements `json:"memory"`
	Disk   DiskRequirements   `json:"disk"`
	Network NetworkRequirements `json:"network,omitempty"`
}

// CPURequirements defines CPU needs
type CPURequirements struct {
	Cores      float64 `json:"cores"`
	Type       string  `json:"type,omitempty"` // "compute", "general", "burstable"
	BurstRatio float64 `json:"burst_ratio,omitempty"`
}

// MemoryRequirements defines memory needs
type MemoryRequirements struct {
	GB         float64 `json:"gb"`
	Type       string  `json:"type,omitempty"` // "standard", "high-performance"
	SwapRatio  float64 `json:"swap_ratio,omitempty"`
}

// DiskRequirements defines storage needs
type DiskRequirements struct {
	GB         float64 `json:"gb"`
	Type       string  `json:"type"` // "ssd", "hdd", "nvme"
	IOPS       int     `json:"iops,omitempty"`
	Throughput int     `json:"throughput_mbps,omitempty"`
}

// NetworkRequirements defines network needs
type NetworkRequirements struct {
	BandwidthMbps int    `json:"bandwidth_mbps"`
	Latency       string `json:"latency,omitempty"` // "low", "medium", "high"
	PublicIP      bool   `json:"public_ip"`
}

// ServiceDefinition contains the sizing parameters for a service
type ServiceDefinition struct {
	Name                 string               `json:"name"`
	Type                 ServiceType          `json:"type"`
	BaseRequirements     ResourceRequirements `json:"base_requirements"`
	ScalingFactor        float64              `json:"scaling_factor"`
	LoadFactor           float64              `json:"load_factor"`
	RedundancyFactor     int                  `json:"redundancy_factor"`
	Description          string               `json:"description"`
	Dependencies         []string             `json:"dependencies,omitempty"`
	Ports                []int                `json:"ports,omitempty"`
	HealthCheckInterval  time.Duration        `json:"health_check_interval,omitempty"`
	MaxInstancesPerNode  int                  `json:"max_instances_per_node,omitempty"`
}

// WorkloadProfile represents the expected workload characteristics
type WorkloadProfile struct {
	Name                string        `json:"name"`
	ConcurrentUsers     int           `json:"concurrent_users"`
	RequestsPerSecond   int           `json:"requests_per_second"`
	AverageRequestSize  int           `json:"average_request_size_kb"`
	AverageResponseSize int           `json:"average_response_size_kb"`
	DataGrowthRate      float64       `json:"data_growth_rate_gb_per_month"`
	RetentionPeriod     time.Duration `json:"retention_period"`
	PeakToAverageRatio  float64       `json:"peak_to_average_ratio"`
	BurstDuration       time.Duration `json:"burst_duration"`
	ReadWriteRatio      float64       `json:"read_write_ratio"`
}

// SizingResult contains the calculated infrastructure requirements
type SizingResult struct {
	TotalCPUCores      float64                        `json:"total_cpu_cores"`
	TotalMemoryGB      float64                        `json:"total_memory_gb"`
	TotalDiskGB        float64                        `json:"total_disk_gb"`
	TotalBandwidthMbps int                            `json:"total_bandwidth_mbps"`
	Services           map[string]ServiceRequirements `json:"services"`
	NodeCount          int                            `json:"node_count"`
	NodeSpecs          NodeSpecification              `json:"node_specs"`
	EstimatedCost      CostEstimate                   `json:"estimated_cost,omitempty"`
	Warnings           []string                       `json:"warnings,omitempty"`
	Recommendations    []string                       `json:"recommendations,omitempty"`
}

// ServiceRequirements contains the calculated requirements for a specific service
type ServiceRequirements struct {
	Service          ServiceDefinition    `json:"service"`
	InstanceCount    int                  `json:"instance_count"`
	TotalResources   ResourceRequirements `json:"total_resources"`
	PerInstance      ResourceRequirements `json:"per_instance"`
	PlacementStrategy string              `json:"placement_strategy"`
}

// NodeSpecification defines the recommended node configuration
type NodeSpecification struct {
	CPUCores       int     `json:"cpu_cores"`
	MemoryGB       int     `json:"memory_gb"`
	DiskGB         int     `json:"disk_gb"`
	DiskType       string  `json:"disk_type"`
	NetworkGbps    int     `json:"network_gbps"`
	Provider       string  `json:"provider,omitempty"`
	InstanceType   string  `json:"instance_type,omitempty"`
	CPUUtilization float64 `json:"cpu_utilization"`
	MemUtilization float64 `json:"mem_utilization"`
}

// CostEstimate provides cost estimation
type CostEstimate struct {
	Monthly   float64            `json:"monthly"`
	Yearly    float64            `json:"yearly"`
	Breakdown map[string]float64 `json:"breakdown,omitempty"`
	Currency  string             `json:"currency"`
}

// SizingConfig contains configuration for the sizing calculator
type SizingConfig struct {
	Environment        string           `json:"environment"` // "development", "staging", "production"
	OverprovisionRatio float64          `json:"overprovision_ratio"`
	GrowthBuffer       float64          `json:"growth_buffer"`
	MaxNodeSize        NodeSpecification `json:"max_node_size"`
	MinNodeSize        NodeSpecification `json:"min_node_size"`
	Provider           string           `json:"provider,omitempty"` // "aws", "hetzner", "digitalocean", etc.
	Region             string           `json:"region,omitempty"`
}

// ValidationError represents a validation error
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// Predefined service definitions
var ServiceDefinitions = map[ServiceType]ServiceDefinition{
	ServiceTypeWebServer: {
		Name: "Web Server",
		Type: ServiceTypeWebServer,
		BaseRequirements: ResourceRequirements{
			CPU:    CPURequirements{Cores: 2, Type: "general"},
			Memory: MemoryRequirements{GB: 4, Type: "standard"},
			Disk:   DiskRequirements{GB: 50, Type: "ssd"},
		},
		ScalingFactor:    0.001, // Per concurrent user
		LoadFactor:       1.5,
		RedundancyFactor: 2,
		Description:      "HTTP/HTTPS web server (nginx, apache, etc)",
		Ports:            []int{80, 443},
	},
	ServiceTypeDatabase: {
		Name: "Database",
		Type: ServiceTypeDatabase,
		BaseRequirements: ResourceRequirements{
			CPU:    CPURequirements{Cores: 4, Type: "compute"},
			Memory: MemoryRequirements{GB: 16, Type: "high-performance"},
			Disk:   DiskRequirements{GB: 100, Type: "nvme", IOPS: 10000},
		},
		ScalingFactor:    0.002,
		LoadFactor:       2.0,
		RedundancyFactor: 2,
		Description:      "Relational or NoSQL database server",
		Ports:            []int{5432, 3306, 27017},
	},
	ServiceTypeCache: {
		Name: "Cache Server",
		Type: ServiceTypeCache,
		BaseRequirements: ResourceRequirements{
			CPU:    CPURequirements{Cores: 2, Type: "general"},
			Memory: MemoryRequirements{GB: 8, Type: "high-performance"},
			Disk:   DiskRequirements{GB: 20, Type: "ssd"},
		},
		ScalingFactor:    0.0005,
		LoadFactor:       1.2,
		RedundancyFactor: 2,
		Description:      "In-memory cache (Redis, Memcached)",
		Ports:            []int{6379, 11211},
	},
	ServiceTypeQueue: {
		Name: "Message Queue",
		Type: ServiceTypeQueue,
		BaseRequirements: ResourceRequirements{
			CPU:    CPURequirements{Cores: 2, Type: "general"},
			Memory: MemoryRequirements{GB: 4, Type: "standard"},
			Disk:   DiskRequirements{GB: 50, Type: "ssd", Throughput: 100},
		},
		ScalingFactor:    0.001,
		LoadFactor:       1.5,
		RedundancyFactor: 3,
		Description:      "Message queue service (RabbitMQ, Kafka)",
		Ports:            []int{5672, 9092},
	},
	ServiceTypeWorker: {
		Name: "Worker Process",
		Type: ServiceTypeWorker,
		BaseRequirements: ResourceRequirements{
			CPU:    CPURequirements{Cores: 1, Type: "compute"},
			Memory: MemoryRequirements{GB: 2, Type: "standard"},
			Disk:   DiskRequirements{GB: 20, Type: "ssd"},
		},
		ScalingFactor:    0.001,
		LoadFactor:       1.0,
		RedundancyFactor: 1,
		Description:      "Background job worker",
	},
	ServiceTypeProxy: {
		Name: "Reverse Proxy",
		Type: ServiceTypeProxy,
		BaseRequirements: ResourceRequirements{
			CPU:    CPURequirements{Cores: 2, Type: "general"},
			Memory: MemoryRequirements{GB: 2, Type: "standard"},
			Disk:   DiskRequirements{GB: 20, Type: "ssd"},
			Network: NetworkRequirements{BandwidthMbps: 1000, PublicIP: true},
		},
		ScalingFactor:    0.0005,
		LoadFactor:       1.3,
		RedundancyFactor: 2,
		Description:      "Load balancer/reverse proxy (HAProxy, nginx)",
		Ports:            []int{80, 443},
	},
	ServiceTypeMonitoring: {
		Name: "Monitoring Stack",
		Type: ServiceTypeMonitoring,
		BaseRequirements: ResourceRequirements{
			CPU:    CPURequirements{Cores: 2, Type: "general"},
			Memory: MemoryRequirements{GB: 8, Type: "standard"},
			Disk:   DiskRequirements{GB: 100, Type: "ssd", IOPS: 5000},
		},
		ScalingFactor:    0.01, // Per monitored service
		LoadFactor:       1.5,
		RedundancyFactor: 1,
		Description:      "Monitoring and metrics (Prometheus, Grafana)",
		Ports:            []int{3000, 9090},
	},
	ServiceTypeLogging: {
		Name: "Logging Stack",
		Type: ServiceTypeLogging,
		BaseRequirements: ResourceRequirements{
			CPU:    CPURequirements{Cores: 2, Type: "general"},
			Memory: MemoryRequirements{GB: 8, Type: "standard"},
			Disk:   DiskRequirements{GB: 200, Type: "ssd", Throughput: 200},
		},
		ScalingFactor:    0.002,
		LoadFactor:       2.0,
		RedundancyFactor: 1,
		Description:      "Centralized logging (ELK, Loki)",
		Ports:            []int{9200, 5601},
	},
	ServiceTypeStorage: {
		Name: "Storage Service",
		Type: ServiceTypeStorage,
		BaseRequirements: ResourceRequirements{
			CPU:    CPURequirements{Cores: 2, Type: "general"},
			Memory: MemoryRequirements{GB: 4, Type: "standard"},
			Disk:   DiskRequirements{GB: 500, Type: "hdd", Throughput: 500},
		},
		ScalingFactor:    0.01, // Per TB of data
		LoadFactor:       1.2,
		RedundancyFactor: 3,
		Description:      "Object/block storage service",
		Ports:            []int{9000},
	},
	ServiceTypeContainer: {
		Name: "Container Runtime",
		Type: ServiceTypeContainer,
		BaseRequirements: ResourceRequirements{
			CPU:    CPURequirements{Cores: 4, Type: "general"},
			Memory: MemoryRequirements{GB: 8, Type: "standard"},
			Disk:   DiskRequirements{GB: 100, Type: "ssd"},
		},
		ScalingFactor:    0.01, // Per container
		LoadFactor:       1.5,
		RedundancyFactor: 1,
		Description:      "Docker/containerd runtime",
		Ports:            []int{2375, 2376},
	},
	ServiceTypeOrchestrator: {
		Name: "Container Orchestrator",
		Type: ServiceTypeOrchestrator,
		BaseRequirements: ResourceRequirements{
			CPU:    CPURequirements{Cores: 2, Type: "general"},
			Memory: MemoryRequirements{GB: 4, Type: "standard"},
			Disk:   DiskRequirements{GB: 50, Type: "ssd"},
		},
		ScalingFactor:    0.1, // Per node managed
		LoadFactor:       1.5,
		RedundancyFactor: 3,
		Description:      "Kubernetes, Nomad, Swarm",
		Ports:            []int{6443, 4646},
	},
	ServiceTypeVault: {
		Name: "Secrets Management",
		Type: ServiceTypeVault,
		BaseRequirements: ResourceRequirements{
			CPU:    CPURequirements{Cores: 2, Type: "general"},
			Memory: MemoryRequirements{GB: 4, Type: "standard"},
			Disk:   DiskRequirements{GB: 50, Type: "ssd", IOPS: 5000},
		},
		ScalingFactor:    0.0001,
		LoadFactor:       1.2,
		RedundancyFactor: 3,
		Description:      "HashiCorp Vault or similar",
		Ports:            []int{8200},
	},
}

// Default workload profiles
var DefaultWorkloadProfiles = map[string]WorkloadProfile{
	"small": {
		Name:                "Small Workload",
		ConcurrentUsers:     100,
		RequestsPerSecond:   10,
		AverageRequestSize:  10,
		AverageResponseSize: 50,
		DataGrowthRate:      10,
		RetentionPeriod:     30 * 24 * time.Hour,
		PeakToAverageRatio:  2.0,
		BurstDuration:       1 * time.Hour,
		ReadWriteRatio:      0.8,
	},
	"medium": {
		Name:                "Medium Workload",
		ConcurrentUsers:     1000,
		RequestsPerSecond:   100,
		AverageRequestSize:  20,
		AverageResponseSize: 100,
		DataGrowthRate:      100,
		RetentionPeriod:     90 * 24 * time.Hour,
		PeakToAverageRatio:  3.0,
		BurstDuration:       2 * time.Hour,
		ReadWriteRatio:      0.7,
	},
	"large": {
		Name:                "Large Workload",
		ConcurrentUsers:     10000,
		RequestsPerSecond:   1000,
		AverageRequestSize:  50,
		AverageResponseSize: 200,
		DataGrowthRate:      1000,
		RetentionPeriod:     365 * 24 * time.Hour,
		PeakToAverageRatio:  4.0,
		BurstDuration:       4 * time.Hour,
		ReadWriteRatio:      0.6,
	},
}

// Environment configurations
var EnvironmentConfigs = map[string]SizingConfig{
	"development": {
		Environment:        "development",
		OverprovisionRatio: 1.2,
		GrowthBuffer:       1.1,
		MaxNodeSize: NodeSpecification{
			CPUCores:    8,
			MemoryGB:    16,
			DiskGB:      200,
			NetworkGbps: 1,
		},
		MinNodeSize: NodeSpecification{
			CPUCores:    2,
			MemoryGB:    4,
			DiskGB:      50,
			NetworkGbps: 1,
		},
	},
	"staging": {
		Environment:        "staging",
		OverprovisionRatio: 1.5,
		GrowthBuffer:       1.3,
		MaxNodeSize: NodeSpecification{
			CPUCores:    16,
			MemoryGB:    32,
			DiskGB:      500,
			NetworkGbps: 10,
		},
		MinNodeSize: NodeSpecification{
			CPUCores:    4,
			MemoryGB:    8,
			DiskGB:      100,
			NetworkGbps: 1,
		},
	},
	"production": {
		Environment:        "production",
		OverprovisionRatio: 2.0,
		GrowthBuffer:       1.5,
		MaxNodeSize: NodeSpecification{
			CPUCores:    64,
			MemoryGB:    128,
			DiskGB:      2000,
			NetworkGbps: 40,
		},
		MinNodeSize: NodeSpecification{
			CPUCores:    8,
			MemoryGB:    16,
			DiskGB:      200,
			NetworkGbps: 10,
		},
	},
}