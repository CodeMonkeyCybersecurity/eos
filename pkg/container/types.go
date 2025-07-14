// Package container defines domain entities for container management
package container

import (
	"time"
)

// Core domain entities

// ContainerStatus represents the status of a container
type ContainerStatus string

const (
	StatusCreated    ContainerStatus = "created"
	StatusRunning    ContainerStatus = "running"
	StatusPaused     ContainerStatus = "paused"
	StatusRestarting ContainerStatus = "restarting"
	StatusExited     ContainerStatus = "exited"
	StatusDead       ContainerStatus = "dead"
)

// Container represents a container instance
type Container struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Image       string            `json:"image"`
	Status      ContainerStatus   `json:"status"`
	State       *ContainerState   `json:"state,omitempty"`
	Config      *ContainerConfig  `json:"config,omitempty"`
	NetworkMode string            `json:"network_mode,omitempty"`
	Ports       []PortMapping     `json:"ports,omitempty"`
	Volumes     []VolumeMount     `json:"volumes,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Environment []string          `json:"environment,omitempty"`
	Created     time.Time         `json:"created"`
	StartedAt   *time.Time        `json:"started_at,omitempty"`
	FinishedAt  *time.Time        `json:"finished_at,omitempty"`
}

// ContainerSpec defines parameters for creating a container
type ContainerSpec struct {
	Name          string            `json:"name"`
	Image         string            `json:"image"`
	Command       []string          `json:"command,omitempty"`
	Args          []string          `json:"args,omitempty"`
	Environment   []string          `json:"environment,omitempty"`
	Labels        map[string]string `json:"labels,omitempty"`
	Ports         []PortMapping     `json:"ports,omitempty"`
	Volumes       []VolumeMount     `json:"volumes,omitempty"`
	NetworkMode   string            `json:"network_mode,omitempty"`
	RestartPolicy *RestartPolicy    `json:"restart_policy,omitempty"`
	Resources     *ResourceLimits   `json:"resources,omitempty"`
	Security      *SecurityConfig   `json:"security,omitempty"`
	HealthCheck   *HealthCheck      `json:"health_check,omitempty"`
	WorkingDir    string            `json:"working_dir,omitempty"`
	User          string            `json:"user,omitempty"`
	Privileged    bool              `json:"privileged,omitempty"`
	ReadOnly      bool              `json:"read_only,omitempty"`
}

// ContainerState represents the current state of a container
type ContainerState struct {
	Status     ContainerStatus `json:"status"`
	Running    bool            `json:"running"`
	Paused     bool            `json:"paused"`
	Restarting bool            `json:"restarting"`
	Dead       bool            `json:"dead"`
	Pid        int             `json:"pid,omitempty"`
	ExitCode   int             `json:"exit_code,omitempty"`
	Error      string          `json:"error,omitempty"`
	StartedAt  *time.Time      `json:"started_at,omitempty"`
	FinishedAt *time.Time      `json:"finished_at,omitempty"`
}

// ContainerConfig represents container configuration
type ContainerConfig struct {
	Hostname     string            `json:"hostname,omitempty"`
	Domainname   string            `json:"domainname,omitempty"`
	User         string            `json:"user,omitempty"`
	AttachStdin  bool              `json:"attach_stdin"`
	AttachStdout bool              `json:"attach_stdout"`
	AttachStderr bool              `json:"attach_stderr"`
	Tty          bool              `json:"tty"`
	OpenStdin    bool              `json:"open_stdin"`
	StdinOnce    bool              `json:"stdin_once"`
	Environment  []string          `json:"environment,omitempty"`
	Command      []string          `json:"command,omitempty"`
	Image        string            `json:"image"`
	WorkingDir   string            `json:"working_dir,omitempty"`
	Entrypoint   []string          `json:"entrypoint,omitempty"`
	Labels       map[string]string `json:"labels,omitempty"`
}

// PortMapping defines port mapping between host and container
type PortMapping struct {
	HostIP        string `json:"host_ip,omitempty"`
	HostPort      string `json:"host_port"`
	ContainerPort string `json:"container_port"`
	Protocol      string `json:"protocol"` // tcp, udp, sctp
}

// VolumeMount defines volume mounting configuration
type VolumeMount struct {
	Type        string `json:"type"`        // bind, volume, tmpfs
	Source      string `json:"source"`      // host path or volume name
	Destination string `json:"destination"` // container path
	ReadOnly    bool   `json:"read_only"`
	Propagation string `json:"propagation,omitempty"` // shared, slave, private, rshared, rslave, rprivate
}

// RestartPolicy defines container restart behavior
type RestartPolicy struct {
	Name              string `json:"name"`                // no, always, unless-stopped, on-failure
	MaximumRetryCount int    `json:"maximum_retry_count"` // for on-failure policy
}

// ResourceLimits defines container resource constraints
type ResourceLimits struct {
	Memory     int64    `json:"memory,omitempty"`      // bytes
	MemorySwap int64    `json:"memory_swap,omitempty"` // bytes
	CPUShares  int64    `json:"cpu_shares,omitempty"`  // relative weight
	CPUQuota   int64    `json:"cpu_quota,omitempty"`   // microseconds
	CPUPeriod  int64    `json:"cpu_period,omitempty"`  // microseconds
	CPUSetCPUs string   `json:"cpuset_cpus,omitempty"` // 0-3, 0,1
	Ulimits    []Ulimit `json:"ulimits,omitempty"`
}

// Ulimit defines resource limits
type Ulimit struct {
	Name string `json:"name"`
	Soft int64  `json:"soft"`
	Hard int64  `json:"hard"`
}

// SecurityConfig defines container security settings
type SecurityConfig struct {
	Privileged      bool     `json:"privileged"`
	ReadOnlyRootfs  bool     `json:"read_only_rootfs"`
	SecurityOpt     []string `json:"security_opt,omitempty"`
	CapAdd          []string `json:"cap_add,omitempty"`
	CapDrop         []string `json:"cap_drop,omitempty"`
	UsernsMode      string   `json:"userns_mode,omitempty"`
	PidMode         string   `json:"pid_mode,omitempty"`
	IpcMode         string   `json:"ipc_mode,omitempty"`
	UTSMode         string   `json:"uts_mode,omitempty"`
	AppArmorProfile string   `json:"apparmor_profile,omitempty"`
	SELinuxLabel    string   `json:"selinux_label,omitempty"`
}

// HealthCheck defines container health check configuration
type HealthCheck struct {
	Test        []string      `json:"test,omitempty"`         // CMD, CMD-SHELL, or NONE
	Interval    time.Duration `json:"interval,omitempty"`     // time between checks
	Timeout     time.Duration `json:"timeout,omitempty"`      // maximum time for check
	StartPeriod time.Duration `json:"start_period,omitempty"` // grace period
	Retries     int           `json:"retries,omitempty"`      // consecutive failures needed
}

// Image represents a container image
type Image struct {
	ID          string            `json:"id"`
	Repository  string            `json:"repository"`
	Tag         string            `json:"tag"`
	Digest      string            `json:"digest,omitempty"`
	Size        int64             `json:"size"`
	Created     time.Time         `json:"created"`
	Labels      map[string]string `json:"labels,omitempty"`
	RepoTags    []string          `json:"repo_tags,omitempty"`
	RepoDigests []string          `json:"repo_digests,omitempty"`
}

// Volume represents a container volume
type Volume struct {
	Name       string            `json:"name"`
	Driver     string            `json:"driver"`
	Mountpoint string            `json:"mountpoint"`
	Labels     map[string]string `json:"labels,omitempty"`
	Options    map[string]string `json:"options,omitempty"`
	Scope      string            `json:"scope"` // local, global
	Created    time.Time         `json:"created"`
}

// VolumeSpec defines parameters for creating a volume
type VolumeSpec struct {
	Name       string            `json:"name"`
	Driver     string            `json:"driver,omitempty"`
	DriverOpts map[string]string `json:"driver_opts,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
}

// Network represents a container network
type Network struct {
	ID         string                      `json:"id"`
	Name       string                      `json:"name"`
	Driver     string                      `json:"driver"`
	Scope      string                      `json:"scope"`
	IPAM       *NetworkIPAM                `json:"ipam,omitempty"`
	Containers map[string]*NetworkEndpoint `json:"containers,omitempty"`
	Options    map[string]string           `json:"options,omitempty"`
	Labels     map[string]string           `json:"labels,omitempty"`
	Created    time.Time                   `json:"created"`
}

// NetworkSpec defines parameters for creating a network
type NetworkSpec struct {
	Name           string            `json:"name"`
	Driver         string            `json:"driver,omitempty"`
	IPAM           *NetworkIPAM      `json:"ipam,omitempty"`
	Options        map[string]string `json:"options,omitempty"`
	Labels         map[string]string `json:"labels,omitempty"`
	EnableIPv6     bool              `json:"enable_ipv6,omitempty"`
	Internal       bool              `json:"internal,omitempty"`
	Attachable     bool              `json:"attachable,omitempty"`
	CheckDuplicate bool              `json:"check_duplicate,omitempty"`
}

// NetworkIPAM defines IP Address Management for networks
type NetworkIPAM struct {
	Driver  string              `json:"driver,omitempty"`
	Config  []NetworkIPAMConfig `json:"config,omitempty"`
	Options map[string]string   `json:"options,omitempty"`
}

// NetworkIPAMConfig defines IPAM configuration
type NetworkIPAMConfig struct {
	Subnet     string            `json:"subnet,omitempty"`
	IPRange    string            `json:"ip_range,omitempty"`
	Gateway    string            `json:"gateway,omitempty"`
	AuxAddress map[string]string `json:"aux_address,omitempty"`
}

// NetworkEndpoint represents a container's connection to a network
type NetworkEndpoint struct {
	Name        string `json:"name,omitempty"`
	EndpointID  string `json:"endpoint_id,omitempty"`
	MacAddress  string `json:"mac_address,omitempty"`
	IPv4Address string `json:"ipv4_address,omitempty"`
	IPv6Address string `json:"ipv6_address,omitempty"`
}

// Note: Service type is defined in config.go to avoid duplication

// BuildConfig defines build configuration for a service
type BuildConfig struct {
	Context    string            `json:"context,omitempty"`
	Dockerfile string            `json:"dockerfile,omitempty"`
	Args       map[string]string `json:"args,omitempty"`
	Target     string            `json:"target,omitempty"`
}

// DeployConfig defines deployment configuration for a service
type DeployConfig struct {
	Mode         string                `json:"mode,omitempty"`
	Replicas     *int                  `json:"replicas,omitempty"`
	Resources    *DeployResourceConfig `json:"resources,omitempty"`
	Placement    *PlacementConfig      `json:"placement,omitempty"`
	UpdateConfig *UpdateConfig         `json:"update_config,omitempty"`
	Labels       map[string]string     `json:"labels,omitempty"`
}

// DeployResourceConfig defines resource configuration for deployment
type DeployResourceConfig struct {
	Limits       *ResourceSpec `json:"limits,omitempty"`
	Reservations *ResourceSpec `json:"reservations,omitempty"`
}

// ResourceSpec defines resource specifications
type ResourceSpec struct {
	CPUs   string `json:"cpus,omitempty"`
	Memory string `json:"memory,omitempty"`
}

// PlacementConfig defines placement constraints for deployment
type PlacementConfig struct {
	Constraints []string `json:"constraints,omitempty"`
	Preferences []string `json:"preferences,omitempty"`
}

// UpdateConfig defines update configuration for deployment
type UpdateConfig struct {
	Parallelism     *int          `json:"parallelism,omitempty"`
	Delay           time.Duration `json:"delay,omitempty"`
	FailureAction   string        `json:"failure_action,omitempty"`
	Monitor         time.Duration `json:"monitor,omitempty"`
	MaxFailureRatio *float64      `json:"max_failure_ratio,omitempty"`
}

// Note: ComposeConfig type is defined in compose.go to avoid duplication

// VolumeConfig defines volume configuration in compose
type VolumeConfig struct {
	Driver     string            `json:"driver,omitempty"`
	DriverOpts map[string]string `json:"driver_opts,omitempty"`
	External   bool              `json:"external,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
	Name       string            `json:"name,omitempty"`
}

// NetworkConfig defines network configuration in compose
type NetworkConfig struct {
	Driver     string            `json:"driver,omitempty"`
	DriverOpts map[string]string `json:"driver_opts,omitempty"`
	External   bool              `json:"external,omitempty"`
	IPAM       *NetworkIPAM      `json:"ipam,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
	Name       string            `json:"name,omitempty"`
}

// SecretConfig defines secret configuration in compose
type SecretConfig struct {
	File     string            `json:"file,omitempty"`
	External bool              `json:"external,omitempty"`
	Labels   map[string]string `json:"labels,omitempty"`
	Name     string            `json:"name,omitempty"`
}

// ConfigFile defines config file configuration in compose
type ConfigFile struct {
	File     string            `json:"file,omitempty"`
	External bool              `json:"external,omitempty"`
	Labels   map[string]string `json:"labels,omitempty"`
	Name     string            `json:"name,omitempty"`
}

// Execution and result types

// Note: ExecConfig type is defined in exec.go to avoid duplication

// ExecResult represents the result of command execution
type ExecResult struct {
	ExitCode int           `json:"exit_code"`
	Stdout   string        `json:"stdout"`
	Stderr   string        `json:"stderr"`
	Duration time.Duration `json:"duration"`
	Error    error         `json:"-"`
}

// Monitoring and statistics

// ContainerStats represents container resource usage statistics
type ContainerStats struct {
	ContainerID  string                   `json:"container_id"`
	Name         string                   `json:"name"`
	CPUUsage     *CPUUsage                `json:"cpu_usage,omitempty"`
	MemoryUsage  *MemoryUsage             `json:"memory_usage,omitempty"`
	NetworkUsage map[string]*NetworkUsage `json:"network_usage,omitempty"`
	BlockIOUsage *BlockIOUsage            `json:"block_io_usage,omitempty"`
	PidsUsage    *PidsUsage               `json:"pids_usage,omitempty"`
	Timestamp    time.Time                `json:"timestamp"`
}

// CPUUsage represents CPU usage statistics
type CPUUsage struct {
	TotalUsage        uint64          `json:"total_usage"`
	UsageInKernelmode uint64          `json:"usage_in_kernelmode"`
	UsageInUsermode   uint64          `json:"usage_in_usermode"`
	SystemCPUUsage    uint64          `json:"system_cpu_usage"`
	OnlineCPUs        uint32          `json:"online_cpus"`
	ThrottlingData    *ThrottlingData `json:"throttling_data,omitempty"`
}

// ThrottlingData represents CPU throttling information
type ThrottlingData struct {
	Periods          uint64 `json:"periods"`
	ThrottledPeriods uint64 `json:"throttled_periods"`
	ThrottledTime    uint64 `json:"throttled_time"`
}

// MemoryUsage represents memory usage statistics
type MemoryUsage struct {
	Usage    uint64            `json:"usage"`
	MaxUsage uint64            `json:"max_usage"`
	Limit    uint64            `json:"limit"`
	Stats    map[string]uint64 `json:"stats,omitempty"`
}

// NetworkUsage represents network usage statistics
type NetworkUsage struct {
	RxBytes   uint64 `json:"rx_bytes"`
	RxDropped uint64 `json:"rx_dropped"`
	RxErrors  uint64 `json:"rx_errors"`
	RxPackets uint64 `json:"rx_packets"`
	TxBytes   uint64 `json:"tx_bytes"`
	TxDropped uint64 `json:"tx_dropped"`
	TxErrors  uint64 `json:"tx_errors"`
	TxPackets uint64 `json:"tx_packets"`
}

// BlockIOUsage represents block I/O usage statistics
type BlockIOUsage struct {
	IoServiceBytesRecursive []BlkioStatEntry `json:"io_service_bytes_recursive,omitempty"`
	IoServicedRecursive     []BlkioStatEntry `json:"io_serviced_recursive,omitempty"`
	IoQueueRecursive        []BlkioStatEntry `json:"io_queue_recursive,omitempty"`
	IoServiceTimeRecursive  []BlkioStatEntry `json:"io_service_time_recursive,omitempty"`
	IoWaitTimeRecursive     []BlkioStatEntry `json:"io_wait_time_recursive,omitempty"`
}

// BlkioStatEntry represents a block I/O statistic entry
type BlkioStatEntry struct {
	Major uint64 `json:"major"`
	Minor uint64 `json:"minor"`
	Op    string `json:"op"`
	Value uint64 `json:"value"`
}

// PidsUsage represents process ID usage statistics
type PidsUsage struct {
	Current uint64 `json:"current"`
	Limit   uint64 `json:"limit"`
}

// Health and events

// HealthStatus represents container health status
type HealthStatus struct {
	Status        string        `json:"status"` // starting, healthy, unhealthy
	FailingStreak int           `json:"failing_streak"`
	Log           []HealthCheck `json:"log,omitempty"`
}

// ContainerEvent represents a container event
type ContainerEvent struct {
	Type     string      `json:"type"`   // container, image, volume, network
	Action   string      `json:"action"` // create, start, stop, destroy, etc.
	Actor    *EventActor `json:"actor,omitempty"`
	Time     time.Time   `json:"time"`
	TimeNano int64       `json:"time_nano"`
	Scope    string      `json:"scope,omitempty"`
}

// EventActor represents the actor of an event
type EventActor struct {
	ID         string            `json:"id"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// Runtime and system information

// RuntimeInfo represents container runtime information
type RuntimeInfo struct {
	ID                 string              `json:"id"`
	Name               string              `json:"name"`
	Version            string              `json:"version"`
	APIVersion         string              `json:"api_version"`
	Architecture       string              `json:"architecture"`
	OSType             string              `json:"os_type"`
	OSVersion          string              `json:"os_version"`
	KernelVersion      string              `json:"kernel_version"`
	TotalMemory        int64               `json:"total_memory"`
	CPUs               int                 `json:"cpus"`
	ServerVersion      string              `json:"server_version"`
	IndexServerAddress string              `json:"index_server_address"`
	RegistryConfig     *RegistryConfig     `json:"registry_config,omitempty"`
	Plugins            map[string][]string `json:"plugins,omitempty"`
	Swarm              *SwarmInfo          `json:"swarm,omitempty"`
}

// RegistryConfig represents registry configuration
type RegistryConfig struct {
	IndexConfigs          map[string]*IndexConfig `json:"index_configs,omitempty"`
	InsecureRegistryCIDRs []string                `json:"insecure_registry_cidrs,omitempty"`
	Mirrors               []string                `json:"mirrors,omitempty"`
}

// IndexConfig represents index configuration
type IndexConfig struct {
	Name     string   `json:"name"`
	Mirrors  []string `json:"mirrors,omitempty"`
	Secure   bool     `json:"secure"`
	Official bool     `json:"official"`
}

// SwarmInfo represents Docker Swarm information
type SwarmInfo struct {
	NodeID   string       `json:"node_id,omitempty"`
	NodeAddr string       `json:"node_addr,omitempty"`
	Cluster  *ClusterInfo `json:"cluster,omitempty"`
}

// ClusterInfo represents cluster information
type ClusterInfo struct {
	ID   string       `json:"id,omitempty"`
	Spec *ClusterSpec `json:"spec,omitempty"`
}

// ClusterSpec represents cluster specification
type ClusterSpec struct {
	Name          string               `json:"name,omitempty"`
	Labels        map[string]string    `json:"labels,omitempty"`
	Orchestration *OrchestrationConfig `json:"orchestration,omitempty"`
	Raft          *RaftConfig          `json:"raft,omitempty"`
	Dispatcher    *DispatcherConfig    `json:"dispatcher,omitempty"`
	CAConfig      *CAConfig            `json:"ca_config,omitempty"`
}

// OrchestrationConfig represents orchestration configuration
type OrchestrationConfig struct {
	TaskHistoryRetentionLimit int `json:"task_history_retention_limit,omitempty"`
}

// RaftConfig represents Raft configuration
type RaftConfig struct {
	SnapshotInterval           uint64 `json:"snapshot_interval,omitempty"`
	KeepOldSnapshots           uint64 `json:"keep_old_snapshots,omitempty"`
	LogEntriesForSlowFollowers uint64 `json:"log_entries_for_slow_followers,omitempty"`
	ElectionTick               int    `json:"election_tick,omitempty"`
	HeartbeatTick              int    `json:"heartbeat_tick,omitempty"`
}

// DispatcherConfig represents dispatcher configuration
type DispatcherConfig struct {
	HeartbeatPeriod uint64 `json:"heartbeat_period,omitempty"`
}

// CAConfig represents certificate authority configuration
type CAConfig struct {
	NodeCertExpiry time.Duration `json:"node_cert_expiry,omitempty"`
}

// SystemUsage represents system resource usage
type SystemUsage struct {
	Containers         int        `json:"containers"`
	ContainersRunning  int        `json:"containers_running"`
	ContainersPaused   int        `json:"containers_paused"`
	ContainersStopped  int        `json:"containers_stopped"`
	Images             int        `json:"images"`
	Driver             string     `json:"driver"`
	DriverStatus       [][]string `json:"driver_status,omitempty"`
	SystemTime         time.Time  `json:"system_time"`
	LoggingDriver      string     `json:"logging_driver"`
	CgroupDriver       string     `json:"cgroup_driver"`
	NEventsListener    int        `json:"n_events_listener"`
	KernelVersion      string     `json:"kernel_version"`
	OperatingSystem    string     `json:"operating_system"`
	OSType             string     `json:"os_type"`
	Architecture       string     `json:"architecture"`
	IndexServerAddress string     `json:"index_server_address"`
	MemTotal           int64      `json:"mem_total"`
	NCPU               int        `json:"ncpu"`
}

// Search and registry types

// SearchResult represents a registry search result
type SearchResult struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	StarCount   int    `json:"star_count"`
	IsOfficial  bool   `json:"is_official"`
	IsAutomated bool   `json:"is_automated"`
}

// Prune results

// PruneResult represents the result of a system prune operation
type PruneResult struct {
	ContainersDeleted int   `json:"containers_deleted"`
	ImagesDeleted     int   `json:"images_deleted"`
	NetworksDeleted   int   `json:"networks_deleted"`
	VolumesDeleted    int   `json:"volumes_deleted"`
	SpaceReclaimed    int64 `json:"space_reclaimed"`
}

// Configuration and policy types

// ContainerConfiguration represents global container configuration
type ContainerConfiguration struct {
	DefaultRegistry       string            `json:"default_registry,omitempty"`
	DefaultNamespace      string            `json:"default_namespace,omitempty"`
	DefaultResourceLimits *ResourceLimits   `json:"default_resource_limits,omitempty"`
	DefaultSecurityConfig *SecurityConfig   `json:"default_security_config,omitempty"`
	RegistryMirrors       []string          `json:"registry_mirrors,omitempty"`
	InsecureRegistries    []string          `json:"insecure_registries,omitempty"`
	LogDriver             string            `json:"log_driver,omitempty"`
	LogOptions            map[string]string `json:"log_options,omitempty"`
}

// NetworkConfiguration represents global network configuration
type NetworkConfiguration struct {
	DefaultNetwork    string   `json:"default_network,omitempty"`
	DefaultIPv4Subnet string   `json:"default_ipv4_subnet,omitempty"`
	DefaultIPv6Subnet string   `json:"default_ipv6_subnet,omitempty"`
	EnableIPv6        bool     `json:"enable_ipv6,omitempty"`
	DNSServers        []string `json:"dns_servers,omitempty"`
	DNSSearch         []string `json:"dns_search,omitempty"`
	MTU               int      `json:"mtu,omitempty"`
}

// SecurityPolicy represents container security policy
type SecurityPolicy struct {
	Name                  string            `json:"name"`
	Description           string            `json:"description,omitempty"`
	AllowPrivileged       bool              `json:"allow_privileged"`
	AllowRootUser         bool              `json:"allow_root_user"`
	AllowedCapabilities   []string          `json:"allowed_capabilities,omitempty"`
	ForbiddenCapabilities []string          `json:"forbidden_capabilities,omitempty"`
	AllowedSysctls        []string          `json:"allowed_sysctls,omitempty"`
	ForbiddenSysctls      []string          `json:"forbidden_sysctls,omitempty"`
	RequiredLabels        map[string]string `json:"required_labels,omitempty"`
	ForbiddenLabels       map[string]string `json:"forbidden_labels,omitempty"`
	AllowedRegistries     []string          `json:"allowed_registries,omitempty"`
	ForbiddenImages       []string          `json:"forbidden_images,omitempty"`
	MaxMemory             int64             `json:"max_memory,omitempty"`
	MaxCPU                float64           `json:"max_cpu,omitempty"`
	ReadOnlyRootfs        bool              `json:"read_only_rootfs"`
	Rules                 []PolicyRule      `json:"rules,omitempty"`
	Version               string            `json:"version"`
	Created               time.Time         `json:"created"`
	Updated               time.Time         `json:"updated"`
}

// PolicyRule represents a specific policy rule
type PolicyRule struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Condition   string         `json:"condition"` // OPA/Rego expression
	Action      PolicyAction   `json:"action"`    // allow, deny, warn
	Severity    PolicySeverity `json:"severity"`  // low, medium, high, critical
	Message     string         `json:"message,omitempty"`
	Tags        []string       `json:"tags,omitempty"`
}

// PolicyAction represents policy rule actions
type PolicyAction string

const (
	PolicyActionAllow PolicyAction = "allow"
	PolicyActionDeny  PolicyAction = "deny"
	PolicyActionWarn  PolicyAction = "warn"
)

// PolicySeverity represents policy rule severity levels
type PolicySeverity string

const (
	PolicySeverityLow      PolicySeverity = "low"
	PolicySeverityMedium   PolicySeverity = "medium"
	PolicySeverityHigh     PolicySeverity = "high"
	PolicySeverityCritical PolicySeverity = "critical"
)

// Security scan results

// SecurityScanResult represents container security scan results
type SecurityScanResult struct {
	ContainerID       string             `json:"container_id"`
	Image             string             `json:"image"`
	ScanTime          time.Time          `json:"scan_time"`
	Scanner           string             `json:"scanner"`
	Vulnerabilities   []Vulnerability    `json:"vulnerabilities,omitempty"`
	Misconfigurations []Misconfiguration `json:"misconfigurations,omitempty"`
	Secrets           []Secret           `json:"secrets,omitempty"`
	Score             *SecurityScore     `json:"score,omitempty"`
}

// Vulnerability represents a security vulnerability
type Vulnerability struct {
	ID           string                `json:"id"`
	Title        string                `json:"title"`
	Description  string                `json:"description"`
	Severity     VulnerabilitySeverity `json:"severity"`
	Package      string                `json:"package,omitempty"`
	Version      string                `json:"version,omitempty"`
	FixedVersion string                `json:"fixed_version,omitempty"`
	References   []string              `json:"references,omitempty"`
	CVSS         *CVSSScore            `json:"cvss,omitempty"`
}

// VulnerabilitySeverity represents vulnerability severity levels
type VulnerabilitySeverity string

const (
	VulnerabilitySeverityUnknown  VulnerabilitySeverity = "unknown"
	VulnerabilitySeverityLow      VulnerabilitySeverity = "low"
	VulnerabilitySeverityMedium   VulnerabilitySeverity = "medium"
	VulnerabilitySeverityHigh     VulnerabilitySeverity = "high"
	VulnerabilitySeverityCritical VulnerabilitySeverity = "critical"
)

// CVSSScore represents Common Vulnerability Scoring System scores
type CVSSScore struct {
	Version string  `json:"version"`
	Vector  string  `json:"vector"`
	Score   float64 `json:"score"`
}

// Misconfiguration represents a security misconfiguration
type Misconfiguration struct {
	ID          string         `json:"id"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Severity    PolicySeverity `json:"severity"`
	Resolution  string         `json:"resolution,omitempty"`
	References  []string       `json:"references,omitempty"`
}

// Secret represents a detected secret
type Secret struct {
	Type      string         `json:"type"`
	Title     string         `json:"title"`
	Severity  PolicySeverity `json:"severity"`
	StartLine int            `json:"start_line,omitempty"`
	EndLine   int            `json:"end_line,omitempty"`
	Code      string         `json:"code,omitempty"`
	Match     string         `json:"match,omitempty"`
}

// SecurityScore represents overall security score
type SecurityScore struct {
	Overall           float64 `json:"overall"`
	Vulnerabilities   float64 `json:"vulnerabilities"`
	Misconfigurations float64 `json:"misconfigurations"`
	Secrets           float64 `json:"secrets"`
	MaxScore          float64 `json:"max_score"`
}

// Audit and logging types

// ContainerAuditEvent represents an audit event for container operations
type ContainerAuditEvent struct {
	ID         string            `json:"id"`
	Timestamp  time.Time         `json:"timestamp"`
	User       string            `json:"user"`
	Action     string            `json:"action"`
	Resource   string            `json:"resource"`
	ResourceID string            `json:"resource_id,omitempty"`
	Details    map[string]string `json:"details,omitempty"`
	Result     string            `json:"result"` // success, failure, partial
	Error      string            `json:"error,omitempty"`
	Duration   time.Duration     `json:"duration,omitempty"`
	SourceIP   string            `json:"source_ip,omitempty"`
	UserAgent  string            `json:"user_agent,omitempty"`
}
