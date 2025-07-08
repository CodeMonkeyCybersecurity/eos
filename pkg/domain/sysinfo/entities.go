// Package sysinfo defines domain entities for system information
package sysinfo

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Platform Information Entities

// PlatformInfo represents comprehensive platform information
type PlatformInfo struct {
	OS           OSType        `json:"os"`
	Architecture string        `json:"architecture"`
	Hostname     string        `json:"hostname"`
	Uptime       time.Duration `json:"uptime"`
	BootTime     time.Time     `json:"boot_time"`
	Timezone     string        `json:"timezone"`
	Locale       string        `json:"locale"`
	KernelInfo   *KernelInfo   `json:"kernel_info,omitempty"`
}

// OSInfo represents operating system information
type OSInfo struct {
	Type         OSType            `json:"type"`
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	Build        string            `json:"build,omitempty"`
	CodeName     string            `json:"codename,omitempty"`
	Distribution *DistributionInfo `json:"distribution,omitempty"`
	Kernel       *KernelInfo       `json:"kernel,omitempty"`
}

// ArchitectureInfo represents system architecture information
type ArchitectureInfo struct {
	CPU          string   `json:"cpu"`
	Platform     string   `json:"platform"`
	Bits         int      `json:"bits"`
	Endianness   string   `json:"endianness"`
	Capabilities []string `json:"capabilities,omitempty"`
}

// KernelInfo represents kernel information
type KernelInfo struct {
	Name       string    `json:"name"`
	Version    string    `json:"version"`
	Release    string    `json:"release"`
	BuildDate  time.Time `json:"build_date,omitempty"`
	Compiler   string    `json:"compiler,omitempty"`
	Parameters []string  `json:"parameters,omitempty"`
}

// DistributionInfo represents Linux distribution information
type DistributionInfo struct {
	ID               string             `json:"id"`
	Name             string             `json:"name"`
	Version          string             `json:"version"`
	VersionID        string             `json:"version_id"`
	VersionCodename  string             `json:"version_codename,omitempty"`
	PrettyName       string             `json:"pretty_name"`
	HomeURL          string             `json:"home_url,omitempty"`
	SupportURL       string             `json:"support_url,omitempty"`
	BugReportURL     string             `json:"bug_report_url,omitempty"`
	PrivacyPolicyURL string             `json:"privacy_policy_url,omitempty"`
	Family           DistroFamily       `json:"family"`
	PackageManager   PackageManagerType `json:"package_manager"`
	ServiceManager   ServiceManagerType `json:"service_manager"`
}

// Hardware Information Entities

// HardwareInfo represents comprehensive hardware information
type HardwareInfo struct {
	CPU     *CPUInfo     `json:"cpu,omitempty"`
	Memory  *MemoryInfo  `json:"memory,omitempty"`
	Disk    *DiskInfo    `json:"disk,omitempty"`
	Network *NetworkInfo `json:"network,omitempty"`
	System  *SystemInfo  `json:"system,omitempty"`
}

// CPUInfo represents CPU information
type CPUInfo struct {
	Model            string    `json:"model"`
	Vendor           string    `json:"vendor"`
	Family           string    `json:"family,omitempty"`
	Cores            int       `json:"cores"`
	Threads          int       `json:"threads"`
	MaxFrequency     uint64    `json:"max_frequency_mhz"`
	MinFrequency     uint64    `json:"min_frequency_mhz,omitempty"`
	CurrentFrequency uint64    `json:"current_frequency_mhz,omitempty"`
	CacheSize        uint64    `json:"cache_size_bytes,omitempty"`
	Features         []string  `json:"features,omitempty"`
	Usage            *CPUUsage `json:"usage,omitempty"`
}

// CPUUsage represents CPU usage information
type CPUUsage struct {
	User      float64   `json:"user_percent"`
	System    float64   `json:"system_percent"`
	Idle      float64   `json:"idle_percent"`
	IOWait    float64   `json:"iowait_percent,omitempty"`
	Nice      float64   `json:"nice_percent,omitempty"`
	Steal     float64   `json:"steal_percent,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// MemoryInfo represents memory information
type MemoryInfo struct {
	Total     uint64       `json:"total_bytes"`
	Available uint64       `json:"available_bytes"`
	Used      uint64       `json:"used_bytes"`
	Free      uint64       `json:"free_bytes"`
	Cached    uint64       `json:"cached_bytes,omitempty"`
	Buffers   uint64       `json:"buffers_bytes,omitempty"`
	SwapTotal uint64       `json:"swap_total_bytes,omitempty"`
	SwapUsed  uint64       `json:"swap_used_bytes,omitempty"`
	SwapFree  uint64       `json:"swap_free_bytes,omitempty"`
	Usage     *MemoryUsage `json:"usage,omitempty"`
}

// MemoryUsage represents memory usage statistics
type MemoryUsage struct {
	UsedPercent      float64   `json:"used_percent"`
	AvailablePercent float64   `json:"available_percent"`
	SwapUsedPercent  float64   `json:"swap_used_percent,omitempty"`
	Timestamp        time.Time `json:"timestamp"`
}

// DiskInfo represents disk information
type DiskInfo struct {
	Total       uint64            `json:"total_bytes"`
	Used        uint64            `json:"used_bytes"`
	Available   uint64            `json:"available_bytes"`
	MountPoints []*MountPoint     `json:"mount_points,omitempty"`
	Filesystems []*FileSystemInfo `json:"filesystems,omitempty"`
	Devices     []*DiskDevice     `json:"devices,omitempty"`
}

// MountPoint represents a filesystem mount point
type MountPoint struct {
	Device     string     `json:"device"`
	MountPoint string     `json:"mount_point"`
	Filesystem string     `json:"filesystem"`
	Options    []string   `json:"options,omitempty"`
	Usage      *DiskUsage `json:"usage,omitempty"`
}

// DiskUsage represents disk usage for a specific path
type DiskUsage struct {
	Total       uint64    `json:"total_bytes"`
	Used        uint64    `json:"used_bytes"`
	Available   uint64    `json:"available_bytes"`
	UsedPercent float64   `json:"used_percent"`
	InodesTotal uint64    `json:"inodes_total,omitempty"`
	InodesUsed  uint64    `json:"inodes_used,omitempty"`
	InodesFree  uint64    `json:"inodes_free,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
}

// FileSystemInfo represents filesystem information
type FileSystemInfo struct {
	Type       string   `json:"type"`
	Device     string   `json:"device"`
	MountPoint string   `json:"mount_point"`
	Size       uint64   `json:"size_bytes"`
	Features   []string `json:"features,omitempty"`
	ReadOnly   bool     `json:"read_only"`
}

// DiskDevice represents a physical or logical disk device
type DiskDevice struct {
	Name      string `json:"name"`
	Model     string `json:"model,omitempty"`
	Size      uint64 `json:"size_bytes"`
	Type      string `json:"type"`
	Interface string `json:"interface,omitempty"`
	Serial    string `json:"serial,omitempty"`
	Removable bool   `json:"removable"`
}

// Network Information Entities

// NetworkInfo represents network information
type NetworkInfo struct {
	Hostname       string              `json:"hostname"`
	Interfaces     []*NetworkInterface `json:"interfaces,omitempty"`
	DefaultGateway string              `json:"default_gateway,omitempty"`
	DNSServers     []string            `json:"dns_servers,omitempty"`
	Routes         []*RouteInfo        `json:"routes,omitempty"`
}

// NetworkInterface represents a network interface
type NetworkInterface struct {
	Name         string          `json:"name"`
	DisplayName  string          `json:"display_name,omitempty"`
	Type         string          `json:"type"`
	HardwareAddr string          `json:"hardware_addr,omitempty"`
	MTU          int             `json:"mtu"`
	Flags        []string        `json:"flags,omitempty"`
	Addresses    []*AddressInfo  `json:"addresses,omitempty"`
	Statistics   *InterfaceStats `json:"statistics,omitempty"`
	Status       InterfaceStatus `json:"status"`
}

// AddressInfo represents network address information
type AddressInfo struct {
	Address   string        `json:"address"`
	Network   string        `json:"network,omitempty"`
	Netmask   string        `json:"netmask,omitempty"`
	Broadcast string        `json:"broadcast,omitempty"`
	Scope     string        `json:"scope,omitempty"`
	Family    AddressFamily `json:"family"`
}

// InterfaceStats represents network interface statistics
type InterfaceStats struct {
	BytesReceived   uint64    `json:"bytes_received"`
	BytesSent       uint64    `json:"bytes_sent"`
	PacketsReceived uint64    `json:"packets_received"`
	PacketsSent     uint64    `json:"packets_sent"`
	ErrorsReceived  uint64    `json:"errors_received"`
	ErrorsSent      uint64    `json:"errors_sent"`
	DroppedReceived uint64    `json:"dropped_received"`
	DroppedSent     uint64    `json:"dropped_sent"`
	Timestamp       time.Time `json:"timestamp"`
}

// RouteInfo represents routing table information
type RouteInfo struct {
	Destination string `json:"destination"`
	Gateway     string `json:"gateway"`
	Interface   string `json:"interface"`
	Metric      int    `json:"metric,omitempty"`
	Type        string `json:"type,omitempty"`
}

// System Service Entities

// ServiceStatus represents system service status
type ServiceStatus struct {
	Name        string       `json:"name"`
	DisplayName string       `json:"display_name,omitempty"`
	State       ServiceState `json:"state"`
	SubState    string       `json:"sub_state,omitempty"`
	LoadState   string       `json:"load_state,omitempty"`
	ActiveState string       `json:"active_state,omitempty"`
	Enabled     bool         `json:"enabled"`
	Running     bool         `json:"running"`
	PID         int          `json:"pid,omitempty"`
	ExecStart   string       `json:"exec_start,omitempty"`
	ExecReload  string       `json:"exec_reload,omitempty"`
	ExecStop    string       `json:"exec_stop,omitempty"`
	Restart     string       `json:"restart,omitempty"`
	StartTime   *time.Time   `json:"start_time,omitempty"`
	Memory      uint64       `json:"memory_bytes,omitempty"`
	CPUUsage    float64      `json:"cpu_usage_percent,omitempty"`
}

// ProcessInfo represents process information
type ProcessInfo struct {
	PID         int       `json:"pid"`
	PPID        int       `json:"ppid,omitempty"`
	Name        string    `json:"name"`
	Command     string    `json:"command,omitempty"`
	Arguments   []string  `json:"arguments,omitempty"`
	User        string    `json:"user,omitempty"`
	Group       string    `json:"group,omitempty"`
	State       string    `json:"state"`
	StartTime   time.Time `json:"start_time"`
	CPUPercent  float64   `json:"cpu_percent,omitempty"`
	Memory      uint64    `json:"memory_bytes,omitempty"`
	OpenFiles   int       `json:"open_files,omitempty"`
	Connections int       `json:"connections,omitempty"`
}

// PortInfo represents network port information
type PortInfo struct {
	Port     int          `json:"port"`
	Protocol string       `json:"protocol"`
	Address  string       `json:"address"`
	State    string       `json:"state"`
	Process  *ProcessInfo `json:"process,omitempty"`
	Service  string       `json:"service,omitempty"`
}

// Security Entities

// SystemCapabilities represents system capabilities
type SystemCapabilities struct {
	Virtualization   *VirtualizationCapabilities `json:"virtualization,omitempty"`
	Containerization *ContainerCapabilities      `json:"containerization,omitempty"`
	Security         *SecurityCapabilities       `json:"security,omitempty"`
	Network          *NetworkCapabilities        `json:"network,omitempty"`
	Hardware         *HardwareCapabilities       `json:"hardware,omitempty"`
}

// VirtualizationCapabilities represents virtualization support
type VirtualizationCapabilities struct {
	KVM           bool `json:"kvm"`
	VMware        bool `json:"vmware"`
	HyperV        bool `json:"hyperv"`
	Xen           bool `json:"xen"`
	QEMU          bool `json:"qemu"`
	VBoxSupported bool `json:"virtualbox"`
}

// ContainerCapabilities represents container support
type ContainerCapabilities struct {
	Docker     bool `json:"docker"`
	Podman     bool `json:"podman"`
	Containerd bool `json:"containerd"`
	CRI        bool `json:"cri"`
	OCI        bool `json:"oci"`
	Runc       bool `json:"runc"`
	Kubernetes bool `json:"kubernetes"`
	K3s        bool `json:"k3s"`
}

// SecurityCapabilities represents security features
type SecurityCapabilities struct {
	SecureBoot bool `json:"secure_boot"`
	TPM        bool `json:"tpm"`
	SELinux    bool `json:"selinux"`
	AppArmor   bool `json:"apparmor"`
	Seccomp    bool `json:"seccomp"`
	Namespaces bool `json:"namespaces"`
	Cgroups    bool `json:"cgroups"`
	ASLR       bool `json:"aslr"`
	NX         bool `json:"nx"`
}

// NetworkCapabilities represents network features
type NetworkCapabilities struct {
	IPv6      bool `json:"ipv6"`
	Netfilter bool `json:"netfilter"`
	Bridge    bool `json:"bridge"`
	VLAN      bool `json:"vlan"`
	TUN       bool `json:"tun"`
	Macvlan   bool `json:"macvlan"`
	IPTables  bool `json:"iptables"`
	NFTables  bool `json:"nftables"`
}

// HardwareCapabilities represents hardware features
type HardwareCapabilities struct {
	Virtualization bool `json:"virtualization"`
	AES            bool `json:"aes"`
	AVX            bool `json:"avx"`
	SSE            bool `json:"sse"`
	RDRAND         bool `json:"rdrand"`
	TSX            bool `json:"tsx"`
}

// User and Environment Entities

// UserInfo represents user information
type UserInfo struct {
	UID      int      `json:"uid"`
	GID      int      `json:"gid"`
	Username string   `json:"username"`
	Name     string   `json:"name,omitempty"`
	HomeDir  string   `json:"home_dir"`
	Shell    string   `json:"shell,omitempty"`
	Groups   []string `json:"groups,omitempty"`
	IsRoot   bool     `json:"is_root"`
	HasSudo  bool     `json:"has_sudo"`
}

// EnvironmentInfo represents environment information
type EnvironmentInfo struct {
	Variables  map[string]string `json:"variables,omitempty"`
	Path       []string          `json:"path,omitempty"`
	WorkingDir string            `json:"working_dir"`
	TempDir    string            `json:"temp_dir"`
	ConfigDirs []string          `json:"config_dirs,omitempty"`
	DataDirs   []string          `json:"data_dirs,omitempty"`
	CacheDirs  []string          `json:"cache_dirs,omitempty"`
}

// PathInfo represents path information
type PathInfo struct {
	Executable  string   `json:"executable"`
	ConfigPaths []string `json:"config_paths,omitempty"`
	DataPaths   []string `json:"data_paths,omitempty"`
	LogPaths    []string `json:"log_paths,omitempty"`
	TempPaths   []string `json:"temp_paths,omitempty"`
	BinaryPaths []string `json:"binary_paths,omitempty"`
}

// Package Management Entities

// PackageInfo represents package information
type PackageInfo struct {
	Name         string        `json:"name"`
	Version      string        `json:"version"`
	Architecture string        `json:"architecture,omitempty"`
	Description  string        `json:"description,omitempty"`
	Size         uint64        `json:"size_bytes,omitempty"`
	InstallDate  *time.Time    `json:"install_date,omitempty"`
	Repository   string        `json:"repository,omitempty"`
	Dependencies []string      `json:"dependencies,omitempty"`
	Status       PackageStatus `json:"status"`
}

// RepositoryInfo represents package repository information
type RepositoryInfo struct {
	Name        string `json:"name"`
	URL         string `json:"url"`
	Enabled     bool   `json:"enabled"`
	GPGCheck    bool   `json:"gpg_check"`
	Description string `json:"description,omitempty"`
	Type        string `json:"type,omitempty"`
}

// UpdateInfo represents available update information
type UpdateInfo struct {
	PackageName    string `json:"package_name"`
	CurrentVersion string `json:"current_version"`
	NewVersion     string `json:"new_version"`
	Size           uint64 `json:"size_bytes,omitempty"`
	Security       bool   `json:"security"`
	Repository     string `json:"repository,omitempty"`
}

// LastUpdateInfo represents last update information
type LastUpdateInfo struct {
	LastCheck   *time.Time `json:"last_check,omitempty"`
	LastUpdate  *time.Time `json:"last_update,omitempty"`
	UpdateCount int        `json:"update_count"`
	Tool        string     `json:"tool,omitempty"`
}

// Container and Virtualization Entities

// ContainerRuntimeInfo represents container runtime information
type ContainerRuntimeInfo struct {
	Type       ContainerRuntime `json:"type"`
	Version    string           `json:"version"`
	APIVersion string           `json:"api_version,omitempty"`
	Available  bool             `json:"available"`
	Running    bool             `json:"running"`
	Socket     string           `json:"socket,omitempty"`
	ConfigPath string           `json:"config_path,omitempty"`
}

// KubernetesInfo represents Kubernetes information
type KubernetesInfo struct {
	Available      bool   `json:"available"`
	Type           string `json:"type"` // k8s, k3s, etc.
	Version        string `json:"version,omitempty"`
	ClientVersion  string `json:"client_version,omitempty"`
	ServerVersion  string `json:"server_version,omitempty"`
	ConfigPath     string `json:"config_path,omitempty"`
	CurrentContext string `json:"current_context,omitempty"`
	Namespace      string `json:"namespace,omitempty"`
}

// ContainerInfo represents container environment information
type ContainerInfo struct {
	InContainer  bool   `json:"in_container"`
	InKubernetes bool   `json:"in_kubernetes"`
	Runtime      string `json:"runtime,omitempty"`
	ContainerID  string `json:"container_id,omitempty"`
	ImageName    string `json:"image_name,omitempty"`
	PodName      string `json:"pod_name,omitempty"`
	Namespace    string `json:"namespace,omitempty"`
}

// Security Information Entities

// SELinuxInfo represents SELinux information
type SELinuxInfo struct {
	Enabled    bool   `json:"enabled"`
	Status     string `json:"status"`
	Mode       string `json:"mode"`
	ConfigMode string `json:"config_mode,omitempty"`
	PolicyType string `json:"policy_type,omitempty"`
	Version    string `json:"version,omitempty"`
}

// AppArmorInfo represents AppArmor information
type AppArmorInfo struct {
	Enabled    bool     `json:"enabled"`
	Status     string   `json:"status"`
	Profiles   []string `json:"profiles,omitempty"`
	Complain   []string `json:"complain,omitempty"`
	Enforce    []string `json:"enforce,omitempty"`
	Unconfined []string `json:"unconfined,omitempty"`
}

// HardeningStatus represents system hardening status
type HardeningStatus struct {
	Score           int                           `json:"score"`
	MaxScore        int                           `json:"max_score"`
	Recommendations []string                      `json:"recommendations,omitempty"`
	Categories      map[string]*HardeningCategory `json:"categories,omitempty"`
}

// HardeningCategory represents a category of hardening checks
type HardeningCategory struct {
	Name     string            `json:"name"`
	Score    int               `json:"score"`
	MaxScore int               `json:"max_score"`
	Checks   []*HardeningCheck `json:"checks,omitempty"`
}

// HardeningCheck represents an individual hardening check
type HardeningCheck struct {
	Name           string `json:"name"`
	Description    string `json:"description"`
	Passed         bool   `json:"passed"`
	Severity       string `json:"severity"`
	Recommendation string `json:"recommendation,omitempty"`
}

// FirewallInfo represents firewall information
type FirewallInfo struct {
	Type    string          `json:"type"` // iptables, ufw, firewalld, etc.
	Enabled bool            `json:"enabled"`
	Status  string          `json:"status"`
	Default string          `json:"default,omitempty"`
	Rules   []*FirewallRule `json:"rules,omitempty"`
	Zones   []*FirewallZone `json:"zones,omitempty"`
}

// FirewallRule represents a firewall rule
type FirewallRule struct {
	Number      int    `json:"number,omitempty"`
	Action      string `json:"action"`
	Direction   string `json:"direction,omitempty"`
	Protocol    string `json:"protocol,omitempty"`
	Source      string `json:"source,omitempty"`
	Destination string `json:"destination,omitempty"`
	Port        string `json:"port,omitempty"`
	Interface   string `json:"interface,omitempty"`
}

// FirewallZone represents a firewall zone
type FirewallZone struct {
	Name       string   `json:"name"`
	Target     string   `json:"target"`
	Interfaces []string `json:"interfaces,omitempty"`
	Sources    []string `json:"sources,omitempty"`
	Services   []string `json:"services,omitempty"`
	Ports      []string `json:"ports,omitempty"`
}

// PasswordPolicyInfo represents password policy information
type PasswordPolicyInfo struct {
	MinLength       int  `json:"min_length"`
	MaxLength       int  `json:"max_length,omitempty"`
	RequireUpper    bool `json:"require_upper"`
	RequireLower    bool `json:"require_lower"`
	RequireDigits   bool `json:"require_digits"`
	RequireSpecial  bool `json:"require_special"`
	MaxAge          int  `json:"max_age_days,omitempty"`
	MinAge          int  `json:"min_age_days,omitempty"`
	WarnAge         int  `json:"warn_age_days,omitempty"`
	HistorySize     int  `json:"history_size,omitempty"`
	LockoutAttempts int  `json:"lockout_attempts,omitempty"`
	LockoutTime     int  `json:"lockout_time_minutes,omitempty"`
}

// System Information Entity

// SystemInfo represents system-level information
type SystemInfo struct {
	Manufacturer string `json:"manufacturer,omitempty"`
	Model        string `json:"model,omitempty"`
	SerialNumber string `json:"serial_number,omitempty"`
	UUID         string `json:"uuid,omitempty"`
	BIOSVendor   string `json:"bios_vendor,omitempty"`
	BIOSVersion  string `json:"bios_version,omitempty"`
	BIOSDate     string `json:"bios_date,omitempty"`
	Chassis      string `json:"chassis,omitempty"`
}

// Enum Types

type OSType string

const (
	OSTypeLinux   OSType = "linux"
	OSTypeMacOS   OSType = "macos"
	OSTypeWindows OSType = "windows"
	OSTypeUnknown OSType = "unknown"
)

type DistroFamily string

const (
	DistroFamilyDebian  DistroFamily = "debian"
	DistroFamilyRedHat  DistroFamily = "redhat"
	DistroFamilyArch    DistroFamily = "arch"
	DistroFamilySUSE    DistroFamily = "suse"
	DistroFamilyGentoo  DistroFamily = "gentoo"
	DistroFamilyAlpine  DistroFamily = "alpine"
	DistroFamilyUnknown DistroFamily = "unknown"
)

type PackageManagerType string

const (
	PackageManagerAPT     PackageManagerType = "apt"
	PackageManagerYUM     PackageManagerType = "yum"
	PackageManagerDNF     PackageManagerType = "dnf"
	PackageManagerZypper  PackageManagerType = "zypper"
	PackageManagerPacman  PackageManagerType = "pacman"
	PackageManagerPortage PackageManagerType = "portage"
	PackageManagerAPK     PackageManagerType = "apk"
	PackageManagerBrew    PackageManagerType = "brew"
	PackageManagerUnknown PackageManagerType = "unknown"
)

type ServiceManagerType string

const (
	ServiceManagerSystemd ServiceManagerType = "systemd"
	ServiceManagerSysV    ServiceManagerType = "sysv"
	ServiceManagerUpstart ServiceManagerType = "upstart"
	ServiceManagerOpenRC  ServiceManagerType = "openrc"
	ServiceManagerLaunchd ServiceManagerType = "launchd"
	ServiceManagerUnknown ServiceManagerType = "unknown"
)

type ServiceState string

const (
	ServiceStateRunning ServiceState = "running"
	ServiceStateStopped ServiceState = "stopped"
	ServiceStateFailed  ServiceState = "failed"
	ServiceStateUnknown ServiceState = "unknown"
)

type InterfaceStatus string

const (
	InterfaceStatusUp      InterfaceStatus = "up"
	InterfaceStatusDown    InterfaceStatus = "down"
	InterfaceStatusUnknown InterfaceStatus = "unknown"
)

type AddressFamily string

const (
	AddressFamilyIPv4 AddressFamily = "ipv4"
	AddressFamilyIPv6 AddressFamily = "ipv6"
)

type PackageStatus string

const (
	PackageStatusInstalled    PackageStatus = "installed"
	PackageStatusNotInstalled PackageStatus = "not_installed"
	PackageStatusUpgradeable  PackageStatus = "upgradeable"
	PackageStatusBroken       PackageStatus = "broken"
)

type ContainerRuntime string

const (
	ContainerRuntimeDocker     ContainerRuntime = "docker"
	ContainerRuntimePodman     ContainerRuntime = "podman"
	ContainerRuntimeContainerd ContainerRuntime = "containerd"
	ContainerRuntimeCRIO       ContainerRuntime = "crio"
	ContainerRuntimeUnknown    ContainerRuntime = "unknown"
)

// UpdateHostname updates the system hostname
func UpdateHostname(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" Starting hostname update",
		zap.String("user", os.Getenv("USER")),
		zap.String("function", "UpdateHostname"))

	// Get the current hostname
	currentHostname, err := os.Hostname()
	if err != nil {
		logger.Error(" Failed to retrieve current hostname",
			zap.Error(err),
			zap.String("troubleshooting", "Check system configuration"))
		return err
	}
	logger.Info(" Current hostname retrieved",
		zap.String("hostname", currentHostname))

	// Ask for confirmation to proceed using default No
	if !interaction.PromptYesNo(rc.Ctx, "Do you want to change the hostname?", false) {
		logger.Info(" Hostname change aborted by user")
		return nil
	}

	// Ask for the new hostname
	newHostname := interaction.PromptInput(rc.Ctx, "Enter the new hostname", "")
	newHostname = strings.TrimSpace(newHostname)

	// Check if the input is not empty
	if newHostname == "" {
		logger.Error(" Empty hostname provided",
			zap.String("troubleshooting", "Hostname cannot be empty"))
		return nil
	}

	logger.Info(" Changing hostname",
		zap.String("old_hostname", currentHostname),
		zap.String("new_hostname", newHostname))

	// Change the hostname temporarily
	logger.Info(" Executing command",
		zap.String("command", "hostname"),
		zap.Strings("args", []string{newHostname}))
	err = exec.Command("hostname", newHostname).Run()
	if err != nil {
		logger.Error(" Failed to change hostname temporarily",
			zap.Error(err),
			zap.String("command", "hostname"),
			zap.String("new_hostname", newHostname),
			zap.String("troubleshooting", "Check permissions and system state"))
		return err
	}
	logger.Info(" Temporary hostname change completed")

	// Change the hostname permanently
	logger.Info(" Writing new hostname to /etc/hostname",
		zap.String("file_path", "/etc/hostname"),
		zap.String("new_hostname", newHostname))
	err = os.WriteFile("/etc/hostname", []byte(newHostname+"\n"), 0644)
	if err != nil {
		logger.Error(" Failed to write /etc/hostname",
			zap.Error(err),
			zap.String("file_path", "/etc/hostname"),
			zap.String("troubleshooting", "Check permissions for /etc/hostname"))
		return err
	}
	logger.Info(" Permanent hostname file updated")

	// Update the /etc/hosts file
	logger.Info(" Executing command",
		zap.String("command", "sed"),
		zap.Strings("args", []string{"-i", "s/" + currentHostname + "/" + newHostname + "/g", "/etc/hosts"}))
	err = exec.Command("sed", "-i", "s/"+currentHostname+"/"+newHostname+"/g", "/etc/hosts").Run()
	if err != nil {
		logger.Error(" Failed to update /etc/hosts",
			zap.Error(err),
			zap.String("file_path", "/etc/hosts"),
			zap.String("old_hostname", currentHostname),
			zap.String("new_hostname", newHostname),
			zap.String("troubleshooting", "Check permissions for /etc/hosts"))
		return err
	}
	logger.Info(" /etc/hosts file updated")

	logger.Info(" Hostname change complete",
		zap.String("old_hostname", currentHostname),
		zap.String("new_hostname", newHostname))
	return nil
}

// detectHostTimeZone attempts to detect the host system's timezone
func DetectHostTimeZone(rc *eos_io.RuntimeContext) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Method 1: Try to read /etc/timezone (Debian/Ubuntu)
	if timezone, err := os.ReadFile("/etc/timezone"); err == nil {
		tz := strings.TrimSpace(string(timezone))
		if tz != "" {
			logger.Debug(" Detected timezone from /etc/timezone", zap.String("timezone", tz))
			return tz, nil
		}
	}

	// Method 2: Try to resolve /etc/localtime symlink (most Linux distributions)
	if link, err := os.Readlink("/etc/localtime"); err == nil {
		// Extract timezone from path like /usr/share/zoneinfo/America/New_York
		if strings.Contains(link, "zoneinfo/") {
			parts := strings.Split(link, "zoneinfo/")
			if len(parts) == 2 {
				tz := parts[1]
				logger.Debug(" Detected timezone from /etc/localtime symlink", zap.String("timezone", tz))
				return tz, nil
			}
		}
	}

	// Method 3: Try timedatectl command (systemd systems)
	if output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "timedatectl",
		Args:    []string{"show", "--property=Timezone", "--value"},
	}); err == nil {
		tz := strings.TrimSpace(output)
		if tz != "" && tz != "n/a" {
			logger.Debug(" Detected timezone from timedatectl", zap.String("timezone", tz))
			return tz, nil
		}
	}

	// Method 4: Try reading from /etc/localtime directly and comparing with zoneinfo
	if stat, err := os.Stat("/etc/localtime"); err == nil {
		// Walk through /usr/share/zoneinfo to find matching file
		zoneinfoPath := "/usr/share/zoneinfo"
		var foundZone string

		filepath.Walk(zoneinfoPath, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}

			// Skip special files
			if strings.Contains(path, "posix/") || strings.Contains(path, "right/") {
				return nil
			}

			if pathStat, err := os.Stat(path); err == nil {
				// Compare file size and modification time as a heuristic
				if pathStat.Size() == stat.Size() && pathStat.ModTime().Equal(stat.ModTime()) {
					// Extract timezone name from path
					if rel, err := filepath.Rel(zoneinfoPath, path); err == nil {
						foundZone = rel
						return filepath.SkipDir // Found it, stop walking
					}
				}
			}
			return nil
		})

		if foundZone != "" {
			logger.Debug(" Detected timezone by comparing /etc/localtime", zap.String("timezone", foundZone))
			return foundZone, nil
		}
	}

	// Method 5: Try environment variables
	if tz := os.Getenv("TZ"); tz != "" {
		logger.Debug(" Detected timezone from TZ environment variable", zap.String("timezone", tz))
		return tz, nil
	}

	logger.Debug(" Unable to detect host timezone using any method")
	return "", fmt.Errorf("unable to detect host timezone")
}
