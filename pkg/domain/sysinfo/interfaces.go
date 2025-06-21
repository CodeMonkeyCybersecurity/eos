// Package sysinfo defines domain interfaces for system information and platform detection
package sysinfo

import (
	"context"
)

// SystemInfoService provides comprehensive system information operations
type SystemInfoService interface {
	// Platform Detection
	GetPlatformInfo(ctx context.Context) (*PlatformInfo, error)
	GetOSInfo(ctx context.Context) (*OSInfo, error)
	GetArchitecture(ctx context.Context) (*ArchitectureInfo, error)

	// Hardware Information
	GetHardwareInfo(ctx context.Context) (*HardwareInfo, error)
	GetMemoryInfo(ctx context.Context) (*MemoryInfo, error)
	GetCPUInfo(ctx context.Context) (*CPUInfo, error)
	GetDiskInfo(ctx context.Context) (*DiskInfo, error)

	// Network Information
	GetNetworkInfo(ctx context.Context) (*NetworkInfo, error)
	GetNetworkInterfaces(ctx context.Context) ([]*NetworkInterface, error)

	// System Capabilities
	CheckCapabilities(ctx context.Context) (*SystemCapabilities, error)
	SupportsContainerization(ctx context.Context) (bool, error)
	SupportsVirtualization(ctx context.Context) (bool, error)

	// Environment Information
	GetEnvironmentInfo(ctx context.Context) (*EnvironmentInfo, error)
	GetUserInfo(ctx context.Context) (*UserInfo, error)
	GetPathInfo(ctx context.Context) (*PathInfo, error)
}

// PlatformDetector provides platform-specific detection capabilities
type PlatformDetector interface {
	// OS Detection
	DetectOS(ctx context.Context) (OSType, error)
	DetectDistribution(ctx context.Context) (*DistributionInfo, error)
	IsLinux(ctx context.Context) (bool, error)
	IsMacOS(ctx context.Context) (bool, error)
	IsWindows(ctx context.Context) (bool, error)

	// Distribution-specific
	IsDebian(ctx context.Context) (bool, error)
	IsRedHat(ctx context.Context) (bool, error)
	IsUbuntu(ctx context.Context) (bool, error)
	IsCentOS(ctx context.Context) (bool, error)
}

// HardwareDetector provides hardware information detection
type HardwareDetector interface {
	// CPU Information
	GetCPUCount(ctx context.Context) (int, error)
	GetCPUModel(ctx context.Context) (string, error)
	GetCPUFeatures(ctx context.Context) ([]string, error)

	// Memory Information
	GetTotalMemory(ctx context.Context) (uint64, error)
	GetAvailableMemory(ctx context.Context) (uint64, error)
	GetMemoryUsage(ctx context.Context) (*MemoryUsage, error)

	// Storage Information
	GetDiskUsage(ctx context.Context, path string) (*DiskUsage, error)
	GetMountPoints(ctx context.Context) ([]*MountPoint, error)
	GetFileSystemInfo(ctx context.Context) ([]*FileSystemInfo, error)
}

// ServiceDetector provides system service detection capabilities
type ServiceDetector interface {
	// Service Management
	IsServiceRunning(ctx context.Context, serviceName string) (bool, error)
	IsServiceEnabled(ctx context.Context, serviceName string) (bool, error)
	GetServiceStatus(ctx context.Context, serviceName string) (*ServiceStatus, error)

	// Process Information
	IsProcessRunning(ctx context.Context, processName string) (bool, error)
	GetProcessInfo(ctx context.Context, processName string) (*ProcessInfo, error)
	GetRunningProcesses(ctx context.Context) ([]*ProcessInfo, error)

	// Port Information
	IsPortOpen(ctx context.Context, port int) (bool, error)
	GetListeningPorts(ctx context.Context) ([]*PortInfo, error)
	CheckPortConnectivity(ctx context.Context, host string, port int) (bool, error)
}

// SecurityDetector provides security-related system information
type SecurityDetector interface {
	// Security Features
	HasSecureBoot(ctx context.Context) (bool, error)
	HasTPM(ctx context.Context) (bool, error)
	GetSELinuxStatus(ctx context.Context) (*SELinuxInfo, error)
	GetAppArmorStatus(ctx context.Context) (*AppArmorInfo, error)

	// User and Permissions
	IsRunningAsRoot(ctx context.Context) (bool, error)
	HasSudoAccess(ctx context.Context) (bool, error)
	GetCurrentUser(ctx context.Context) (*UserInfo, error)
	GetUserGroups(ctx context.Context, username string) ([]string, error)

	// System Hardening
	CheckSystemHardening(ctx context.Context) (*HardeningStatus, error)
	GetFirewallStatus(ctx context.Context) (*FirewallInfo, error)
	CheckPasswordPolicy(ctx context.Context) (*PasswordPolicyInfo, error)
}

// PackageDetector provides package management information
type PackageDetector interface {
	// Package Managers
	GetPackageManager(ctx context.Context) (PackageManagerType, error)
	IsPackageInstalled(ctx context.Context, packageName string) (bool, error)
	GetInstalledPackages(ctx context.Context) ([]*PackageInfo, error)
	GetPackageInfo(ctx context.Context, packageName string) (*PackageInfo, error)

	// Repository Information
	GetEnabledRepositories(ctx context.Context) ([]*RepositoryInfo, error)
	IsRepositoryEnabled(ctx context.Context, repoName string) (bool, error)

	// Update Information
	CheckForUpdates(ctx context.Context) ([]*UpdateInfo, error)
	GetLastUpdateTime(ctx context.Context) (*LastUpdateInfo, error)
}

// ContainerDetector provides container and virtualization detection
type ContainerDetector interface {
	// Container Runtime
	HasDocker(ctx context.Context) (bool, error)
	HasPodman(ctx context.Context) (bool, error)
	HasContainerd(ctx context.Context) (bool, error)
	GetContainerRuntime(ctx context.Context) (*ContainerRuntimeInfo, error)

	// Kubernetes
	HasKubernetes(ctx context.Context) (bool, error)
	HasK3s(ctx context.Context) (bool, error)
	GetKubernetesInfo(ctx context.Context) (*KubernetesInfo, error)

	// Running in Container
	IsRunningInContainer(ctx context.Context) (bool, error)
	IsRunningInKubernetes(ctx context.Context) (bool, error)
	GetContainerInfo(ctx context.Context) (*ContainerInfo, error)
}

// CapabilityChecker provides system capability checking
type CapabilityChecker interface {
	// Virtualization Support
	SupportsKVM(ctx context.Context) (bool, error)
	SupportsVMware(ctx context.Context) (bool, error)
	SupportsHyperV(ctx context.Context) (bool, error)

	// Container Support
	SupportsDocker(ctx context.Context) (bool, error)
	SupportsPodman(ctx context.Context) (bool, error)
	SupportsOCI(ctx context.Context) (bool, error)

	// Security Features
	SupportsSeccomp(ctx context.Context) (bool, error)
	SupportsNamespaces(ctx context.Context) (bool, error)
	SupportsCgroups(ctx context.Context) (bool, error)

	// Network Features
	SupportsIPv6(ctx context.Context) (bool, error)
	SupportsNetfilter(ctx context.Context) (bool, error)
	SupportsBridge(ctx context.Context) (bool, error)
}
