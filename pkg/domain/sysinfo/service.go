// Package sysinfo implements domain services for system information
package sysinfo

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
)

// Service implements SystemInfoService and coordinates system information operations
type Service struct {
	platformDetector  PlatformDetector
	hardwareDetector  HardwareDetector
	serviceDetector   ServiceDetector
	securityDetector  SecurityDetector
	packageDetector   PackageDetector
	containerDetector ContainerDetector
	capabilityChecker CapabilityChecker
	logger            *zap.Logger
}

// NewService creates a new system information domain service
func NewService(
	platformDetector PlatformDetector,
	hardwareDetector HardwareDetector,
	serviceDetector ServiceDetector,
	securityDetector SecurityDetector,
	packageDetector PackageDetector,
	containerDetector ContainerDetector,
	capabilityChecker CapabilityChecker,
	logger *zap.Logger,
) *Service {
	return &Service{
		platformDetector:  platformDetector,
		hardwareDetector:  hardwareDetector,
		serviceDetector:   serviceDetector,
		securityDetector:  securityDetector,
		packageDetector:   packageDetector,
		containerDetector: containerDetector,
		capabilityChecker: capabilityChecker,
		logger:            logger.Named("sysinfo.service"),
	}
}

// GetPlatformInfo retrieves comprehensive platform information
func (s *Service) GetPlatformInfo(ctx context.Context) (*PlatformInfo, error) {
	s.logger.Debug("Getting platform information")

	osType, err := s.platformDetector.DetectOS(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to detect OS: %w", err)
	}

	archInfo, err := s.GetArchitecture(ctx)
	if err != nil {
		s.logger.Warn("Failed to get architecture info", zap.Error(err))
		archInfo = &ArchitectureInfo{CPU: "unknown", Platform: "unknown"}
	}

	// Get additional platform details
	_, _ = s.platformDetector.DetectDistribution(ctx)

	var kernelInfo *KernelInfo
	if osType == OSTypeLinux || osType == OSTypeMacOS {
		// Kernel info is primarily relevant for Unix-like systems
		kernelInfo = &KernelInfo{
			Name:    "linux", // This would be detected by infrastructure
			Version: "unknown",
		}
	}

	platformInfo := &PlatformInfo{
		OS:           osType,
		Architecture: archInfo.CPU,
		Hostname:     "localhost", // This would be detected by infrastructure
		Uptime:       0,           // This would be detected by infrastructure
		BootTime:     time.Now(),  // This would be detected by infrastructure
		Timezone:     "UTC",       // This would be detected by infrastructure
		KernelInfo:   kernelInfo,
	}

	s.logger.Debug("Platform information retrieved",
		zap.String("os", string(platformInfo.OS)),
		zap.String("architecture", platformInfo.Architecture))

	return platformInfo, nil
}

// GetOSInfo retrieves operating system information
func (s *Service) GetOSInfo(ctx context.Context) (*OSInfo, error) {
	s.logger.Debug("Getting OS information")

	osType, err := s.platformDetector.DetectOS(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to detect OS: %w", err)
	}

	distroInfo, err := s.platformDetector.DetectDistribution(ctx)
	if err != nil {
		s.logger.Debug("Failed to get distribution info", zap.Error(err))
	}

	osInfo := &OSInfo{
		Type:         osType,
		Name:         string(osType),
		Version:      "unknown", // This would be detected by infrastructure
		Distribution: distroInfo,
	}

	if distroInfo != nil {
		osInfo.Name = distroInfo.Name
		osInfo.Version = distroInfo.Version
		osInfo.CodeName = distroInfo.VersionCodename
	}

	s.logger.Debug("OS information retrieved",
		zap.String("type", string(osInfo.Type)),
		zap.String("name", osInfo.Name),
		zap.String("version", osInfo.Version))

	return osInfo, nil
}

// GetArchitecture retrieves architecture information
func (s *Service) GetArchitecture(ctx context.Context) (*ArchitectureInfo, error) {
	s.logger.Debug("Getting architecture information")

	// This would be implemented by infrastructure layer
	archInfo := &ArchitectureInfo{
		CPU:          "x86_64", // Default, would be detected
		Platform:     "x86_64",
		Bits:         64,
		Endianness:   "little",
		Capabilities: []string{}, // Would be detected from /proc/cpuinfo or similar
	}

	s.logger.Debug("Architecture information retrieved",
		zap.String("cpu", archInfo.CPU),
		zap.Int("bits", archInfo.Bits))

	return archInfo, nil
}

// GetHardwareInfo retrieves comprehensive hardware information
func (s *Service) GetHardwareInfo(ctx context.Context) (*HardwareInfo, error) {
	s.logger.Debug("Getting hardware information")

	var hardwareInfo HardwareInfo

	// Get CPU information
	if cpuInfo, err := s.GetCPUInfo(ctx); err != nil {
		s.logger.Warn("Failed to get CPU info", zap.Error(err))
	} else {
		hardwareInfo.CPU = cpuInfo
	}

	// Get memory information
	if memInfo, err := s.GetMemoryInfo(ctx); err != nil {
		s.logger.Warn("Failed to get memory info", zap.Error(err))
	} else {
		hardwareInfo.Memory = memInfo
	}

	// Get disk information
	if diskInfo, err := s.GetDiskInfo(ctx); err != nil {
		s.logger.Warn("Failed to get disk info", zap.Error(err))
	} else {
		hardwareInfo.Disk = diskInfo
	}

	// Get network information
	if netInfo, err := s.GetNetworkInfo(ctx); err != nil {
		s.logger.Warn("Failed to get network info", zap.Error(err))
	} else {
		hardwareInfo.Network = netInfo
	}

	s.logger.Debug("Hardware information retrieved")
	return &hardwareInfo, nil
}

// GetMemoryInfo retrieves memory information
func (s *Service) GetMemoryInfo(ctx context.Context) (*MemoryInfo, error) {
	s.logger.Debug("Getting memory information")

	if s.hardwareDetector == nil {
		return nil, fmt.Errorf("hardware detector not available")
	}

	total, err := s.hardwareDetector.GetTotalMemory(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get total memory: %w", err)
	}

	available, err := s.hardwareDetector.GetAvailableMemory(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get available memory: %w", err)
	}

	usage, err := s.hardwareDetector.GetMemoryUsage(ctx)
	if err != nil {
		s.logger.Debug("Failed to get detailed memory usage", zap.Error(err))
	}

	used := total - available

	memInfo := &MemoryInfo{
		Total:     total,
		Available: available,
		Used:      used,
		Free:      available, // Simplified
		Usage:     usage,
	}

	s.logger.Debug("Memory information retrieved",
		zap.Uint64("total_gb", total/(1024*1024*1024)),
		zap.Uint64("available_gb", available/(1024*1024*1024)))

	return memInfo, nil
}

// GetCPUInfo retrieves CPU information
func (s *Service) GetCPUInfo(ctx context.Context) (*CPUInfo, error) {
	s.logger.Debug("Getting CPU information")

	if s.hardwareDetector == nil {
		return nil, fmt.Errorf("hardware detector not available")
	}

	count, err := s.hardwareDetector.GetCPUCount(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get CPU count: %w", err)
	}

	model, err := s.hardwareDetector.GetCPUModel(ctx)
	if err != nil {
		s.logger.Debug("Failed to get CPU model", zap.Error(err))
		model = "unknown"
	}

	features, err := s.hardwareDetector.GetCPUFeatures(ctx)
	if err != nil {
		s.logger.Debug("Failed to get CPU features", zap.Error(err))
		features = []string{}
	}

	cpuInfo := &CPUInfo{
		Model:    model,
		Cores:    count,
		Threads:  count, // Simplified, would detect hyperthreading
		Features: features,
	}

	s.logger.Debug("CPU information retrieved",
		zap.String("model", cpuInfo.Model),
		zap.Int("cores", cpuInfo.Cores))

	return cpuInfo, nil
}

// GetDiskInfo retrieves disk information
func (s *Service) GetDiskInfo(ctx context.Context) (*DiskInfo, error) {
	s.logger.Debug("Getting disk information")

	if s.hardwareDetector == nil {
		return nil, fmt.Errorf("hardware detector not available")
	}

	// Get mount points
	mountPoints, err := s.hardwareDetector.GetMountPoints(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get mount points: %w", err)
	}

	// Get filesystem info
	filesystems, err := s.hardwareDetector.GetFileSystemInfo(ctx)
	if err != nil {
		s.logger.Debug("Failed to get filesystem info", zap.Error(err))
		filesystems = []*FileSystemInfo{}
	}

	// Calculate total usage from root filesystem
	var total, used, available uint64
	if len(mountPoints) > 0 {
		for _, mp := range mountPoints {
			if mp.MountPoint == "/" && mp.Usage != nil {
				total = mp.Usage.Total
				used = mp.Usage.Used
				available = mp.Usage.Available
				break
			}
		}
	}

	diskInfo := &DiskInfo{
		Total:       total,
		Used:        used,
		Available:   available,
		MountPoints: mountPoints,
		Filesystems: filesystems,
	}

	s.logger.Debug("Disk information retrieved",
		zap.Uint64("total_gb", total/(1024*1024*1024)),
		zap.Int("mount_points", len(mountPoints)))

	return diskInfo, nil
}

// GetNetworkInfo retrieves network information
func (s *Service) GetNetworkInfo(ctx context.Context) (*NetworkInfo, error) {
	s.logger.Debug("Getting network information")

	interfaces, err := s.GetNetworkInterfaces(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get network interfaces: %w", err)
	}

	netInfo := &NetworkInfo{
		Hostname:   "localhost", // Would be detected by infrastructure
		Interfaces: interfaces,
		DNSServers: []string{}, // Would be detected by infrastructure
	}

	s.logger.Debug("Network information retrieved",
		zap.Int("interfaces", len(interfaces)))

	return netInfo, nil
}

// GetNetworkInterfaces retrieves network interface information
func (s *Service) GetNetworkInterfaces(ctx context.Context) ([]*NetworkInterface, error) {
	s.logger.Debug("Getting network interfaces")

	// This would be implemented by infrastructure layer
	// For now, return empty slice
	interfaces := []*NetworkInterface{}

	s.logger.Debug("Network interfaces retrieved",
		zap.Int("count", len(interfaces)))

	return interfaces, nil
}

// CheckCapabilities checks system capabilities
func (s *Service) CheckCapabilities(ctx context.Context) (*SystemCapabilities, error) {
	s.logger.Debug("Checking system capabilities")

	capabilities := &SystemCapabilities{}

	// Check virtualization support
	if virt, err := s.checkVirtualizationCapabilities(ctx); err != nil {
		s.logger.Debug("Failed to check virtualization capabilities", zap.Error(err))
	} else {
		capabilities.Virtualization = virt
	}

	// Check containerization support
	if container, err := s.checkContainerCapabilities(ctx); err != nil {
		s.logger.Debug("Failed to check container capabilities", zap.Error(err))
	} else {
		capabilities.Containerization = container
	}

	// Check security capabilities
	if security, err := s.checkSecurityCapabilities(ctx); err != nil {
		s.logger.Debug("Failed to check security capabilities", zap.Error(err))
	} else {
		capabilities.Security = security
	}

	s.logger.Debug("System capabilities checked")
	return capabilities, nil
}

// SupportsContainerization checks if the system supports containerization
func (s *Service) SupportsContainerization(ctx context.Context) (bool, error) {
	s.logger.Debug("Checking containerization support")

	if s.capabilityChecker == nil {
		return false, fmt.Errorf("capability checker not available")
	}

	docker, _ := s.capabilityChecker.SupportsDocker(ctx)
	podman, _ := s.capabilityChecker.SupportsPodman(ctx)
	oci, _ := s.capabilityChecker.SupportsOCI(ctx)

	supported := docker || podman || oci

	s.logger.Debug("Containerization support checked",
		zap.Bool("supported", supported),
		zap.Bool("docker", docker),
		zap.Bool("podman", podman))

	return supported, nil
}

// SupportsVirtualization checks if the system supports virtualization
func (s *Service) SupportsVirtualization(ctx context.Context) (bool, error) {
	s.logger.Debug("Checking virtualization support")

	if s.capabilityChecker == nil {
		return false, fmt.Errorf("capability checker not available")
	}

	kvm, _ := s.capabilityChecker.SupportsKVM(ctx)
	vmware, _ := s.capabilityChecker.SupportsVMware(ctx)
	hyperv, _ := s.capabilityChecker.SupportsHyperV(ctx)

	supported := kvm || vmware || hyperv

	s.logger.Debug("Virtualization support checked",
		zap.Bool("supported", supported),
		zap.Bool("kvm", kvm),
		zap.Bool("vmware", vmware))

	return supported, nil
}

// GetEnvironmentInfo retrieves environment information
func (s *Service) GetEnvironmentInfo(ctx context.Context) (*EnvironmentInfo, error) {
	s.logger.Debug("Getting environment information")

	// This would be implemented by infrastructure layer
	envInfo := &EnvironmentInfo{
		Variables:  map[string]string{}, // Would get from os.Environ()
		Path:       []string{},          // Would parse PATH
		WorkingDir: "/",                 // Would get from os.Getwd()
		TempDir:    "/tmp",              // Would get from os.TempDir()
	}

	s.logger.Debug("Environment information retrieved")
	return envInfo, nil
}

// GetUserInfo retrieves current user information
func (s *Service) GetUserInfo(ctx context.Context) (*UserInfo, error) {
	s.logger.Debug("Getting user information")

	if s.securityDetector == nil {
		return nil, fmt.Errorf("security detector not available")
	}

	currentUser, err := s.securityDetector.GetCurrentUser(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get current user: %w", err)
	}

	isRoot, _ := s.securityDetector.IsRunningAsRoot(ctx)
	hasSudo, _ := s.securityDetector.HasSudoAccess(ctx)

	userInfo := currentUser
	userInfo.IsRoot = isRoot
	userInfo.HasSudo = hasSudo

	s.logger.Debug("User information retrieved",
		zap.String("username", userInfo.Username),
		zap.Bool("is_root", userInfo.IsRoot))

	return userInfo, nil
}

// GetPathInfo retrieves path information
func (s *Service) GetPathInfo(ctx context.Context) (*PathInfo, error) {
	s.logger.Debug("Getting path information")

	// This would be implemented by infrastructure layer
	pathInfo := &PathInfo{
		Executable:  "/usr/local/bin/eos", // Would get from os.Executable()
		ConfigPaths: []string{"/etc/eos"},
		DataPaths:   []string{"/var/lib/eos"},
		LogPaths:    []string{"/var/log/eos"},
		TempPaths:   []string{"/tmp"},
	}

	s.logger.Debug("Path information retrieved")
	return pathInfo, nil
}

// Helper methods for capability checking

func (s *Service) checkVirtualizationCapabilities(ctx context.Context) (*VirtualizationCapabilities, error) {
	if s.capabilityChecker == nil {
		return &VirtualizationCapabilities{}, nil
	}

	kvm, _ := s.capabilityChecker.SupportsKVM(ctx)
	vmware, _ := s.capabilityChecker.SupportsVMware(ctx)
	hyperv, _ := s.capabilityChecker.SupportsHyperV(ctx)

	return &VirtualizationCapabilities{
		KVM:    kvm,
		VMware: vmware,
		HyperV: hyperv,
	}, nil
}

func (s *Service) checkContainerCapabilities(ctx context.Context) (*ContainerCapabilities, error) {
	if s.capabilityChecker == nil {
		return &ContainerCapabilities{}, nil
	}

	docker, _ := s.capabilityChecker.SupportsDocker(ctx)
	podman, _ := s.capabilityChecker.SupportsPodman(ctx)
	oci, _ := s.capabilityChecker.SupportsOCI(ctx)

	kubernetes := false
	k3s := false
	if s.containerDetector != nil {
		kubernetes, _ = s.containerDetector.HasKubernetes(ctx)
		k3s, _ = s.containerDetector.HasK3s(ctx)
	}

	return &ContainerCapabilities{
		Docker:     docker,
		Podman:     podman,
		OCI:        oci,
		Kubernetes: kubernetes,
		K3s:        k3s,
	}, nil
}

func (s *Service) checkSecurityCapabilities(ctx context.Context) (*SecurityCapabilities, error) {
	if s.capabilityChecker == nil {
		return &SecurityCapabilities{}, nil
	}

	seccomp, _ := s.capabilityChecker.SupportsSeccomp(ctx)
	namespaces, _ := s.capabilityChecker.SupportsNamespaces(ctx)
	cgroups, _ := s.capabilityChecker.SupportsCgroups(ctx)

	return &SecurityCapabilities{
		Seccomp:    seccomp,
		Namespaces: namespaces,
		Cgroups:    cgroups,
	}, nil
}
