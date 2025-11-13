// Package sysinfo provides infrastructure implementations for system information domain
package sysinfo

import (
	"context"
	"runtime"

	"go.uber.org/zap"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
)

// PlatformDetectorImpl implements PlatformDetector using existing platform package
type PlatformDetectorImpl struct {
	rc     *eos_io.RuntimeContext
	logger *zap.Logger
}

// NewPlatformDetector creates a new platform detector implementation
func NewPlatformDetector(rc *eos_io.RuntimeContext, logger *zap.Logger) *PlatformDetectorImpl {
	return &PlatformDetectorImpl{
		rc:     rc,
		logger: logger.Named("platform"),
	}
}

// DetectOS detects the operating system type
func (p *PlatformDetectorImpl) DetectOS(ctx context.Context) (OSType, error) {
	p.logger.Debug("Detecting operating system")

	switch runtime.GOOS {
	case "linux":
		return OSTypeLinux, nil
	case "darwin":
		return OSTypeMacOS, nil
	case "windows":
		return OSTypeWindows, nil
	default:
		p.logger.Warn("Unknown operating system", zap.String("goos", runtime.GOOS))
		return OSTypeUnknown, nil
	}
}

// DetectDistribution detects Linux distribution information
func (p *PlatformDetectorImpl) DetectDistribution(ctx context.Context) (*DistributionInfo, error) {
	p.logger.Debug("Detecting Linux distribution")

	if !platform.IsLinux() {
		return nil, nil
	}

	distro := platform.DetectLinuxDistro(p.rc)

	// Create distribution info based on detected distro
	distroInfo := &DistributionInfo{
		ID:             distro,
		Name:           distro,
		Family:         p.mapDistroFamily(distro),
		PackageManager: p.mapPackageManager(distro),
		ServiceManager: ServiceManagerSystemd, // Most modern distros use systemd
	}

	// Try to get more detailed info from /etc/os-release if available
	if detailedInfo := p.parseOSRelease(); detailedInfo != nil {
		// Update with detailed information
		if detailedInfo.ID != "" {
			distroInfo.ID = detailedInfo.ID
		}
		if detailedInfo.Name != "" {
			distroInfo.Name = detailedInfo.Name
		}
		if detailedInfo.Version != "" {
			distroInfo.Version = detailedInfo.Version
		}
		if detailedInfo.VersionID != "" {
			distroInfo.VersionID = detailedInfo.VersionID
		}
		if detailedInfo.PrettyName != "" {
			distroInfo.PrettyName = detailedInfo.PrettyName
		}
		distroInfo.VersionCodename = detailedInfo.VersionCodename
		distroInfo.HomeURL = detailedInfo.HomeURL
		distroInfo.SupportURL = detailedInfo.SupportURL
		distroInfo.BugReportURL = detailedInfo.BugReportURL
		distroInfo.PrivacyPolicyURL = detailedInfo.PrivacyPolicyURL
	}

	p.logger.Debug("Distribution detected",
		zap.String("id", distroInfo.ID),
		zap.String("name", distroInfo.Name),
		zap.String("family", string(distroInfo.Family)))

	return distroInfo, nil
}

// IsLinux checks if the system is Linux
func (p *PlatformDetectorImpl) IsLinux(ctx context.Context) (bool, error) {
	return platform.IsLinux(), nil
}

// IsMacOS checks if the system is macOS
func (p *PlatformDetectorImpl) IsMacOS(ctx context.Context) (bool, error) {
	return platform.IsMacOS(), nil
}

// IsWindows checks if the system is Windows
func (p *PlatformDetectorImpl) IsWindows(ctx context.Context) (bool, error) {
	return platform.IsWindows(), nil
}

// IsDebian checks if the system is Debian-based
func (p *PlatformDetectorImpl) IsDebian(ctx context.Context) (bool, error) {
	return platform.IsDebian(p.rc), nil
}

// IsRedHat checks if the system is Red Hat-based
func (p *PlatformDetectorImpl) IsRedHat(ctx context.Context) (bool, error) {
	return platform.IsRHEL(p.rc), nil
}

// IsUbuntu checks if the system is Ubuntu
func (p *PlatformDetectorImpl) IsUbuntu(ctx context.Context) (bool, error) {
	distro := platform.DetectLinuxDistro(p.rc)
	return distro == "ubuntu", nil
}

// IsCentOS checks if the system is CentOS
func (p *PlatformDetectorImpl) IsCentOS(ctx context.Context) (bool, error) {
	distro := platform.DetectLinuxDistro(p.rc)
	return distro == "centos", nil
}

// Helper methods

// mapDistroFamily maps distro names to families
func (p *PlatformDetectorImpl) mapDistroFamily(distro string) DistroFamily {
	switch distro {
	case "debian", "ubuntu":
		return DistroFamilyDebian
	case "rhel", "centos", "fedora":
		return DistroFamilyRedHat
	case "arch", "manjaro":
		return DistroFamilyArch
	case "opensuse", "sles":
		return DistroFamilySUSE
	case "gentoo":
		return DistroFamilyGentoo
	case "alpine":
		return DistroFamilyAlpine
	default:
		return DistroFamilyUnknown
	}
}

// mapPackageManager maps distro families to package managers
func (p *PlatformDetectorImpl) mapPackageManager(distro string) PackageManagerType {
	switch distro {
	case "debian", "ubuntu":
		return PackageManagerAPT
	case "rhel", "centos":
		return PackageManagerYUM
	case "fedora":
		return PackageManagerDNF
	case "opensuse", "sles":
		return PackageManagerZypper
	case "arch", "manjaro":
		return PackageManagerPacman
	case "gentoo":
		return PackageManagerPortage
	case "alpine":
		return PackageManagerAPK
	default:
		return PackageManagerUnknown
	}
}

// parseOSRelease parses /etc/os-release for detailed distribution information
// This is a simplified version - a full implementation would parse the actual file
func (p *PlatformDetectorImpl) parseOSRelease() *DistributionInfo {
	// This would read and parse /etc/os-release
	// For now, return nil to use the basic detection above
	return nil
}

// Additional helper methods for extended platform detection

// GetPlatformString returns a human-readable platform string
func (p *PlatformDetectorImpl) GetPlatformString(ctx context.Context) string {
	osType, _ := p.DetectOS(ctx)
	arch := runtime.GOARCH

	return string(osType) + "/" + arch
}

// IsContainerEnvironment checks if running in a container
func (p *PlatformDetectorImpl) IsContainerEnvironment(ctx context.Context) bool {
	// This would check for container indicators like:
	// - /.dockerenv file
	// - /proc/1/cgroup contains docker/lxc
	// - Environment variables like KUBERNETES_SERVICE_HOST
	return false
}

// IsVirtualEnvironment checks if running in a virtual machine
func (p *PlatformDetectorImpl) IsVirtualEnvironment(ctx context.Context) bool {
	// This would check for virtualization indicators like:
	// - DMI information
	// - CPU features
	// - Hypervisor detection
	return false
}

// GetSystemArchitecture returns detailed architecture information
func (p *PlatformDetectorImpl) GetSystemArchitecture() *ArchitectureInfo {
	return &ArchitectureInfo{
		CPU:        runtime.GOARCH,
		Platform:   runtime.GOOS,
		Bits:       64,       // Most systems are 64-bit today
		Endianness: "little", // Most common
	}
}
