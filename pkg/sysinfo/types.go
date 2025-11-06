// pkg/sysinfo/types.go
package sysinfo

import "context"

// OSType represents different operating system types
type OSType string

const (
	OSTypeLinux   OSType = "linux"
	OSTypeMacOS   OSType = "macos"
	OSTypeWindows OSType = "windows"
	OSTypeUnknown OSType = "unknown"
)

// DistributionType represents different Linux distributions
type DistributionType string

const (
	DistributionUbuntu  DistributionType = "ubuntu"
	DistributionCentOS  DistributionType = "centos"
	DistributionRedHat  DistributionType = "redhat"
	DistributionDebian  DistributionType = "debian"
	DistributionUnknown DistributionType = "unknown"
)

// OSInfo contains operating system information
type OSInfo struct {
	Type         OSType           `json:"type"`
	Distribution DistributionType `json:"distribution,omitempty"`
	Version      string           `json:"version"`
	Kernel       string           `json:"kernel"`
	Architecture string           `json:"architecture"`
}

// DistroFamily represents different Linux distribution families
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

// PackageManagerType represents different package managers
type PackageManagerType string

const (
	PackageManagerAPT     PackageManagerType = "apt"
	PackageManagerYUM     PackageManagerType = "yum"
	PackageManagerDNF     PackageManagerType = "dnf"
	PackageManagerZypper  PackageManagerType = "zypper"
	PackageManagerPacman  PackageManagerType = "pacman"
	PackageManagerPortage PackageManagerType = "portage"
	PackageManagerAPK     PackageManagerType = "apk"
	PackageManagerUnknown PackageManagerType = "unknown"
)

// ServiceManagerType represents different service managers
type ServiceManagerType string

const (
	ServiceManagerSystemd ServiceManagerType = "systemd"
	ServiceManagerOpenRC  ServiceManagerType = "openrc"
	ServiceManagerSysV    ServiceManagerType = "sysv"
	ServiceManagerUnknown ServiceManagerType = "unknown"
)

// DistributionInfo contains detailed distribution information
type DistributionInfo struct {
	ID               string             `json:"id"`
	Name             string             `json:"name"`
	Version          string             `json:"version"`
	VersionID        string             `json:"version_id"`
	PrettyName       string             `json:"pretty_name"`
	VersionCodename  string             `json:"version_codename"`
	HomeURL          string             `json:"home_url"`
	SupportURL       string             `json:"support_url"`
	BugReportURL     string             `json:"bug_report_url"`
	PrivacyPolicyURL string             `json:"privacy_policy_url"`
	Family           DistroFamily       `json:"family"`
	PackageManager   PackageManagerType `json:"package_manager"`
	ServiceManager   ServiceManagerType `json:"service_manager"`
}

// ArchitectureInfo contains architecture information
type ArchitectureInfo struct {
	CPU        string `json:"cpu"`
	Platform   string `json:"platform"`
	Bits       int    `json:"bits"`
	Endianness string `json:"endianness"`
}

// PlatformDetector interface for detecting platform information
type PlatformDetector interface {
	DetectOS(ctx context.Context) (OSType, error)
	DetectDistribution(ctx context.Context) (*DistributionInfo, error)
	GetOSInfo(ctx context.Context) (*OSInfo, error)
}
