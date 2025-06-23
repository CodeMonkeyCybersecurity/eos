// pkg/osquery/types.go

package osquery

// OsqueryPaths contains platform-specific paths for osquery
type OsqueryPaths struct {
	ConfigPath   string
	LogPath      string
	DatabasePath string
	ServiceName  string
}

// InstallMethod represents the installation method for osquery
type InstallMethod string

const (
	// InstallMethodPackage uses native package managers (apt, yum, brew, choco)
	InstallMethodPackage InstallMethod = "package"
	// InstallMethodBinary downloads and installs binary directly
	InstallMethodBinary InstallMethod = "binary"
	// InstallMethodMSI uses MSI installer on Windows
	InstallMethodMSI InstallMethod = "msi"
)

// PlatformConfig contains platform-specific configuration
type PlatformConfig struct {
	Platform      string
	Architecture  string
	Distribution  string // For Linux: debian, rhel, etc.
	Version       string // OS version
	InstallMethod InstallMethod
}

// OsqueryVersion represents osquery version information
type OsqueryVersion struct {
	Version string
	Build   string
	Platform string
}