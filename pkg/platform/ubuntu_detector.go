package platform

import (
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// UbuntuRelease represents Ubuntu release information
type UbuntuRelease struct {
	Version        string // e.g., "24.04", "22.04", "20.04"
	Codename       string // e.g., "noble", "jammy", "focal"
	PrettyName     string // e.g., "Ubuntu 24.04.2 LTS"
	ID             string // e.g., "ubuntu"
	IDLike         string // e.g., "debian"
	Arch           string // e.g., "amd64"
	IsLTS          bool   // true if it's an LTS release
	SupportedBy    string // for tracking which repositories support this version
}

// OSReleaseInfo represents parsed /etc/os-release information
type OSReleaseInfo struct {
	Name             string
	Version          string
	VersionID        string
	VersionCodename  string
	ID               string
	IDLike           string
	PrettyName       string
	HomeURL          string
	SupportURL       string
	BugReportURL     string
	PrivacyPolicyURL string
	UbuntuCodename   string
}

// DetectUbuntuRelease detects the Ubuntu version and returns detailed information
// This is the unified function that should be used throughout the codebase
func DetectUbuntuRelease(rc *eos_io.RuntimeContext) (*UbuntuRelease, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS - Check if we can read the os-release file
	logger.Debug("Starting Ubuntu version detection")
	
	osInfo, err := parseOSRelease(rc)
	if err != nil {
		return nil, fmt.Errorf("failed to parse OS release information: %w", err)
	}
	
	// INTERVENE - Extract Ubuntu-specific information
	if !isUbuntu(osInfo) {
		return nil, fmt.Errorf("system is not Ubuntu (detected: %s)", osInfo.ID)
	}
	
	release := &UbuntuRelease{
		Version:     osInfo.VersionID,
		Codename:    getCodename(osInfo),
		PrettyName:  osInfo.PrettyName,
		ID:          osInfo.ID,
		IDLike:      osInfo.IDLike,
		Arch:        "amd64", // Default, could be enhanced to detect actual arch
		IsLTS:       isLTSVersion(osInfo.Version),
	}
	
	// EVALUATE - Verify we got the required information
	if release.Version == "" || release.Codename == "" {
		logger.Error("Failed to extract Ubuntu version information",
			zap.String("version", release.Version),
			zap.String("codename", release.Codename),
			zap.Any("raw_os_info", osInfo),
		)
		return nil, fmt.Errorf("could not determine Ubuntu version from /etc/os-release")
	}
	
	logger.Info("Ubuntu version detected successfully",
		zap.String("version", release.Version),
		zap.String("codename", release.Codename),
		zap.String("pretty_name", release.PrettyName),
		zap.Bool("is_lts", release.IsLTS),
	)
	
	return release, nil
}

// parseOSRelease parses the /etc/os-release file and returns structured information
func parseOSRelease(rc *eos_io.RuntimeContext) (*OSReleaseInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Read the file
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return nil, fmt.Errorf("failed to read /etc/os-release: %w", err)
	}
	
	logger.Debug("Read os-release file", zap.String("content", string(data)))
	
	info := &OSReleaseInfo{}
	
	// Parse each line
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		
		// Remove quotes if present (handles both "value" and value formats)
		value = strings.Trim(value, "\"'")
		
		switch key {
		case "NAME":
			info.Name = value
		case "VERSION":
			info.Version = value
		case "VERSION_ID":
			info.VersionID = value
		case "VERSION_CODENAME":
			info.VersionCodename = value
		case "ID":
			info.ID = value
		case "ID_LIKE":
			info.IDLike = value
		case "PRETTY_NAME":
			info.PrettyName = value
		case "HOME_URL":
			info.HomeURL = value
		case "SUPPORT_URL":
			info.SupportURL = value
		case "BUG_REPORT_URL":
			info.BugReportURL = value
		case "PRIVACY_POLICY_URL":
			info.PrivacyPolicyURL = value
		case "UBUNTU_CODENAME":
			info.UbuntuCodename = value
		}
	}
	
	logger.Debug("Parsed OS release information",
		zap.String("name", info.Name),
		zap.String("version_id", info.VersionID),
		zap.String("version_codename", info.VersionCodename),
		zap.String("id", info.ID),
	)
	
	return info, nil
}

// isUbuntu checks if the parsed OS information indicates Ubuntu
func isUbuntu(info *OSReleaseInfo) bool {
	return strings.ToLower(info.ID) == "ubuntu"
}

// getCodename extracts the codename, preferring VERSION_CODENAME over UBUNTU_CODENAME
func getCodename(info *OSReleaseInfo) string {
	if info.VersionCodename != "" {
		return info.VersionCodename
	}
	if info.UbuntuCodename != "" {
		return info.UbuntuCodename
	}
	return ""
}

// isLTSVersion determines if the version string indicates an LTS release
func isLTSVersion(version string) bool {
	return strings.Contains(strings.ToUpper(version), "LTS")
}

// GetSupportedUbuntuVersions returns a list of Ubuntu versions known to be supported
func GetSupportedUbuntuVersions() []string {
	return []string{"20.04", "22.04", "24.04"}
}

// GetUbuntuCodenames returns a mapping of version numbers to codenames
func GetUbuntuCodenames() map[string]string {
	return map[string]string{
		"20.04": "focal",
		"22.04": "jammy",
		"24.04": "noble",
		"18.04": "bionic", // Legacy support
	}
}

// ValidateUbuntuVersion checks if the detected Ubuntu version is supported
func ValidateUbuntuVersion(release *UbuntuRelease, supportedVersions []string) error {
	for _, supported := range supportedVersions {
		if release.Version == supported {
			return nil
		}
	}
	
	return fmt.Errorf("Ubuntu version %s (%s) is not supported. Supported versions: %v", 
		release.Version, release.Codename, supportedVersions)
}

// IsDebianBased checks if the system is Debian-based (includes Ubuntu)
func IsDebianBased(rc *eos_io.RuntimeContext) (bool, error) {
	osInfo, err := parseOSRelease(rc)
	if err != nil {
		return false, err
	}
	
	id := strings.ToLower(osInfo.ID)
	idLike := strings.ToLower(osInfo.IDLike)
	
	return id == "ubuntu" || id == "debian" || strings.Contains(idLike, "debian"), nil
}

// GetSaltRepoURL returns the appropriate Salt repository URL for the Ubuntu release
func GetSaltRepoURL(version, codename string) string {
	// Current Salt repository structure: https://repo.saltproject.io/salt/py3/ubuntu/VERSION/ARCH/latest
	const saltRepoBaseURL = "https://repo.saltproject.io/salt/py3/ubuntu"
	return fmt.Sprintf("%s/%s/amd64/latest", saltRepoBaseURL, version)
}

// GetSaltRepoKeyURL returns the GPG key URL for the given Ubuntu version
func GetSaltRepoKeyURL(version string) string {
	// Salt GPG key URL - use the latest available key
	const saltKeyBaseURL = "https://repo.saltproject.io/salt/py3/ubuntu"
	return fmt.Sprintf("%s/%s/amd64/SALTSTACK-GPG-KEY.pub", saltKeyBaseURL, version)
}