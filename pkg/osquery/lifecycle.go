// pkg/osquery/lifecycle.go

package osquery

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// installLinux handles osquery installation on Linux systems
func installLinux(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Detect Linux distribution
	distro := platform.DetectLinuxDistro(rc)
	arch := platform.GetArch()

	logger.Info("🐧 Installing osquery on Linux",
		zap.String("distro", distro),
		zap.String("arch", arch))

	switch distro {
	case "debian":
		return installDebianUbuntu(rc, arch)
	case "rhel":
		return installRHELCentOS(rc, arch)
	default:
		logger.Error("❌ Unsupported Linux distribution",
			zap.String("distro", distro),
			zap.String("troubleshooting", "Supported distributions: Debian/Ubuntu, RHEL/CentOS"))
		return fmt.Errorf("unsupported Linux distribution: %s", distro)
	}
}

// installDebianUbuntu handles installation on Debian/Ubuntu systems
func installDebianUbuntu(rc *eos_io.RuntimeContext, arch string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("📦 Installing osquery on Debian/Ubuntu")

	// Create keyrings directory
	logger.Info("📁 Creating APT keyrings directory")
	if err := execute.RunSimple(rc.Ctx, "mkdir", "-p", "/etc/apt/keyrings"); err != nil {
		logger.Error("❌ Failed to create keyrings directory",
			zap.Error(err),
			zap.String("troubleshooting", "Ensure you have sudo/root privileges"))
		return fmt.Errorf("create keyrings directory: %w", err)
	}

	// Download and install GPG key
	logger.Info("🔑 Downloading osquery GPG key")
	keyPath := "/tmp/osquery-key.gpg"
	if err := execute.RunSimple(rc.Ctx, "curl", "-fsSL", "https://pkg.osquery.io/deb/pubkey.gpg", "-o", keyPath); err != nil {
		logger.Error("❌ Failed to download GPG key",
			zap.Error(err),
			zap.String("troubleshooting", "Check internet connectivity and DNS resolution"))
		return fmt.Errorf("download GPG key: %w", err)
	}
	defer func() {
		if err := os.Remove(keyPath); err != nil {
			logger.Warn("⚠️ Failed to remove temporary GPG key",
				zap.String("path", keyPath),
				zap.Error(err))
		}
	}()

	// Convert to keyring format
	keyringPath := "/etc/apt/keyrings/osquery.asc"
	logger.Info("🔐 Installing GPG key to keyring")
	if err := execute.RunSimple(rc.Ctx, "cp", keyPath, keyringPath); err != nil {
		logger.Error("❌ Failed to install GPG key",
			zap.Error(err),
			zap.String("keyring_path", keyringPath))
		return fmt.Errorf("install GPG key: %w", err)
	}

	// Add repository
	logger.Info("📋 Adding osquery APT repository")
	repoLine := fmt.Sprintf("deb [arch=%s signed-by=%s] https://pkg.osquery.io/deb deb main", arch, keyringPath)
	repoPath := "/etc/apt/sources.list.d/osquery.list"
	if err := os.WriteFile(repoPath, []byte(repoLine+"\n"), 0644); err != nil {
		logger.Error("❌ Failed to write repository file",
			zap.Error(err),
			zap.String("repo_path", repoPath))
		return fmt.Errorf("write repository file: %w", err)
	}

	// Update package list
	logger.Info("🔄 Updating package lists")
	if err := execute.RunSimple(rc.Ctx, "apt-get", "update"); err != nil {
		logger.Error("❌ Failed to update package lists",
			zap.Error(err),
			zap.String("troubleshooting", "Check repository configuration and network connectivity"))
		return fmt.Errorf("update package lists: %w", err)
	}

	// Install osquery
	logger.Info("📦 Installing osquery package")
	if err := execute.RunSimple(rc.Ctx, "apt-get", "install", "-y", "osquery"); err != nil {
		logger.Error("❌ Failed to install osquery",
			zap.Error(err),
			zap.String("troubleshooting", "Ensure package dependencies are met and disk space is available"))
		return fmt.Errorf("install osquery: %w", err)
	}

	// Configure and start service
	if err := configureLinuxService(rc); err != nil {
		return err
	}

	logger.Info("✅ osquery installed successfully on Debian/Ubuntu")
	return nil
}

// installRHELCentOS handles installation on RHEL/CentOS systems
func installRHELCentOS(rc *eos_io.RuntimeContext, arch string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("📦 Installing osquery on RHEL/CentOS",
		zap.String("arch", arch))

	// Import GPG key
	logger.Info("🔑 Importing osquery GPG key")
	if err := execute.RunSimple(rc.Ctx, "rpm", "--import", "https://pkg.osquery.io/rpm/pubkey.gpg"); err != nil {
		logger.Error("❌ Failed to import GPG key",
			zap.Error(err),
			zap.String("troubleshooting", "Check internet connectivity and RPM configuration"))
		return fmt.Errorf("import GPG key: %w", err)
	}

	// Add YUM repository
	logger.Info("📋 Adding osquery YUM repository")
	repoContent := `[osquery]
name=osquery
baseurl=https://pkg.osquery.io/rpm/$basearch/
enabled=1
gpgcheck=1
gpgkey=https://pkg.osquery.io/rpm/pubkey.gpg
`
	repoPath := "/etc/yum.repos.d/osquery.repo"
	if err := os.WriteFile(repoPath, []byte(repoContent), 0644); err != nil {
		logger.Error("❌ Failed to write repository file",
			zap.Error(err),
			zap.String("repo_path", repoPath))
		return fmt.Errorf("write repository file: %w", err)
	}

	// Install osquery
	logger.Info("📦 Installing osquery package")
	if err := execute.RunSimple(rc.Ctx, "yum", "install", "-y", "osquery"); err != nil {
		logger.Error("❌ Failed to install osquery",
			zap.Error(err),
			zap.String("troubleshooting", "Ensure YUM is not locked and dependencies are available"))
		return fmt.Errorf("install osquery: %w", err)
	}

	// Configure and start service
	if err := configureLinuxService(rc); err != nil {
		return err
	}

	logger.Info("✅ osquery installed successfully on RHEL/CentOS")
	return nil
}

// configureLinuxService configures and starts osquery service on Linux
func configureLinuxService(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	paths := GetOsqueryPaths()

	// Create configuration directory
	configDir := filepath.Dir(paths.ConfigPath)
	logger.Info("📁 Creating configuration directory",
		zap.String("path", configDir))
	if err := os.MkdirAll(configDir, 0755); err != nil {
		logger.Error("❌ Failed to create config directory",
			zap.Error(err),
			zap.String("path", configDir))
		return fmt.Errorf("create config directory: %w", err)
	}

	// Write configuration
	logger.Info("📝 Writing osquery configuration",
		zap.String("path", paths.ConfigPath))
	if err := os.WriteFile(paths.ConfigPath, []byte(defaultOsqueryConfig), 0644); err != nil {
		logger.Error("❌ Failed to write configuration",
			zap.Error(err),
			zap.String("path", paths.ConfigPath))
		return fmt.Errorf("write configuration: %w", err)
	}

	// Enable and start service
	logger.Info("🚀 Starting osquery service")
	if err := execute.RunSimple(rc.Ctx, "systemctl", "enable", "osqueryd"); err != nil {
		logger.Warn("⚠️ Failed to enable osquery service",
			zap.Error(err),
			zap.String("note", "Service may need manual configuration"))
	}

	if err := execute.RunSimple(rc.Ctx, "systemctl", "start", "osqueryd"); err != nil {
		logger.Warn("⚠️ Failed to start osquery service",
			zap.Error(err),
			zap.String("note", "Service may need manual start"))
	}

	return nil
}
