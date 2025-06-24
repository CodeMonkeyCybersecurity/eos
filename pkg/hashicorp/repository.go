// pkg/hashicorp/repository.go

package hashicorp

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	cerr "github.com/cockroachdb/errors"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

const (
	hashicorpGPGKeyURL = "https://apt.releases.hashicorp.com/gpg"
	hashicorpKeyPath   = "/usr/share/keyrings/hashicorp-archive-keyring.gpg"
	debianRepoPath     = "/etc/apt/sources.list.d/hashicorp.list"
	rhelRepoPath       = "/etc/yum.repos.d/hashicorp.repo"
)

// InstallGPGKey installs and configures HashiCorp's GPG key for package verification
func InstallGPGKey(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" Installing HashiCorp GPG key",
		zap.String("url", hashicorpGPGKeyURL),
		zap.String("key_path", hashicorpKeyPath))

	distro := platform.DetectLinuxDistro(rc)
	logger.Info("🔍 Configuring GPG key for distribution", zap.String("distro", distro))

	switch distro {
	case "debian":
		return installDebianGPGKey(rc, logger)
	case "rhel":
		return installRHELGPGKey(rc, logger)
	default:
		err := fmt.Errorf("unsupported distribution for GPG key installation: %s", distro)
		logger.Error(" GPG key installation not supported",
			zap.String("distro", distro),
			zap.Error(err))
		return cerr.Wrap(err, "check distribution support")
	}
}

// installDebianGPGKey installs GPG key for Debian/Ubuntu systems
func installDebianGPGKey(rc *eos_io.RuntimeContext, logger otelzap.LoggerWithCtx) error {
	logger.Info("📥 Downloading HashiCorp GPG key for Debian/Ubuntu")

	// Check if key already exists
	if _, err := os.Stat(hashicorpKeyPath); err == nil {
		logger.Info(" HashiCorp GPG key already exists", zap.String("path", hashicorpKeyPath))
		return nil
	}

	// Download and install the GPG key
	cmd := fmt.Sprintf("wget -O- %s | gpg --dearmor -o %s", hashicorpGPGKeyURL, hashicorpKeyPath)
	if err := execute.RunSimple(rc.Ctx, "sh", "-c", cmd); err != nil {
		logger.Error(" Failed to download and install GPG key",
			zap.String("command", cmd),
			zap.Error(err))
		return cerr.Wrap(err, "download and install GPG key")
	}

	// Verify the key was installed
	if _, err := os.Stat(hashicorpKeyPath); err != nil {
		logger.Error(" GPG key file not found after installation",
			zap.String("path", hashicorpKeyPath),
			zap.Error(err))
		return cerr.Wrap(err, "verify GPG key installation")
	}

	logger.Info(" HashiCorp GPG key installed successfully",
		zap.String("path", hashicorpKeyPath))
	return nil
}

// installRHELGPGKey installs GPG key for RHEL/CentOS systems
func installRHELGPGKey(rc *eos_io.RuntimeContext, logger otelzap.LoggerWithCtx) error {
	logger.Info("📥 Installing HashiCorp GPG key for RHEL/CentOS")

	// For RHEL systems, the GPG key is typically handled by the repository configuration
	// But we can still import it explicitly
	if err := execute.RunSimple(rc.Ctx, "rpm", "--import", hashicorpGPGKeyURL); err != nil {
		logger.Error(" Failed to import GPG key via rpm",
			zap.String("url", hashicorpGPGKeyURL),
			zap.Error(err))
		return cerr.Wrap(err, "import GPG key via rpm")
	}

	logger.Info(" HashiCorp GPG key imported successfully for RHEL")
	return nil
}

// AddRepository adds HashiCorp's package repository to the system
func AddRepository(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" Adding HashiCorp package repository")

	distro := platform.DetectLinuxDistro(rc)
	logger.Info("🔍 Configuring repository for distribution", zap.String("distro", distro))

	switch distro {
	case "debian":
		return addDebianRepository(rc, logger)
	case "rhel":
		return addRHELRepository(rc, logger)
	default:
		err := fmt.Errorf("unsupported distribution for repository configuration: %s", distro)
		logger.Error(" Repository configuration not supported",
			zap.String("distro", distro),
			zap.Error(err))
		return cerr.Wrap(err, "check distribution support")
	}
}

// addDebianRepository adds HashiCorp repository for Debian/Ubuntu systems
func addDebianRepository(rc *eos_io.RuntimeContext, logger otelzap.LoggerWithCtx) error {
	logger.Info(" Configuring HashiCorp repository for Debian/Ubuntu",
		zap.String("repo_file", debianRepoPath))

	// Check if repository already exists
	if _, err := os.Stat(debianRepoPath); err == nil {
		logger.Info(" HashiCorp repository already configured",
			zap.String("path", debianRepoPath))
		return nil
	}

	// Get the distribution codename
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "lsb_release",
		Args:    []string{"-cs"},
	})
	if err != nil {
		logger.Error(" Failed to get distribution codename", zap.Error(err))
		return cerr.Wrap(err, "get distribution codename")
	}

	codename := output
	logger.Info("🔍 Detected distribution codename", zap.String("codename", codename))

	// Create repository configuration
	repoConfig := fmt.Sprintf("deb [signed-by=%s] https://apt.releases.hashicorp.com %s main",
		hashicorpKeyPath, codename)

	if err := os.WriteFile(debianRepoPath, []byte(repoConfig+"\n"), 0644); err != nil {
		logger.Error(" Failed to write repository configuration",
			zap.String("path", debianRepoPath),
			zap.String("config", repoConfig),
			zap.Error(err))
		return cerr.Wrap(err, "write repository configuration")
	}

	logger.Info(" HashiCorp repository configured successfully",
		zap.String("path", debianRepoPath),
		zap.String("config", repoConfig))

	// Update package lists
	logger.Info(" Updating package lists")
	if err := execute.RunSimple(rc.Ctx, "apt-get", "update"); err != nil {
		logger.Error(" Failed to update package lists", zap.Error(err))
		return cerr.Wrap(err, "update package lists")
	}

	logger.Info(" Package lists updated successfully")
	return nil
}

// addRHELRepository adds HashiCorp repository for RHEL/CentOS systems
func addRHELRepository(rc *eos_io.RuntimeContext, logger otelzap.LoggerWithCtx) error {
	logger.Info(" Configuring HashiCorp repository for RHEL/CentOS",
		zap.String("repo_file", rhelRepoPath))

	// Check if repository already exists
	if _, err := os.Stat(rhelRepoPath); err == nil {
		logger.Info(" HashiCorp repository already configured",
			zap.String("path", rhelRepoPath))
		return nil
	}

	// Create repository configuration
	repoConfig := `[hashicorp]
name=HashiCorp Stable - $basearch
baseurl=https://rpm.releases.hashicorp.com/RHEL/$releasever/$basearch/stable
enabled=1
gpgcheck=1
gpgkey=https://rpm.releases.hashicorp.com/gpg
`

	if err := os.WriteFile(rhelRepoPath, []byte(repoConfig), 0644); err != nil {
		logger.Error(" Failed to write repository configuration",
			zap.String("path", rhelRepoPath),
			zap.Error(err))
		return cerr.Wrap(err, "write repository configuration")
	}

	logger.Info(" HashiCorp repository configured successfully",
		zap.String("path", rhelRepoPath))

	// Update package cache
	logger.Info(" Updating package cache")
	if err := execute.RunSimple(rc.Ctx, "dnf", "makecache"); err != nil {
		logger.Error(" Failed to update package cache", zap.Error(err))
		return cerr.Wrap(err, "update package cache")
	}

	logger.Info(" Package cache updated successfully")
	return nil
}

// RemoveRepository removes HashiCorp's package repository from the system
func RemoveRepository(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("🗑️ Removing HashiCorp package repository")

	distro := platform.DetectLinuxDistro(rc)
	logger.Info("🔍 Removing repository for distribution", zap.String("distro", distro))

	var repoPath string
	switch distro {
	case "debian":
		repoPath = debianRepoPath
	case "rhel":
		repoPath = rhelRepoPath
	default:
		err := fmt.Errorf("unsupported distribution for repository removal: %s", distro)
		logger.Error(" Repository removal not supported",
			zap.String("distro", distro),
			zap.Error(err))
		return cerr.Wrap(err, "check distribution support")
	}

	// Remove repository file
	if err := os.Remove(repoPath); err != nil && !os.IsNotExist(err) {
		logger.Error(" Failed to remove repository file",
			zap.String("path", repoPath),
			zap.Error(err))
		return cerr.Wrap(err, "remove repository file")
	}

	// Remove GPG key
	if err := os.Remove(hashicorpKeyPath); err != nil && !os.IsNotExist(err) {
		logger.Error(" Failed to remove GPG key",
			zap.String("path", hashicorpKeyPath),
			zap.Error(err))
		return cerr.Wrap(err, "remove GPG key")
	}

	logger.Info(" HashiCorp repository and GPG key removed successfully",
		zap.String("repo_path", repoPath),
		zap.String("key_path", hashicorpKeyPath))
	return nil
}
