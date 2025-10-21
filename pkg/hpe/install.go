// pkg/hpe/install.go

package hpe

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// SetupHPERepository sets up the HPE MCP repository and installs management tools
//
// This function implements the Assess → Intervene → Evaluate pattern:
// - Assess: Check platform support, detect distribution, verify root privileges
// - Intervene: Download GPG keys, add repository, update apt, install packages
// - Evaluate: Verify keys and packages were installed successfully
func SetupHPERepository(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	start := time.Now()

	logger.Info("Setting up HPE Management Component Pack repository",
		zap.String("function", "SetupHPERepository"))

	// ASSESS: Platform validation
	if err := assessPlatform(rc); err != nil {
		return err
	}

	// ASSESS: Root privileges check
	if os.Getuid() != 0 {
		logger.Error("Insufficient privileges",
			zap.String("current_user", os.Getenv("USER")),
			zap.String("remediation", "This operation requires root privileges. Run with sudo."))
		return fmt.Errorf("must run as root to configure APT repositories")
	}

	// Get HPE repository configuration
	config, err := getHPERepoConfig(rc)
	if err != nil {
		return fmt.Errorf("failed to get HPE repo config: %w", err)
	}

	// INTERVENE: Download and enroll HPE public keys
	logger.Info("Downloading and enrolling HPE public keys",
		zap.Int("key_count", len(config.Keys)))

	if err := downloadAndEnrollKeys(rc, config); err != nil {
		return fmt.Errorf("failed to enroll GPG keys: %w", err)
	}

	// INTERVENE: Add MCP repository
	logger.Info("Adding MCP repository",
		zap.String("repo_file", config.RepoFile))

	if err := addMCPRepository(rc, config); err != nil {
		return fmt.Errorf("failed to add MCP repository: %w", err)
	}

	// INTERVENE: Update package index
	logger.Info("Updating package index")

	if err := updatePackageIndex(rc); err != nil {
		return fmt.Errorf("failed to update package index: %w", err)
	}

	// INTERVENE: Install HPE packages
	logger.Info("Installing HPE packages",
		zap.Int("package_count", len(config.Packages)))

	installedPackages, failedPackages := installHPEPackages(rc, config)

	// EVALUATE: Report results
	logger.Info("HPE repository setup completed",
		zap.Duration("duration", time.Since(start)),
		zap.Int("installed_packages", len(installedPackages)),
		zap.Int("failed_packages", len(failedPackages)))

	if len(failedPackages) > 0 {
		logger.Warn("Some packages failed to install",
			zap.Strings("failed", failedPackages),
			zap.String("note", "These packages may not be compatible with your hardware generation"))
	}

	logger.Info("terminal prompt: HPE Management Component Pack setup complete")
	logger.Info("terminal prompt: Installed packages:", zap.Strings("packages", installedPackages))

	return nil
}

// assessPlatform validates the platform is supported for HPE repository setup
func assessPlatform(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check platform
	osPlat := platform.GetOSPlatform()
	if osPlat != "linux" {
		logger.Error("Unsupported platform",
			zap.String("platform", osPlat),
			zap.String("supported", "linux"),
			zap.String("remediation", "HPE MCP repository is only available for Linux"))
		return fmt.Errorf("unsupported platform: %s (HPE MCP requires Linux)", osPlat)
	}

	// Detect distribution
	distro := platform.DetectLinuxDistro(rc)
	logger.Info("Linux distribution detected",
		zap.String("distro", distro))

	// Check if it's a Debian-based distribution
	if distro != "ubuntu" && distro != "debian" {
		logger.Warn("Unverified distribution",
			zap.String("distro", distro),
			zap.String("note", "HPE MCP repository is designed for Debian/Ubuntu. Continuing anyway."))
	}

	return nil
}

// getHPERepoConfig returns the configuration for HPE repository setup
func getHPERepoConfig(rc *eos_io.RuntimeContext) (*HPERepoConfig, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Get distribution codename
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "lsb_release",
		Args:    []string{"-sc"},
	})
	if err != nil {
		logger.Error("Failed to detect distribution codename",
			zap.Error(err),
			zap.String("remediation", "Ensure lsb_release is installed: sudo apt install lsb-release"))
		return nil, fmt.Errorf("failed to detect distribution codename: %w", err)
	}

	distCodename := output

	logger.Debug("Distribution codename detected",
		zap.String("codename", distCodename))

	return &HPERepoConfig{
		RepoFile:     "/etc/apt/sources.list.d/mcp.list",
		KeyringDir:   "/etc/apt/trusted.gpg.d",
		RepoURL:      "https://downloads.linux.hpe.com/SDR/repo/mcp",
		Distribution: distCodename,
		Keys: []HPEKey{
			{
				URL:      "https://downloads.linux.hpe.com/SDR/hpPublicKey2048_key1.pub",
				FileName: "hpPublicKey2048_key1",
			},
			{
				URL:      "https://downloads.linux.hpe.com/SDR/hpePublicKey2048_key1.pub",
				FileName: "hpePublicKey2048_key1",
			},
			{
				URL:      "https://downloads.linux.hpe.com/SDR/hpePublicKey2048_key2.pub",
				FileName: "hpePublicKey2048_key2",
			},
		},
		Packages: []HPEPackage{
			{Name: "hp-health", Description: "HPE System Health Application and Command line Utilities (Gen9 and earlier)"},
			{Name: "hponcfg", Description: "HPE RILOE II/iLO online configuration utility"},
			{Name: "amsd", Description: "HPE Agentless Management Service (Gen10 and newer)"},
			{Name: "hp-ams", Description: "HPE Agentless Management Service (Gen9 and earlier)"},
			{Name: "hp-snmp-agents", Description: "Insight Management SNMP Agents for HPE ProLiant Systems (Gen9 and earlier)"},
			{Name: "hpsmh", Description: "HPE System Management Homepage (Gen9 and earlier)"},
			{Name: "hp-smh-templates", Description: "HPE System Management Homepage Templates (Gen9 and earlier)"},
			{Name: "ssacli", Description: "HPE Command Line Smart Storage Administration Utility"},
			{Name: "ssaducli", Description: "HPE Command Line Smart Storage Administration Diagnostics"},
			{Name: "ssa", Description: "HPE Array Smart Storage Administration Service"},
			{Name: "storcli", Description: "MegaRAID command line interface"},
		},
	}, nil
}

// downloadAndEnrollKeys downloads HPE GPG keys and imports them into the APT keyring
func downloadAndEnrollKeys(rc *eos_io.RuntimeContext, config *HPERepoConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Create temporary directory for key downloads
	tempDir, err := os.MkdirTemp("", "hpe-keys-")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tempDir)

	logger.Debug("Created temporary directory for keys",
		zap.String("temp_dir", tempDir))

	for _, key := range config.Keys {
		logger.Info("Processing GPG key",
			zap.String("url", key.URL),
			zap.String("filename", key.FileName))

		keyFile := filepath.Join(tempDir, key.FileName+".pub")
		gpgFile := filepath.Join(config.KeyringDir, key.FileName+".gpg")

		// Download key
		_, err := execute.Run(rc.Ctx, execute.Options{
			Command: "wget",
			Args:    []string{"-q", key.URL, "-O", keyFile},
		})
		if err != nil {
			logger.Warn("Failed to download key",
				zap.String("url", key.URL),
				zap.Error(err))
			continue // Continue with other keys
		}

		// Create temporary keyring and import key
		tempKeyring := filepath.Join(tempDir, "temp-keyring.gpg")

		_, err = execute.Run(rc.Ctx, execute.Options{
			Command: "gpg",
			Args:    []string{"--no-default-keyring", "--keyring", tempKeyring, "--import", keyFile},
		})
		if err != nil {
			logger.Warn("Failed to import key to temp keyring",
				zap.String("key", key.FileName),
				zap.Error(err))
			continue
		}

		// Export key to APT keyring directory
		output, err := execute.Run(rc.Ctx, execute.Options{
			Command: "gpg",
			Args:    []string{"--no-default-keyring", "--keyring", tempKeyring, "--export"},
			Capture: true,
		})
		if err != nil {
			logger.Warn("Failed to export key",
				zap.String("key", key.FileName),
				zap.Error(err))
			continue
		}

		// Write exported key to keyring directory
		if err := os.WriteFile(gpgFile, []byte(output), 0644); err != nil {
			logger.Warn("Failed to write key to keyring directory",
				zap.String("file", gpgFile),
				zap.Error(err))
			continue
		}

		logger.Info("Successfully enrolled GPG key",
			zap.String("key", key.FileName),
			zap.String("location", gpgFile))
	}

	// EVALUATE: List keys in keyring directory
	logger.Info("Listing GPG keys in keyring directory to confirm enrollment")

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ls",
		Args:    []string{"-la", config.KeyringDir},
	})
	if err != nil {
		logger.Warn("Failed to list keyring directory", zap.Error(err))
	} else {
		logger.Debug("Keyring directory contents",
			zap.String("output", output))
	}

	return nil
}

// addMCPRepository adds the HPE MCP repository to APT sources
func addMCPRepository(rc *eos_io.RuntimeContext, config *HPERepoConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Construct repository line
	signedByKey := filepath.Join(config.KeyringDir, "hpePublicKey2048_key2.gpg")
	repoLine := fmt.Sprintf("deb [signed-by=%s] %s %s/current non-free\n",
		signedByKey, config.RepoURL, config.Distribution)

	logger.Debug("Writing repository configuration",
		zap.String("file", config.RepoFile),
		zap.String("content", repoLine))

	// Write repository file
	if err := os.WriteFile(config.RepoFile, []byte(repoLine), 0644); err != nil {
		return fmt.Errorf("failed to write repository file: %w", err)
	}

	logger.Info("MCP repository added successfully",
		zap.String("file", config.RepoFile))

	return nil
}

// updatePackageIndex runs apt update to refresh package lists
func updatePackageIndex(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "apt",
		Args:    []string{"update"},
		Capture: true,
	})
	if err != nil {
		logger.Error("Failed to update package index",
			zap.Error(err),
			zap.String("output", output),
			zap.String("remediation", "Check repository configuration and network connectivity"))
		return fmt.Errorf("apt update failed: %s", output)
	}

	logger.Info("Package index updated successfully")
	return nil
}

// installHPEPackages installs HPE packages, returning lists of successful and failed installations
func installHPEPackages(rc *eos_io.RuntimeContext, config *HPERepoConfig) (installed []string, failed []string) {
	logger := otelzap.Ctx(rc.Ctx)

	for _, pkg := range config.Packages {
		logger.Info("Installing package",
			zap.String("package", pkg.Name),
			zap.String("description", pkg.Description))

		output, err := execute.Run(rc.Ctx, execute.Options{
			Command: "apt",
			Args:    []string{"install", "-y", pkg.Name},
			Capture: true,
		})

		if err != nil {
			logger.Warn("Failed to install package",
				zap.String("package", pkg.Name),
				zap.Error(err),
				zap.String("output", output),
				zap.String("note", "Continuing with next package"))
			failed = append(failed, pkg.Name)
		} else {
			logger.Info("Package installed successfully",
				zap.String("package", pkg.Name))
			installed = append(installed, pkg.Name)
		}
	}

	return installed, failed
}
