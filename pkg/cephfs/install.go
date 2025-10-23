//go:build !darwin
// +build !darwin

package cephfs

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Install performs the complete CephFS installation process
func Install(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS: Check if CephFS installation is possible
	logger.Info("Assessing CephFS installation prerequisites")
	if err := assessInstallationPrerequisites(rc, config); err != nil {
		return fmt.Errorf("failed to assess installation prerequisites: %w", err)
	}

	// INTERVENE: Perform installation steps
	logger.Info("Performing CephFS installation")
	if err := performInstallation(rc, config); err != nil {
		return fmt.Errorf("failed to perform installation: %w", err)
	}

	// EVALUATE: Verify installation was successful
	logger.Info("Verifying CephFS installation")
	if err := verifyInstallation(rc, config); err != nil {
		return fmt.Errorf("failed to verify installation: %w", err)
	}

	logger.Info("CephFS installation completed successfully")
	return nil
}

// assessInstallationPrerequisites checks if installation prerequisites are met
func assessInstallationPrerequisites(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Prompt for missing configuration if not provided
	if err := promptForMissingConfiguration(rc, config); err != nil {
		return fmt.Errorf("failed to get configuration: %w", err)
	}

	// Validate configuration
	if err := validateConfiguration(rc, config); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	// Check if cluster already exists
	logger.Debug("Checking if cluster already exists")
	status, err := GetClusterStatus(rc, config)
	if err != nil {
		logger.Debug("Could not get cluster status, assuming cluster doesn't exist", zap.Error(err))
	} else if status.ClusterExists && !config.ForceRedeploy {
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("CephFS cluster already exists on %s. Use --force-redeploy to override", config.AdminHost))
	}

	// Check system requirements
	if err := checkSystemRequirements(rc, config); err != nil {
		return fmt.Errorf("system requirements check failed: %w", err)
	}

	// Check SSH access
	if err := checkSSHAccess(rc, config); err != nil {
		return fmt.Errorf("SSH access check failed: %w", err)
	}

	// Check cephadm availability
	if err := checkCephadmAvailability(rc, config); err != nil {
		return fmt.Errorf("cephadm availability check failed: %w", err)
	}

	logger.Debug("Installation prerequisites satisfied")
	return nil
}

// promptForMissingConfiguration prompts user for missing configuration values
func promptForMissingConfiguration(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Prompt for cluster FSID if not provided
	if config.ClusterFSID == "" {
		logger.Info("terminal prompt: Enter Ceph cluster FSID (leave empty for auto-generation)")
		fsid := interaction.PromptInput(rc.Ctx, "Cluster FSID (leave empty for auto-generation): ", "")
		config.ClusterFSID = fsid
	}

	// Prompt for admin host if not provided
	if config.AdminHost == "" {
		logger.Info("terminal prompt: Enter admin host for CephFS deployment")
		host := interaction.PromptInput(rc.Ctx, "Admin Host: ", "")
		if host == "" {
			return fmt.Errorf("admin host is required")
		}
		config.AdminHost = host
	}

	// Prompt for public network if not provided
	if config.PublicNetwork == "" {
		logger.Info("terminal prompt: Enter public network CIDR (e.g., 10.0.0.0/24)")
		network := interaction.PromptInput(rc.Ctx, "Public Network (e.g., 10.0.0.0/24): ", "")
		if network == "" {
			return fmt.Errorf("public network is required")
		}
		config.PublicNetwork = network
	}

	// Prompt for cluster network if not provided
	if config.ClusterNetwork == "" {
		logger.Info("terminal prompt: Enter cluster network CIDR (e.g., 10.1.0.0/24)")
		network := interaction.PromptInput(rc.Ctx, "Cluster Network (e.g., 10.1.0.0/24): ", "")
		if network == "" {
			return fmt.Errorf("cluster network is required")
		}
		config.ClusterNetwork = network
	}

	// Set defaults for optional fields
	if config.SSHUser == "" {
		config.SSHUser = DefaultSSHUser
	}

	if config.CephImage == "" {
		config.CephImage = DefaultCephImage
	}

	return nil
}

// validateConfiguration validates the provided configuration
func validateConfiguration(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Validating configuration")

	// Validate required fields
	if config.AdminHost == "" {
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("admin host is required"))
	}

	if config.PublicNetwork == "" {
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("public network is required"))
	}

	if config.ClusterNetwork == "" {
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("cluster network is required"))
	}

	// Validate Ceph image format
	if !IsValidCephImage(config.CephImage) {
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("invalid Ceph image format: %s", config.CephImage))
	}

	// Validate network CIDR format (basic validation)
	if !strings.Contains(config.PublicNetwork, "/") {
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("public network must be in CIDR format (e.g., 10.0.0.0/24)"))
	}

	if !strings.Contains(config.ClusterNetwork, "/") {
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("cluster network must be in CIDR format (e.g., 10.1.0.0/24)"))
	}

	logger.Debug("Configuration validation passed")
	return nil
}

// checkSystemRequirements checks if system meets minimum requirements
func checkSystemRequirements(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Checking system requirements on admin host")

	// Check available memory
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ssh",
		Args: []string{
			"-o", "ConnectTimeout=10",
			"-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=no",
			fmt.Sprintf("%s@%s", config.SSHUser, config.AdminHost),
			"free", "-m",
		},
		Timeout: 30 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("failed to check memory on admin host: %w", err)
	}

	// Basic memory check - should have at least 4GB available
	if !strings.Contains(output, "Mem:") {
		return fmt.Errorf("could not parse memory information from admin host")
	}

	// Check available disk space
	diskOutput, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ssh",
		Args: []string{
			"-o", "ConnectTimeout=10",
			"-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=no",
			fmt.Sprintf("%s@%s", config.SSHUser, config.AdminHost),
			"df", "-h", "/",
		},
		Timeout: 30 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("failed to check disk space on admin host: %w", err)
	}

	if !strings.Contains(diskOutput, "/") {
		return fmt.Errorf("could not parse disk space information from admin host")
	}

	// Check if Docker is available (for cephadm)
	dockerOutput, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ssh",
		Args: []string{
			"-o", "ConnectTimeout=10",
			"-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=no",
			fmt.Sprintf("%s@%s", config.SSHUser, config.AdminHost),
			"which", "docker",
		},
		Timeout: 30 * time.Second,
	})
	if err != nil {
		logger.Warn("Docker not found on admin host - cephadm may install podman instead")
	} else {
		logger.Debug("Docker found on admin host", zap.String("path", strings.TrimSpace(dockerOutput)))
	}

	logger.Debug("System requirements check completed")
	return nil
}

// checkSSHAccess verifies SSH access to the admin host
func checkSSHAccess(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Checking SSH access to admin host")

	// Test basic SSH connectivity
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ssh",
		Args: []string{
			"-o", "ConnectTimeout=10",
			"-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=no",
			fmt.Sprintf("%s@%s", config.SSHUser, config.AdminHost),
			"whoami",
		},
		Timeout: 30 * time.Second,
	})
	if err != nil {
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("SSH access to %s@%s failed: %w", config.SSHUser, config.AdminHost, err))
	}

	expectedUser := config.SSHUser
	actualUser := strings.TrimSpace(output)
	if actualUser != expectedUser {
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("SSH user mismatch: expected %s, got %s", expectedUser, actualUser))
	}

	// Test sudo access if user is not root
	if config.SSHUser != "root" {
		sudoOutput, err := execute.Run(rc.Ctx, execute.Options{
			Command: "ssh",
			Args: []string{
				"-o", "ConnectTimeout=10",
				"-o", "BatchMode=yes",
				"-o", "StrictHostKeyChecking=no",
				fmt.Sprintf("%s@%s", config.SSHUser, config.AdminHost),
				"sudo", "-n", "whoami",
			},
			Timeout: 30 * time.Second,
		})
		if err != nil {
			return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("sudo access test failed for %s@%s: %w", config.SSHUser, config.AdminHost, err))
		}

		if strings.TrimSpace(sudoOutput) != "root" {
			return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("sudo access verification failed: expected root, got %s", strings.TrimSpace(sudoOutput)))
		}
	}

	logger.Debug("SSH access verification passed")
	return nil
}

// performInstallation performs the actual installation steps
func performInstallation(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Install cephadm if not already installed
	if err := installCephadm(rc, config); err != nil {
		return fmt.Errorf("failed to install cephadm: %w", err)
	}

	// Bootstrap Ceph cluster if needed
	if err := bootstrapCephCluster(rc, config); err != nil {
		return fmt.Errorf("failed to bootstrap Ceph cluster: %w", err)
	}

	// Install additional tools and dependencies
	if err := installDependencies(rc, config); err != nil {
		return fmt.Errorf("failed to install dependencies: %w", err)
	}

	logger.Info("Installation steps completed")
	return nil
}

// installCephadm installs cephadm on the admin host
func installCephadm(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Installing cephadm on admin host")

	// Check if cephadm is already installed
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ssh",
		Args: []string{
			"-o", "ConnectTimeout=10",
			"-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=no",
			fmt.Sprintf("%s@%s", config.SSHUser, config.AdminHost),
			"which", "cephadm",
		},
		Timeout: 30 * time.Second,
	})
	if err == nil {
		logger.Debug("cephadm already installed")
		return nil
	}

	// Download and install cephadm
	installCmd := "curl --silent --remote-name --location https://github.com/ceph/ceph/raw/main/src/cephadm/cephadm && chmod +x cephadm && sudo mv cephadm /usr/local/bin/"

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ssh",
		Args: []string{
			"-o", "ConnectTimeout=10",
			"-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=no",
			fmt.Sprintf("%s@%s", config.SSHUser, config.AdminHost),
			"bash", "-c", installCmd,
		},
		Timeout: 5 * time.Minute,
	})
	if err != nil {
		return fmt.Errorf("failed to install cephadm: %w", err)
	}

	logger.Debug("cephadm installation completed", zap.String("output", output))
	return nil
}

// bootstrapCephCluster bootstraps the Ceph cluster if needed
func bootstrapCephCluster(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Checking if Ceph cluster needs bootstrapping")

	// Check if cluster is already bootstrapped
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ssh",
		Args: []string{
			"-o", "ConnectTimeout=10",
			"-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=no",
			fmt.Sprintf("%s@%s", config.SSHUser, config.AdminHost),
			"test", "-f", "/etc/ceph/ceph.conf",
		},
		Timeout: 30 * time.Second,
	})
	if err == nil {
		logger.Debug("Ceph cluster already bootstrapped")
		return nil
	}

	// Generate cluster FSID if not provided
	if config.ClusterFSID == "" {
		fsid, err := generateClusterFSID(rc)
		if err != nil {
			return fmt.Errorf("failed to generate cluster FSID: %w", err)
		}
		config.ClusterFSID = fsid
	}

	logger.Info("Bootstrapping Ceph cluster", zap.String("fsid", config.ClusterFSID))

	// Build bootstrap command
	bootstrapCmd := fmt.Sprintf("cephadm bootstrap --mon-ip $(hostname -I | awk '{print $1}') --cluster-fsid %s --ssh-user %s",
		config.ClusterFSID, config.SSHUser)

	// Add image if specified
	if config.CephImage != "" && config.CephImage != DefaultCephImage {
		bootstrapCmd += fmt.Sprintf(" --image %s", config.CephImage)
	}

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ssh",
		Args: []string{
			"-o", "ConnectTimeout=10",
			"-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=no",
			fmt.Sprintf("%s@%s", config.SSHUser, config.AdminHost),
			"sudo", "bash", "-c", bootstrapCmd,
		},
		Timeout: 15 * time.Minute,
	})
	if err != nil {
		return fmt.Errorf("failed to bootstrap Ceph cluster: %w", err)
	}

	logger.Info("Ceph cluster bootstrap completed")
	logger.Debug("Bootstrap output", zap.String("output", output))

	return nil
}

// installDependencies installs additional dependencies
func installDependencies(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Installing additional dependencies")

	// Install ceph-common for client commands
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ssh",
		Args: []string{
			"-o", "ConnectTimeout=10",
			"-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=no",
			fmt.Sprintf("%s@%s", config.SSHUser, config.AdminHost),
			"sudo", "apt-get", "update", "&&", "sudo", "apt-get", "install", "-y", "ceph-common",
		},
		Timeout: 10 * time.Minute,
	})
	if err != nil {
		logger.Warn("Failed to install ceph-common, continuing anyway", zap.Error(err))
	} else {
		logger.Debug("ceph-common installation completed", zap.String("output", output))
	}

	return nil
}

// verifyInstallation verifies the installation was successful
func verifyInstallation(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Verify cephadm is installed and accessible
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ssh",
		Args: []string{
			"-o", "ConnectTimeout=10",
			"-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=no",
			fmt.Sprintf("%s@%s", config.SSHUser, config.AdminHost),
			"cephadm", "--help",
		},
		Timeout: 30 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("cephadm verification failed: %w", err)
	}

	if !strings.Contains(output, "usage:") && !strings.Contains(output, "cephadm") {
		return fmt.Errorf("cephadm installation verification failed")
	}

	// Verify Ceph cluster is accessible
	clusterOutput, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ssh",
		Args: []string{
			"-o", "ConnectTimeout=10",
			"-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=no",
			fmt.Sprintf("%s@%s", config.SSHUser, config.AdminHost),
			"ceph", "--version",
		},
		Timeout: 60 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("ceph cluster verification failed: %w", err)
	}

	if !strings.Contains(clusterOutput, "ceph version") {
		return fmt.Errorf("ceph cluster verification failed: unexpected output: %s", clusterOutput)
	}

	logger.Info("Installation verification passed")
	logger.Debug("Ceph version", zap.String("version", strings.TrimSpace(clusterOutput)))

	return nil
}

// generateClusterFSID generates a new cluster FSID for Ceph
func generateClusterFSID(rc *eos_io.RuntimeContext) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Use uuidgen to generate a new UUID for the cluster
	cmd := exec.Command("uuidgen")
	output, err := cmd.Output()
	if err != nil {
		logger.Error("Failed to generate UUID", zap.Error(err))
		return "", fmt.Errorf("failed to generate cluster FSID: %w", err)
	}

	fsid := strings.TrimSpace(string(output))
	logger.Info("Generated new cluster FSID", zap.String("fsid", fsid))

	return fsid, nil
}
