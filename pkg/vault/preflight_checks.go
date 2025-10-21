package vault

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// PreflightChecks performs comprehensive pre-flight validation before attempting Vault installation
func PreflightChecks(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Running pre-flight checks for Vault installation")
	
	// Check if running as root
	if err := checkRootPrivileges(rc); err != nil {
		return err
	}
	
	// Check if required directories can be created
	if err := checkDirectoryPermissions(rc); err != nil {
		return err
	}
	
	// Check if required system tools are available
	if err := checkSystemTools(rc); err != nil {
		return err
	}
	
	// Check if Vault is already installed and configured
	if err := checkVaultStatus(rc); err != nil {
		return err
	}
	
	// Check available disk space
	if err := checkDiskSpace(rc); err != nil {
		return err
	}
	
	// Check network connectivity requirements
	if err := checkNetworkRequirements(rc); err != nil {
		return err
	}
	
	logger.Info("Pre-flight checks completed successfully")
	return nil
}

func checkRootPrivileges(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	if os.Geteuid() != 0 {
		logger.Error("Vault installation requires root privileges")
		return eos_err.NewUserError(
			"Vault installation requires root privileges. Please run with sudo:\n" +
				"  sudo eos create vault\n\n" +
				"This is required because Vault installation needs to:\n" +
				"• Create system directories under /var/lib/eos/\n" +
				"• Install system packages\n" +
				"• Configure systemd services\n" +
				"• Set up proper file permissions for security")
	}
	
	logger.Debug("Root privileges confirmed")
	return nil
}

func checkDirectoryPermissions(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// List of directories that need to be created
	requiredDirs := []string{
		VaultBaseDir,           // /opt/vault
		shared.TLSDir,             // /opt/vault/tls
		shared.SecretsDir,         // /var/lib/eos/secret
		shared.EosRunDir,          // /var/run/eos
		filepath.Dir(shared.VaultAgentCACopyPath), // /opt/vault/agent
	}
	
	for _, dir := range requiredDirs {
		parentDir := filepath.Dir(dir)
		
		// Check if parent directory exists and is writable
		if _, err := os.Stat(parentDir); os.IsNotExist(err) {
			// Check if we can create the parent directory
			if err := os.MkdirAll(parentDir, 0755); err != nil {
				logger.Error("Cannot create required parent directory",
					zap.String("directory", parentDir),
					zap.Error(err))
				return eos_err.NewUserError("Cannot create required directory: %s\nError: %v\n\nThis usually means you need to run with sudo privileges.", parentDir, err)
			}
			// Clean up the test directory
			_ = os.RemoveAll(parentDir)
		}
		
		// Test if we can create the target directory
		if err := os.MkdirAll(dir, 0755); err != nil {
			logger.Error("Cannot create required directory",
				zap.String("directory", dir),
				zap.Error(err))
			return eos_err.NewUserError("Cannot create required directory: %s\nError: %v\n\nThis usually means you need to run with sudo privileges.", dir, err)
		}
		
		// Clean up the test directory
		_ = os.RemoveAll(dir)
	}
	
	logger.Debug("Directory permissions check passed")
	return nil
}

func checkSystemTools(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Define required tools with their package names
	// Format: command -> package name (for apt-get install)
	requiredTools := map[string]string{
		"systemctl": "systemd",
		"openssl":   "openssl",
		"curl":      "curl",
		"unzip":     "unzip",
		"apt-get":   "apt", // For Ubuntu/Debian
	}

	var missingTools []string
	var missingPackages []string

	for tool, pkg := range requiredTools {
		if _, err := exec.LookPath(tool); err != nil {
			missingTools = append(missingTools, tool)
			missingPackages = append(missingPackages, pkg)
		}
	}

	if len(missingTools) > 0 {
		logger.Warn("Missing required system tools",
			zap.Strings("missing_tools", missingTools),
			zap.Strings("packages", missingPackages))

		// Prompt user if they want to install the missing dependencies
		logger.Info("terminal prompt: Missing dependencies detected")
		fmt.Printf("\nMissing required tools: %s\n", strings.Join(missingTools, ", "))
		fmt.Printf("Required packages: %s\n\n", strings.Join(missingPackages, " "))

		// Use interaction.PromptYesNo for y/N prompt (default: No)
		if !interaction.PromptYesNo(rc.Ctx, "Would you like to install these dependencies now?", false) {
			logger.Info("User declined dependency installation")
			return eos_err.NewUserError(
				"Missing required system tools: %s\n\n"+
					"Please install them manually:\n"+
					"  sudo apt-get update && sudo apt-get install %s\n\n"+
					"Then run the command again.",
				strings.Join(missingTools, ", "),
				strings.Join(missingPackages, " "))
		}

		logger.Info("User approved dependency installation, proceeding with installation")

		// Install the missing packages
		if err := installDependencies(rc, missingPackages); err != nil {
			return fmt.Errorf("failed to install dependencies: %w", err)
		}

		logger.Info("Dependencies installed successfully")
	}

	logger.Debug("System tools check passed")
	return nil
}

// installDependencies installs the specified packages using apt-get
func installDependencies(rc *eos_io.RuntimeContext, packages []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Updating package lists")
	fmt.Println("\nUpdating package lists...")

	// Run apt-get update
	updateCmd := exec.CommandContext(rc.Ctx, "apt-get", "update")
	updateCmd.Stdout = os.Stdout
	updateCmd.Stderr = os.Stderr

	if err := updateCmd.Run(); err != nil {
		return fmt.Errorf("failed to update package lists: %w", err)
	}

	logger.Info("Installing packages",
		zap.Strings("packages", packages))
	fmt.Printf("\nInstalling packages: %s\n", strings.Join(packages, " "))

	// Run apt-get install with -y flag
	installArgs := append([]string{"install", "-y"}, packages...)
	installCmd := exec.CommandContext(rc.Ctx, "apt-get", installArgs...)
	installCmd.Stdout = os.Stdout
	installCmd.Stderr = os.Stderr

	if err := installCmd.Run(); err != nil {
		return fmt.Errorf("failed to install packages: %w", err)
	}

	fmt.Println("\nDependencies installed successfully!")
	return nil
}

func checkVaultStatus(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// IDEMPOTENT: Check if Vault is already installed and running
	// This is NOT an error - we'll handle existing installations gracefully
	if _, err := exec.LookPath("vault"); err == nil {
		logger.Info("Vault binary already installed - will verify and update configuration if needed")

		// Check if Vault service is running
		if output, err := exec.Command("systemctl", "is-active", "vault").Output(); err == nil {
			if strings.TrimSpace(string(output)) == "active" {
				logger.Info("Vault service is already running - will verify state and configuration",
					zap.String("status", "active"),
					zap.String("behavior", "idempotent - will check and update if needed"))
				// NOT AN ERROR - let the installation flow handle existing state
				// Each phase will check if its work is already done and skip if so
			}
		}
	}

	logger.Debug("Vault status check passed (idempotent operation)")
	return nil
}

func checkDiskSpace(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Check available disk space in /opt and /var
	checkPaths := []string{"/opt", "/var"}
	minSpaceGB := int64(2) // Minimum 2GB required
	
	for _, path := range checkPaths {
		if available, err := getDiskSpaceGB(path); err == nil {
			if available < minSpaceGB {
				logger.Error("Insufficient disk space",
					zap.String("path", path),
					zap.Int64("available_gb", available),
					zap.Int64("required_gb", minSpaceGB))
				return eos_err.NewUserError("Insufficient disk space in %s. Available: %d GB, Required: %d GB. Please free up disk space and try again.", path, available, minSpaceGB)
			}
		}
	}
	
	logger.Debug("Disk space check passed")
	return nil
}

func checkNetworkRequirements(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if required ports are not already in use
	requiredPorts := []int{shared.VaultDefaultPortInt, shared.VaultDefaultPortInt + 1} // Vault API (8179) and cluster (8180) ports

	for _, port := range requiredPorts {
		if isPortInUse(port) {
			// IDEMPOTENT: Check if it's Vault itself using the port (which is fine)
			// Only fail if a DIFFERENT service is using the port
			if isVaultUsingPort(port) {
				logger.Info("Vault is already using required port (expected for existing installation)",
					zap.Int("port", port),
					zap.String("behavior", "idempotent - will verify configuration"))
				continue // This is fine - Vault should be using these ports
			}

			logger.Error("Required port is already in use by another service",
				zap.Int("port", port))
			return eos_err.NewUserError("Port %d is already in use by another service (not Vault).\n\nVault requires ports %d (API) and %d (cluster) to be available.\nPlease stop the conflicting service or choose different ports.", port, shared.VaultDefaultPortInt, shared.VaultDefaultPortInt+1)
		}
	}

	logger.Debug("Network requirements check passed")
	return nil
}

// Helper functions

func getDiskSpaceGB(path string) (int64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, err
	}
	
	// Available space in bytes
	available := stat.Bavail * uint64(stat.Bsize)
	// Convert to GB
	return int64(available / (1024 * 1024 * 1024)), nil
}

func isPortInUse(port int) bool {
	conn, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return true // Port is in use
	}
	_ = conn.Close() // Best effort close for port check
	return false
}

func isVaultUsingPort(port int) bool {
	// Check if vault process is listening on this port using lsof
	out, err := exec.Command("lsof", "-i", fmt.Sprintf(":%d", port), "-sTCP:LISTEN").Output()
	if err != nil {
		return false // Can't determine, assume not vault
	}

	// Check if any line contains "vault" process
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.Contains(strings.ToLower(line), "vault") {
			return true
		}
	}
	return false
}