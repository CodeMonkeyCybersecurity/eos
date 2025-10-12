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
		shared.VaultDir,           // /opt/vault
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
	
	requiredTools := []string{
		"systemctl",
		"openssl",
		"curl",
		"apt-get", // For Ubuntu/Debian
	}
	
	var missingTools []string
	
	for _, tool := range requiredTools {
		if _, err := exec.LookPath(tool); err != nil {
			missingTools = append(missingTools, tool)
		}
	}
	
	if len(missingTools) > 0 {
		logger.Error("Missing required system tools",
			zap.Strings("missing_tools", missingTools))
		return eos_err.NewUserError("Missing required system tools: %s\n\nPlease install the missing tools and try again.\nOn Ubuntu/Debian: sudo apt-get update && sudo apt-get install %s", strings.Join(missingTools, ", "), strings.Join(missingTools, " "))
	}
	
	logger.Debug("System tools check passed")
	return nil
}

func checkVaultStatus(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Check if Vault binary already exists
	if _, err := exec.LookPath("vault"); err == nil {
		logger.Info("Vault binary already installed")
		
		// Check if Vault service is running
		if output, err := exec.Command("systemctl", "is-active", "vault").Output(); err == nil {
			if strings.TrimSpace(string(output)) == "active" {
				logger.Warn("Vault service is already running")
				return eos_err.NewUserError(
					"Vault service is already running.\n\n" +
						"If you want to reinstall Vault, please first stop the service:\n" +
						"  sudo systemctl stop vault\n\n" +
						"Or use the update command to modify the existing installation:\n" +
						"  eos update vault")
			}
		}
	}
	
	logger.Debug("Vault status check passed")
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
	requiredPorts := []int{8200, 8201} // Vault API and cluster ports
	
	for _, port := range requiredPorts {
		if isPortInUse(port) {
			logger.Error("Required port is already in use",
				zap.Int("port", port))
			return eos_err.NewUserError("Port %d is already in use by another service.\n\nVault requires ports 8200 (API) and 8201 (cluster) to be available.\nPlease stop the conflicting service or choose different ports.", port)
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
	conn.Close()
	return false
}