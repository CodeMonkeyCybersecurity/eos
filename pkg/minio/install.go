package minio

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CheckPrerequisites performs preflight checks for all required dependencies
func CheckPrerequisites(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS - Check if we can perform the operation
	logger.Info("Assessing MinIO deployment prerequisites")
	
	// Check OS requirements
	if err := checkOSRequirements(rc); err != nil {
		return err
	}
	
	// Check required commands
	if err := checkRequiredCommands(rc); err != nil {
		return err
	}
	
	// Check system resources
	if err := checkSystemResources(rc); err != nil {
		return err
	}
	
	// Check network requirements
	if err := checkNetworkRequirements(rc); err != nil {
		return err
	}
	
	logger.Info("All prerequisites satisfied")
	return nil
}

// checkOSRequirements verifies the operating system requirements
func checkOSRequirements(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Debug("Checking OS requirements")
	
	// Check if running on Ubuntu
	if _, err := os.Stat("/etc/os-release"); err != nil {
		return eos_err.NewUserError("cannot determine OS type: /etc/os-release not found")
	}
	
	content, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return fmt.Errorf("failed to read OS information: %w", err)
	}
	
	osInfo := string(content)
	if !containsString(osInfo, "ID=ubuntu") {
		return eos_err.NewUserError("MinIO deployment requires Ubuntu Linux")
	}
	
	if !containsString(osInfo, "VERSION_ID=\"22.04\"") && !containsString(osInfo, "VERSION_ID=\"24.04\"") {
		logger.Warn("MinIO deployment is tested on Ubuntu 22.04/24.04, other versions may work but are not officially supported")
	}
	
	// Check if running as root (skip in dev mode for testing)
	if os.Geteuid() != 0 && os.Getenv("EOS_DEV_MODE") != "true" {
		return eos_err.NewUserError("this command requires root privileges, please run with sudo")
	}
	
	return nil
}

// checkRequiredCommands verifies all required commands are available
func checkRequiredCommands(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Debug("Checking required commands")
	
	dependencies := GetRequiredDependencies()
	var missingDeps []string
	var missingOptional []string
	
	for _, dep := range dependencies {
		logger.Debug("Checking for command",
			zap.String("command", dep.Command),
			zap.String("description", dep.Description))
		
		if _, err := exec.LookPath(dep.Command); err != nil {
			if dep.Required {
				missingDeps = append(missingDeps, fmt.Sprintf("- %s (%s): %s", 
					dep.Name, dep.Command, dep.Description))
			} else {
				missingOptional = append(missingOptional, dep.Name)
			}
		}
	}
	
	if len(missingOptional) > 0 {
		logger.Info("Optional dependencies not found (deployment will continue)",
			zap.Strings("optional_deps", missingOptional))
	}
	
	if len(missingDeps) > 0 {
		errorMsg := "Missing required dependencies:\n"
		for _, dep := range missingDeps {
			errorMsg += dep + "\n"
		}
		errorMsg += "\nPlease install these dependencies before proceeding."
		errorMsg += "\n\nFor Ubuntu, you can install most dependencies with:"
		errorMsg += "\n  sudo apt-get update && sudo apt-get install -y curl"
		errorMsg += "\n\nFor HashiCorp tools (Terraform, Nomad, Vault, Consul):"
		errorMsg += "\n  See: https://developer.hashicorp.com/tutorials/library"
		errorMsg += "\n\nFor SaltStack:"
		errorMsg += "\n  See: https://docs.saltproject.io/salt/install-guide/en/latest/topics/install-by-operating-system/ubuntu.html"
		
		return eos_err.NewUserError("%s", errorMsg)
	}
	
	return nil
}

// checkSystemResources verifies system has adequate resources
func checkSystemResources(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Debug("Checking system resources")
	
	// Check storage path exists
	storagePath := DefaultStoragePath
	if info, err := os.Stat(storagePath); err != nil {
		if os.IsNotExist(err) {
			return eos_err.NewUserError(
				"storage path %s does not exist\n"+
				"MinIO requires an external disk mounted at this location\n"+
				"Please mount a disk or specify a different path with --storage-path", 
				storagePath)
		}
		return fmt.Errorf("failed to check storage path: %w", err)
	} else if !info.IsDir() {
		return eos_err.NewUserError("%s exists but is not a directory", storagePath)
	}
	
	// Check if we have write permissions
	testFile := fmt.Sprintf("%s/.minio-test", storagePath)
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		return eos_err.NewUserError("no write permission for storage path %s: %v", storagePath, err)
	}
	os.Remove(testFile)
	
	return nil
}

// checkNetworkRequirements verifies network connectivity
func checkNetworkRequirements(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Debug("Checking network requirements")
	
	// Check if ports are available
	ports := []int{DefaultAPIPort, DefaultConsolePort}
	for _, port := range ports {
		if err := checkPortAvailable(port); err != nil {
			return eos_err.NewUserError(
				"port %d is already in use\n"+
				"Please ensure the port is available or specify a different port", 
				port)
		}
	}
	
	// Check Vault connectivity
	logger.Debug("Checking Vault connectivity")
	cmd := exec.Command("vault", "status")
	if err := cmd.Run(); err != nil {
		// Vault might be sealed, which returns exit code 2
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 2 {
			logger.Info("Vault is sealed but reachable")
		} else {
			logger.Warn("Cannot connect to Vault (will attempt to configure during deployment)",
				zap.Error(err))
		}
	}
	
	return nil
}

// checkPortAvailable checks if a port is available for binding
func checkPortAvailable(port int) error {
	// Use lsof or ss to check if port is in use
	cmd := exec.Command("ss", "-tlnp", fmt.Sprintf("sport = :%d", port))
	output, err := cmd.CombinedOutput()
	
	// If ss fails, try lsof
	if err != nil {
		cmd = exec.Command("lsof", "-i", fmt.Sprintf(":%d", port))
		output, err = cmd.CombinedOutput()
	}
	
	// If command succeeded and has output, port is in use
	if err == nil && len(output) > 0 {
		return fmt.Errorf("port %d is already in use", port)
	}
	
	return nil
}

// containsString checks if a string contains a substring
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && stringContains(s, substr)
}

// stringContains is a simple substring check
func stringContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}