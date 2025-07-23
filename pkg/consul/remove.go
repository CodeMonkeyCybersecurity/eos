// pkg/consul/remove.go

package consul

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// RemoveConsul performs complete removal of Consul from the system
func RemoveConsul(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Starting Consul removal process")
	
	// ASSESS - Check current state
	if err := assessConsulState(rc); err != nil {
		logger.Info("Consul assessment completed", zap.Error(err))
	}
	
	// INTERVENE - Perform removal steps
	if err := stopConsulService(rc); err != nil {
		logger.Warn("Failed to stop Consul service", zap.Error(err))
		// Continue with removal even if stop fails
	}
	
	if err := removeConsulPackage(rc); err != nil {
		return fmt.Errorf("failed to remove Consul package: %w", err)
	}
	
	if err := cleanupConsulFiles(rc); err != nil {
		return fmt.Errorf("failed to cleanup Consul files: %w", err)
	}
	
	if err := removeConsulUser(rc); err != nil {
		logger.Warn("Failed to remove Consul user", zap.Error(err))
		// Not critical, continue
	}
	
	// EVALUATE - Verify removal
	if err := verifyConsulRemoval(rc); err != nil {
		return fmt.Errorf("Consul removal verification failed: %w", err)
	}
	
	logger.Info("Consul removal completed successfully")
	return nil
}

func assessConsulState(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Assessing current Consul installation state")
	
	// Check if Consul binary exists
	if _, err := exec.LookPath("consul"); err != nil {
		logger.Info("Consul binary not found in PATH")
	} else {
		logger.Info("Consul binary found")
	}
	
	// Check if service is running
	cmd := exec.Command("systemctl", "is-active", "consul")
	if err := cmd.Run(); err != nil {
		logger.Info("Consul service is not active")
	} else {
		logger.Info("Consul service is currently active")
	}
	
	// Check for existing data
	dataDirs := []string{
		"/etc/consul.d",
		"/var/lib/consul",
		"/var/log/consul",
	}
	
	for _, dir := range dataDirs {
		if info, err := os.Stat(dir); err == nil {
			logger.Info("Found Consul directory",
				zap.String("path", dir),
				zap.Bool("is_dir", info.IsDir()))
		}
	}
	
	return nil
}

func stopConsulService(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Stopping Consul service")
	
	// Stop the service
	if err := exec.Command("systemctl", "stop", "consul").Run(); err != nil {
		logger.Warn("Failed to stop Consul service", zap.Error(err))
	}
	
	// Disable the service
	if err := exec.Command("systemctl", "disable", "consul").Run(); err != nil {
		logger.Warn("Failed to disable Consul service", zap.Error(err))
	}
	
	// Kill any remaining consul processes
	if err := exec.Command("pkill", "-f", "consul").Run(); err != nil {
		logger.Debug("No Consul processes to kill", zap.Error(err))
	}
	
	return nil
}

func removeConsulPackage(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Removing Consul package")
	
	// Try to remove via apt
	cmd := exec.Command("apt-get", "remove", "--purge", "-y", "consul")
	if output, err := cmd.CombinedOutput(); err != nil {
		logger.Debug("Package removal output", zap.String("output", string(output)))
		// Package might not be installed via apt, continue
	}
	
	// Remove the binary if it still exists
	consulPaths := []string{
		"/usr/bin/consul",
		"/usr/local/bin/consul",
	}
	
	for _, path := range consulPaths {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			logger.Warn("Failed to remove Consul binary",
				zap.String("path", path),
				zap.Error(err))
		} else if err == nil {
			logger.Info("Removed Consul binary", zap.String("path", path))
		}
	}
	
	return nil
}

func cleanupConsulFiles(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Cleaning up Consul files and directories")
	
	// Directories to remove
	dirsToRemove := []string{
		"/etc/consul.d",
		"/etc/consul",
		"/var/lib/consul",
		"/var/log/consul",
		"/opt/consul",
	}
	
	for _, dir := range dirsToRemove {
		if err := os.RemoveAll(dir); err != nil && !os.IsNotExist(err) {
			logger.Warn("Failed to remove directory",
				zap.String("path", dir),
				zap.Error(err))
		} else if err == nil {
			logger.Info("Removed directory", zap.String("path", dir))
		}
	}
	
	// Remove systemd service files
	serviceFiles := []string{
		"/etc/systemd/system/consul.service",
		"/lib/systemd/system/consul.service",
	}
	
	for _, file := range serviceFiles {
		if err := os.Remove(file); err != nil && !os.IsNotExist(err) {
			logger.Warn("Failed to remove service file",
				zap.String("path", file),
				zap.Error(err))
		} else if err == nil {
			logger.Info("Removed service file", zap.String("path", file))
		}
	}
	
	// Reload systemd
	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		logger.Warn("Failed to reload systemd", zap.Error(err))
	}
	
	// Clean up any consul-related files in home directories
	if err := cleanupHomeDirectories(rc); err != nil {
		logger.Warn("Failed to cleanup home directories", zap.Error(err))
	}
	
	return nil
}

func cleanupHomeDirectories(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Common locations for consul configs in home directories
	homePatterns := []string{
		"/root/.consul",
		"/root/.consul.d",
		"/home/*/.consul",
		"/home/*/.consul.d",
	}
	
	for _, pattern := range homePatterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		
		for _, match := range matches {
			if err := os.RemoveAll(match); err != nil {
				logger.Warn("Failed to remove user consul directory",
					zap.String("path", match),
					zap.Error(err))
			} else {
				logger.Info("Removed user consul directory", zap.String("path", match))
			}
		}
	}
	
	return nil
}

func removeConsulUser(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Removing Consul user and group")
	
	// Remove the consul user (this will also remove the primary group)
	if err := exec.Command("userdel", "-r", "consul").Run(); err != nil {
		logger.Debug("Failed to remove consul user", zap.Error(err))
		// User might not exist, not critical
	}
	
	// Ensure the group is also removed
	if err := exec.Command("groupdel", "consul").Run(); err != nil {
		logger.Debug("Failed to remove consul group", zap.Error(err))
		// Group might not exist or be removed with user, not critical
	}
	
	return nil
}

func verifyConsulRemoval(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Verifying Consul removal")
	
	issues := []string{}
	
	// Check if binary still exists
	if _, err := exec.LookPath("consul"); err == nil {
		issues = append(issues, "Consul binary still exists in PATH")
	}
	
	// Check if service still exists
	cmd := exec.Command("systemctl", "list-unit-files", "consul.service")
	if output, err := cmd.Output(); err == nil && len(output) > 0 {
		issues = append(issues, "Consul service file still exists")
	}
	
	// Check if directories still exist
	dirsToCheck := []string{
		"/etc/consul.d",
		"/var/lib/consul",
		"/var/log/consul",
	}
	
	for _, dir := range dirsToCheck {
		if _, err := os.Stat(dir); err == nil {
			issues = append(issues, fmt.Sprintf("Directory still exists: %s", dir))
		}
	}
	
	// Check if user still exists
	if _, err := exec.Command("id", "consul").Output(); err == nil {
		issues = append(issues, "Consul user still exists")
	}
	
	if len(issues) > 0 {
		logger.Warn("Consul removal verification found issues",
			zap.Strings("issues", issues))
		return fmt.Errorf("removal incomplete: %d issues found", len(issues))
	}
	
	logger.Info("Consul removal verified - all components successfully removed")
	return nil
}