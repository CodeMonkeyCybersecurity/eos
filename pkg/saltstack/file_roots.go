package saltstack

import (
	"fmt"
	"os"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// SetupFileRoots configures Salt file_roots for eos state management
// This integrates the functionality from setup-salt-file-roots.sh
func SetupFileRoots(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Setting up Salt file_roots configuration for eos")
	
	// ASSESS - Check if we have root privileges
	if os.Geteuid() != 0 {
		return fmt.Errorf("file_roots setup requires root privileges")
	}
	
	// INTERVENE - Create necessary directories and symlinks
	if err := createSaltDirectories(rc); err != nil {
		return fmt.Errorf("failed to create Salt directories: %w", err)
	}
	
	if err := createStateSymlinks(rc); err != nil {
		return fmt.Errorf("failed to create state symlinks: %w", err)
	}
	
	// EVALUATE - Verify setup
	if err := verifyFileRootsSetup(rc); err != nil {
		return fmt.Errorf("file_roots setup verification failed: %w", err)
	}
	
	logger.Info("Salt file_roots setup completed successfully")
	return nil
}

// createSaltDirectories creates the necessary Salt directories
func createSaltDirectories(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	directories := []string{
		"/srv/salt",
		"/srv/salt/eos",
		"/srv/pillar",
	}
	
	for _, dir := range directories {
		logger.Debug("Creating directory", zap.String("path", dir))
		
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
		
		logger.Debug("Directory created successfully", zap.String("path", dir))
	}
	
	return nil
}

// createStateSymlinks creates symbolic links from /srv/salt to eos Salt states
func createStateSymlinks(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Define symlinks to create
	symlinks := map[string]string{
		"/srv/salt/hashicorp": "/opt/eos/salt/states/hashicorp",
		"/srv/salt/minio":     "/opt/eos/salt/states/minio", 
		"/srv/salt/states":    "/opt/eos/salt/states",
		"/srv/salt/dependencies": "/opt/eos/salt/states/dependencies.sls",
	}
	
	for linkPath, targetPath := range symlinks {
		logger.Debug("Creating symlink", 
			zap.String("link", linkPath),
			zap.String("target", targetPath))
		
		// Check if target exists
		if _, err := os.Stat(targetPath); os.IsNotExist(err) {
			logger.Warn("Target path does not exist, skipping symlink",
				zap.String("target", targetPath))
			continue
		}
		
		// Check if symlink already exists and is correct
		if existingTarget, err := os.Readlink(linkPath); err == nil {
			if existingTarget == targetPath {
				logger.Debug("Symlink already exists and is correct", 
					zap.String("link", linkPath))
				continue
			} else {
				logger.Info("Updating existing symlink",
					zap.String("link", linkPath),
					zap.String("old_target", existingTarget),
					zap.String("new_target", targetPath))
				// Remove existing symlink
				os.Remove(linkPath)
			}
		} else if _, err := os.Stat(linkPath); err == nil {
			// Path exists but is not a symlink
			logger.Warn("Path exists but is not a symlink, removing",
				zap.String("path", linkPath))
			os.RemoveAll(linkPath)
		}
		
		// Create the symlink
		if err := os.Symlink(targetPath, linkPath); err != nil {
			return fmt.Errorf("failed to create symlink %s -> %s: %w", 
				linkPath, targetPath, err)
		}
		
		logger.Info("Symlink created successfully",
			zap.String("link", linkPath),
			zap.String("target", targetPath))
	}
	
	return nil
}

// verifyFileRootsSetup verifies that the file_roots setup is working correctly
func verifyFileRootsSetup(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Verifying Salt file_roots setup")
	
	// Check that required paths exist
	requiredPaths := []string{
		"/srv/salt",
		"/srv/salt/hashicorp",
		"/srv/salt/states",
		"/srv/pillar",
	}
	
	for _, path := range requiredPaths {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return fmt.Errorf("required path does not exist: %s", path)
		}
		logger.Debug("Required path exists", zap.String("path", path))
	}
	
	// Test Salt state accessibility if Salt is installed
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "which",
		Args:    []string{"salt-call"},
		Capture: true,
	}); err == nil {
		logger.Info("Salt is installed, testing state accessibility")
		
		if err := testStateAccessibility(rc); err != nil {
			logger.Warn("State accessibility test failed", zap.Error(err))
			// Don't fail the setup - Salt configuration might not be complete yet
		} else {
			logger.Info("Salt states are accessible")
		}
	} else {
		logger.Debug("Salt not yet installed, skipping state accessibility test")
	}
	
	logger.Info("File_roots setup verification completed successfully")
	return nil
}

// testStateAccessibility tests if Salt states are accessible
func testStateAccessibility(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	testStates := []string{
		"dependencies",
		"hashicorp.vault.install",
		"hashicorp.vault.eos_complete",
	}
	
	for _, state := range testStates {
		logger.Debug("Testing state accessibility", zap.String("state", state))
		
		output, err := execute.Run(rc.Ctx, execute.Options{
			Command: "salt-call",
			Args:    []string{"--local", "state.show_sls", state},
			Capture: true,
		})
		
		if err != nil {
			logger.Debug("State not accessible", 
				zap.String("state", state),
				zap.Error(err))
			return fmt.Errorf("state %s not accessible: %w", state, err)
		}
		
		logger.Debug("State accessible", 
			zap.String("state", state),
			zap.Int("output_length", len(output)))
	}
	
	return nil
}

// GetFileRootsStatus returns the current status of file_roots setup
func GetFileRootsStatus(rc *eos_io.RuntimeContext) (map[string]interface{}, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	status := make(map[string]interface{})
	
	// Check directories
	directories := []string{
		"/srv/salt",
		"/srv/salt/eos", 
		"/srv/pillar",
	}
	
	dirStatus := make(map[string]bool)
	for _, dir := range directories {
		if _, err := os.Stat(dir); err == nil {
			dirStatus[dir] = true
		} else {
			dirStatus[dir] = false
		}
	}
	status["directories"] = dirStatus
	
	// Check symlinks
	symlinks := map[string]string{
		"/srv/salt/hashicorp": "/opt/eos/salt/states/hashicorp",
		"/srv/salt/minio":     "/opt/eos/salt/states/minio",
		"/srv/salt/states":    "/opt/eos/salt/states",
	}
	
	symlinkStatus := make(map[string]interface{})
	for linkPath, expectedTarget := range symlinks {
		linkInfo := make(map[string]interface{})
		
		if target, err := os.Readlink(linkPath); err == nil {
			linkInfo["exists"] = true
			linkInfo["target"] = target
			linkInfo["correct"] = target == expectedTarget
		} else {
			linkInfo["exists"] = false
			linkInfo["target"] = nil
			linkInfo["correct"] = false
		}
		
		symlinkStatus[linkPath] = linkInfo
	}
	status["symlinks"] = symlinkStatus
	
	// Check Salt availability
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "which",
		Args:    []string{"salt-call"},
		Capture: true,
	}); err == nil {
		status["salt_available"] = true
		
		// Test state accessibility
		if testStateAccessibility(rc) == nil {
			status["states_accessible"] = true
		} else {
			status["states_accessible"] = false
		}
	} else {
		status["salt_available"] = false
		status["states_accessible"] = false
	}
	
	logger.Debug("File_roots status check completed", zap.Any("status", status))
	return status, nil
}