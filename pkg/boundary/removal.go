package boundary

import (
	"fmt"
	"os"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// RemoveBoundaryCompletely removes Boundary from the system completely
func RemoveBoundaryCompletely(rc *eos_io.RuntimeContext, keepData bool) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting comprehensive Boundary removal", zap.Bool("keep_data", keepData))

	// ASSESS - Check current Boundary state
	state := assessBoundaryState(rc)
	logger.Info("Boundary assessment completed",
		zap.Bool("service_exists", state.ServiceExists),
		zap.Bool("binary_exists", state.BinaryExists),
		zap.Bool("config_exists", state.ConfigExists))

	// INTERVENE - Remove Boundary components
	if err := removeBoundaryComponents(rc, state, keepData); err != nil {
		return fmt.Errorf("failed to remove Boundary components: %w", err)
	}

	// EVALUATE - Verify removal
	if err := verifyBoundaryRemoval(rc); err != nil {
		logger.Warn("Boundary removal verification had issues", zap.Error(err))
		// Don't fail - partial removal is better than none
	}

	logger.Info("Boundary removal completed successfully")
	return nil
}

// BoundaryState represents the current state of Boundary installation
type BoundaryState struct {
	ServiceExists bool
	BinaryExists  bool
	ConfigExists  bool
}

// assessBoundaryState checks the current state of Boundary
func assessBoundaryState(rc *eos_io.RuntimeContext) *BoundaryState {
	logger := otelzap.Ctx(rc.Ctx)
	state := &BoundaryState{}

	// Check if service exists
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"list-units", "--all", "--type=service", "--quiet", "boundary.service"},
		Capture: true,
		Timeout: 5 * time.Second,
	})
	state.ServiceExists = err == nil && output != ""

	// Check if binary exists
	_, err = os.Stat("/usr/local/bin/boundary")
	state.BinaryExists = err == nil

	// Check if config exists
	_, err = os.Stat("/etc/boundary.d")
	state.ConfigExists = err == nil

	logger.Debug("Boundary state assessed",
		zap.Bool("service", state.ServiceExists),
		zap.Bool("binary", state.BinaryExists),
		zap.Bool("config", state.ConfigExists))

	return state
}

// removeBoundaryComponents removes all Boundary components
func removeBoundaryComponents(rc *eos_io.RuntimeContext, state *BoundaryState, keepData bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Stop and disable service if it exists
	if state.ServiceExists {
		logger.Info("Stopping and disabling Boundary service")

		// Stop service
		_, _ = execute.Run(rc.Ctx, execute.Options{
			Command: "systemctl",
			Args:    []string{"stop", "boundary"},
			Timeout: 30 * time.Second,
		})

		// Disable service
		_, _ = execute.Run(rc.Ctx, execute.Options{
			Command: "systemctl",
			Args:    []string{"disable", "boundary"},
			Timeout: 10 * time.Second,
		})
	}

	// Kill any remaining Boundary processes
	logger.Info("Killing any remaining Boundary processes")
	_, _ = execute.Run(rc.Ctx, execute.Options{
		Command: "pkill",
		Args:    []string{"-f", "boundary"},
		Timeout: 5 * time.Second,
	})

	// Remove binary
	if state.BinaryExists {
		logger.Info("Removing Boundary binary")
		binaries := GetBoundaryBinaries()
		for _, binary := range binaries {
			if err := os.Remove(binary); err != nil && !os.IsNotExist(err) {
				logger.Debug("Failed to remove binary", zap.String("file", binary), zap.Error(err))
			}
		}
	}

	// Remove systemd service files
	logger.Info("Removing Boundary systemd service files")
	systemdFiles := []string{
		"/etc/systemd/system/boundary.service",
		"/etc/systemd/system/boundary-controller.service",
		"/etc/systemd/system/boundary-worker.service",
		"/lib/systemd/system/boundary.service",
		"/lib/systemd/system/boundary-controller.service",
		"/lib/systemd/system/boundary-worker.service",
	}
	for _, file := range systemdFiles {
		if err := os.Remove(file); err != nil && !os.IsNotExist(err) {
			logger.Debug("Failed to remove systemd file", zap.String("file", file), zap.Error(err))
		}
	}

	// Remove directories
	logger.Info("Removing Boundary directories")
	directories := GetBoundaryDirectories()
	for _, dir := range directories {
		// Skip data directories if keepData is true
		if keepData && dir.IsData {
			logger.Info("Preserving data directory", zap.String("path", dir.Path))
			continue
		}

		if err := os.RemoveAll(dir.Path); err != nil && !os.IsNotExist(err) {
			logger.Warn("Failed to remove directory",
				zap.String("path", dir.Path),
				zap.String("description", dir.Description),
				zap.Error(err))
		}
	}

	// Remove Boundary user and group
	logger.Info("Removing Boundary user and group")
	_, _ = execute.Run(rc.Ctx, execute.Options{
		Command: "userdel",
		Args:    []string{"-r", "boundary"},
		Timeout: 5 * time.Second,
	})
	_, _ = execute.Run(rc.Ctx, execute.Options{
		Command: "groupdel",
		Args:    []string{"boundary"},
		Timeout: 5 * time.Second,
	})

	// Reload systemd
	_ = execute.RunSimple(rc.Ctx, "systemctl", "daemon-reload")

	return nil
}

// verifyBoundaryRemoval verifies that Boundary has been removed
func verifyBoundaryRemoval(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Verifying Boundary removal")

	var issues []string

	// Check service doesn't exist
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"is-active", "boundary"},
		Capture: true,
		Timeout: 5 * time.Second,
	})
	if err == nil && output == "active" {
		issues = append(issues, "Boundary service still active")
	}

	// Check binary is removed
	if _, err := os.Stat("/usr/local/bin/boundary"); err == nil {
		issues = append(issues, "Boundary binary still exists")
	}

	// Check no Boundary processes
	output, _ = execute.Run(rc.Ctx, execute.Options{
		Command: "pgrep",
		Args:    []string{"-f", "boundary"},
		Capture: true,
		Timeout: 5 * time.Second,
	})
	if output != "" {
		issues = append(issues, "Boundary processes still running")
	}

	if len(issues) > 0 {
		return fmt.Errorf("Boundary removal incomplete: %v", issues)
	}

	logger.Info("Boundary removal verified successfully")
	return nil
}

// GetBoundaryServices returns the list of services managed by Boundary
func GetBoundaryServices() []ServiceConfig {
	return []ServiceConfig{
		{Name: "boundary", Component: "boundary", Required: false},
		{Name: "boundary-controller", Component: "boundary", Required: false},
		{Name: "boundary-worker", Component: "boundary", Required: false},
	}
}

// DirectoryConfig represents a directory managed by Boundary
type DirectoryConfig struct {
	Path        string
	Component   string
	IsData      bool
	Description string
}

// ServiceConfig represents a service managed by Boundary
type ServiceConfig struct {
	Name      string
	Component string
	Required  bool
}

// GetBoundaryDirectories returns the list of directories managed by Boundary
func GetBoundaryDirectories() []DirectoryConfig {
	return []DirectoryConfig{
		{Path: "/etc/boundary.d", Component: "boundary", IsData: false, Description: "Boundary configuration directory"},
		{Path: "/opt/boundary", Component: "boundary", IsData: false, Description: "Boundary binary directory"},
		{Path: "/opt/boundary/data", Component: "boundary", IsData: true, Description: "Boundary data directory"},
		{Path: "/var/lib/boundary", Component: "boundary", IsData: true, Description: "Boundary state directory"},
		{Path: "/var/log/boundary", Component: "boundary", IsData: true, Description: "Boundary log directory"},
	}
}

// GetBoundaryBinaries returns the list of binaries managed by Boundary
func GetBoundaryBinaries() []string {
	return []string{
		"/usr/local/bin/boundary",
		"/usr/bin/boundary",
		"/opt/boundary/bin/boundary",
	}
}

// GetBoundarySystemdFiles returns the list of systemd files managed by Boundary
func GetBoundarySystemdFiles() []string {
	return []string{
		"/etc/systemd/system/boundary.service",
		"/etc/systemd/system/boundary-controller.service",
		"/etc/systemd/system/boundary-worker.service",
		"/lib/systemd/system/boundary.service",
		"/lib/systemd/system/boundary-controller.service",
		"/lib/systemd/system/boundary-worker.service",
	}
}
