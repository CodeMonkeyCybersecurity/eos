package osquery

import (
	"fmt"
	"os"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// RemoveOsqueryCompletely removes osquery from the system completely
func RemoveOsqueryCompletely(rc *eos_io.RuntimeContext, keepData bool) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting comprehensive osquery removal", zap.Bool("keep_data", keepData))

	// ASSESS - Check current osquery state
	state := assessOsqueryState(rc)
	logger.Info("Osquery assessment completed",
		zap.Bool("service_exists", state.ServiceExists),
		zap.Bool("package_installed", state.PackageInstalled),
		zap.Bool("binary_exists", state.BinaryExists))

	// INTERVENE - Remove osquery components
	if err := removeOsqueryComponents(rc, state, keepData); err != nil {
		return fmt.Errorf("failed to remove osquery components: %w", err)
	}

	// EVALUATE - Verify removal
	if err := verifyOsqueryRemoval(rc); err != nil {
		logger.Warn("Osquery removal verification had issues", zap.Error(err))
		// Don't fail - partial removal is better than none
	}

	logger.Info("Osquery removal completed successfully")
	return nil
}

// OsqueryState represents the current state of osquery installation
type OsqueryState struct {
	ServiceExists    bool
	PackageInstalled bool
	BinaryExists     bool
	ConfigExists     bool
}

// assessOsqueryState checks the current state of osquery
func assessOsqueryState(rc *eos_io.RuntimeContext) *OsqueryState {
	logger := otelzap.Ctx(rc.Ctx)
	state := &OsqueryState{}

	// Check if service exists
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"list-units", "--all", "--type=service", "--quiet", "osqueryd.service"},
		Capture: true,
		Timeout: 5 * time.Second,
	})
	state.ServiceExists = err == nil && output != ""

	// Check if package is installed
	output, err = execute.Run(rc.Ctx, execute.Options{
		Command: "dpkg",
		Args:    []string{"-l", "osquery"},
		Capture: true,
		Timeout: 5 * time.Second,
	})
	state.PackageInstalled = err == nil && output != ""

	// Check if binary exists
	_, err = os.Stat("/usr/bin/osqueryd")
	state.BinaryExists = err == nil
	if !state.BinaryExists {
		_, err = os.Stat("/usr/local/bin/osqueryd")
		state.BinaryExists = err == nil
	}

	// Check if config exists
	_, err = os.Stat("/etc/osquery")
	state.ConfigExists = err == nil

	logger.Debug("Osquery state assessed",
		zap.Bool("service", state.ServiceExists),
		zap.Bool("package", state.PackageInstalled),
		zap.Bool("binary", state.BinaryExists),
		zap.Bool("config", state.ConfigExists))

	return state
}

// removeOsqueryComponents removes all osquery components
func removeOsqueryComponents(rc *eos_io.RuntimeContext, state *OsqueryState, keepData bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Stop and disable service if it exists
	if state.ServiceExists {
		logger.Info("Stopping and disabling osqueryd service")

		// Stop service
		_, _ = execute.Run(rc.Ctx, execute.Options{
			Command: "systemctl",
			Args:    []string{"stop", "osqueryd"},
			Timeout: 30 * time.Second,
		})

		// Disable service
		_, _ = execute.Run(rc.Ctx, execute.Options{
			Command: "systemctl",
			Args:    []string{"disable", "osqueryd"},
			Timeout: 10 * time.Second,
		})
	}

	// Kill any remaining osquery processes
	logger.Info("Killing any remaining osquery processes")
	_, _ = execute.Run(rc.Ctx, execute.Options{
		Command: "pkill",
		Args:    []string{"-f", "osqueryd"},
		Timeout: 5 * time.Second,
	})

	// Remove package if installed
	if state.PackageInstalled {
		logger.Info("Removing osquery package")
		if err := execute.RunSimple(rc.Ctx, "apt-get", "remove", "-y", "osquery"); err != nil {
			logger.Warn("Failed to remove osquery package", zap.Error(err))
		}

		// Purge configuration
		if !keepData {
			_ = execute.RunSimple(rc.Ctx, "apt-get", "purge", "-y", "osquery")
		}
	}

	// Remove APT sources
	logger.Info("Removing osquery APT sources")
	aptSources := []string{
		"/etc/apt/sources.list.d/osquery.list",
		"/etc/apt/sources.list.d/deb_osquery_io_deb.list",
	}
	for _, source := range aptSources {
		if err := os.Remove(source); err != nil && !os.IsNotExist(err) {
			logger.Debug("Failed to remove APT source", zap.String("file", source), zap.Error(err))
		}
	}

	// Remove GPG key
	gpgKeys := []string{
		"/usr/share/keyrings/osquery.asc",
		"/etc/apt/keyrings/osquery.asc",
	}
	for _, key := range gpgKeys {
		if err := os.Remove(key); err != nil && !os.IsNotExist(err) {
			logger.Debug("Failed to remove GPG key", zap.String("file", key), zap.Error(err))
		}
	}

	// Remove binaries if they exist
	logger.Info("Removing osquery binaries")
	binaries := []string{
		"/usr/bin/osqueryd",
		"/usr/bin/osqueryi",
		"/usr/bin/osqueryctl",
		"/usr/local/bin/osqueryd",
		"/usr/local/bin/osqueryi",
		"/usr/local/bin/osqueryctl",
	}
	for _, binary := range binaries {
		if err := os.Remove(binary); err != nil && !os.IsNotExist(err) {
			logger.Debug("Failed to remove binary", zap.String("file", binary), zap.Error(err))
		}
	}

	// Remove directories
	logger.Info("Removing osquery directories")
	directories := GetOsqueryDirectories()
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

	// Remove systemd service files
	systemdFiles := []string{
		"/etc/systemd/system/osqueryd.service",
		"/lib/systemd/system/osqueryd.service",
	}
	for _, file := range systemdFiles {
		if err := os.Remove(file); err != nil && !os.IsNotExist(err) {
			logger.Debug("Failed to remove systemd file", zap.String("file", file), zap.Error(err))
		}
	}

	// Reload systemd
	_ = execute.RunSimple(rc.Ctx, "systemctl", "daemon-reload")

	// Update APT cache
	logger.Info("Updating APT cache")
	_ = execute.RunSimple(rc.Ctx, "apt-get", "update")

	return nil
}

// verifyOsqueryRemoval verifies that osquery has been removed
func verifyOsqueryRemoval(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Verifying osquery removal")

	var issues []string

	// Check service doesn't exist
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"is-active", "osqueryd"},
		Capture: true,
		Timeout: 5 * time.Second,
	})
	if err == nil && output == "active" {
		issues = append(issues, "osqueryd service still active")
	}

	// Check package is removed
	output, err = execute.Run(rc.Ctx, execute.Options{
		Command: "dpkg",
		Args:    []string{"-l", "osquery"},
		Capture: true,
		Timeout: 5 * time.Second,
	})
	if err == nil && output != "" {
		// Check if it's in removed state
		if !contains(output, "rc ") && !contains(output, "rn ") {
			issues = append(issues, "osquery package still installed")
		}
	}

	// Check binaries are removed
	binaries := []string{"/usr/bin/osqueryd", "/usr/local/bin/osqueryd"}
	for _, binary := range binaries {
		if _, err := os.Stat(binary); err == nil {
			issues = append(issues, fmt.Sprintf("binary still exists: %s", binary))
		}
	}

	// Check no osquery processes
	output, _ = execute.Run(rc.Ctx, execute.Options{
		Command: "pgrep",
		Args:    []string{"-f", "osqueryd"},
		Capture: true,
		Timeout: 5 * time.Second,
	})
	if output != "" {
		issues = append(issues, "osquery processes still running")
	}

	if len(issues) > 0 {
		return fmt.Errorf("osquery removal incomplete: %v", issues)
	}

	logger.Info("Osquery removal verified successfully")
	return nil
}

// GetOsqueryServices returns the list of services managed by osquery
func GetOsqueryServices() []ServiceConfig {
	return []ServiceConfig{
		{Name: "osqueryd", Component: "osquery", Required: false},
	}
}

// DirectoryConfig represents a directory managed by osquery
type DirectoryConfig struct {
	Path        string
	Component   string
	IsData      bool
	Description string
}

// ServiceConfig represents a service managed by osquery
type ServiceConfig struct {
	Name      string
	Component string
	Required  bool
}

// GetOsqueryDirectories returns the list of directories managed by osquery
func GetOsqueryDirectories() []DirectoryConfig {
	return []DirectoryConfig{
		{Path: "/etc/osquery", Component: "osquery", IsData: false, Description: "Osquery configuration directory"},
		{Path: "/var/log/osquery", Component: "osquery", IsData: true, Description: "Osquery log directory"},
		{Path: "/var/osquery", Component: "osquery", IsData: true, Description: "Osquery data directory"},
		{Path: "/usr/share/osquery", Component: "osquery", IsData: false, Description: "Osquery packs directory"},
	}
}

// GetOsqueryBinaries returns the list of binaries managed by osquery
func GetOsqueryBinaries() []string {
	return []string{
		"/usr/bin/osqueryd",
		"/usr/bin/osqueryi",
		"/usr/bin/osqueryctl",
		"/usr/local/bin/osqueryd",
		"/usr/local/bin/osqueryi",
		"/usr/local/bin/osqueryctl",
	}
}

// GetOsqueryAPTSources returns the list of APT sources managed by osquery
func GetOsqueryAPTSources() []string {
	return []string{
		"/etc/apt/sources.list.d/osquery.list",
		"/etc/apt/sources.list.d/deb_osquery_io_deb.list",
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && (s == substr || len(s) > len(substr) && (s[0:len(substr)] == substr || s[len(s)-len(substr):] == substr || len(s) > len(substr) && contains(s[1:len(s)-1], substr)))
}
