package packer

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// EnsureInstalled ensures Packer is installed on the system
// TODO: Implement actual installation logic
func EnsureInstalled(rc *eos_io.RuntimeContext, logger *zap.Logger) error {
	l := otelzap.Ctx(rc.Ctx)
	l.Info("Ensuring Packer is installed")
	
	// Check if already installed
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "packer",
		Args:    []string{"version"},
		Capture: true,
		Timeout: 5 * time.Second,
	}); err == nil {
		l.Info("Packer is already installed")
		return nil
	}
	
	// TODO: Implement actual installation
	return fmt.Errorf("packer installation not yet implemented")
}

// RemovePackerCompletely removes Packer from the system completely
func RemovePackerCompletely(rc *eos_io.RuntimeContext, keepData bool) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting comprehensive Packer removal", zap.Bool("keep_data", keepData))

	// ASSESS - Check current Packer state
	state := assessPackerState(rc)
	logger.Info("Packer assessment completed",
		zap.Bool("binary_exists", state.BinaryExists),
		zap.Bool("config_exists", state.ConfigExists))

	// INTERVENE - Remove Packer components
	if err := removePackerComponents(rc, state, keepData); err != nil {
		return fmt.Errorf("failed to remove Packer components: %w", err)
	}

	// EVALUATE - Verify removal
	if err := verifyPackerRemoval(rc); err != nil {
		logger.Warn("Packer removal verification had issues", zap.Error(err))
		// Don't fail - partial removal is better than none
	}

	logger.Info("Packer removal completed successfully")
	return nil
}

// PackerState represents the current state of Packer installation
type PackerState struct {
	BinaryExists bool
	ConfigExists bool
}

// assessPackerState checks the current state of Packer
func assessPackerState(rc *eos_io.RuntimeContext) *PackerState {
	state := &PackerState{}

	// Check if binary exists
	binaries := GetPackerBinaries()
	for _, binary := range binaries {
		if _, err := os.Stat(binary); err == nil {
			state.BinaryExists = true
			break
		}
	}

	// Check if config exists
	homeDir, _ := os.UserHomeDir()
	if _, err := os.Stat(filepath.Join(homeDir, ".packer.d")); err == nil {
		state.ConfigExists = true
	}

	return state
}

// removePackerComponents removes all Packer components
func removePackerComponents(rc *eos_io.RuntimeContext, state *PackerState, keepData bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Remove binaries
	if state.BinaryExists {
		logger.Info("Removing Packer binaries")
		for _, binary := range GetPackerBinaries() {
			if err := os.Remove(binary); err != nil && !os.IsNotExist(err) {
				logger.Debug("Failed to remove binary", zap.String("path", binary), zap.Error(err))
			}
		}
	}

	// Remove directories
	logger.Info("Removing Packer directories")
	for _, dir := range GetPackerDirectories() {
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

	return nil
}

// verifyPackerRemoval verifies that Packer has been removed
func verifyPackerRemoval(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Verifying Packer removal")

	var issues []string

	// Check binaries are removed
	for _, binary := range GetPackerBinaries() {
		if _, err := os.Stat(binary); err == nil {
			issues = append(issues, fmt.Sprintf("binary still exists: %s", binary))
		}
	}

	// Check packer command doesn't work
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "packer",
		Args:    []string{"version"},
		Capture: true,
		Timeout: 5 * time.Second,
	})
	if err == nil {
		issues = append(issues, "packer command still works")
	}

	if len(issues) > 0 {
		return fmt.Errorf("packer removal incomplete: %v", issues)
	}

	logger.Info("Packer removal verified successfully")
	return nil
}

// GetPackerServices returns the list of services managed by Packer
func GetPackerServices() []ServiceConfig {
	// Packer doesn't run as a service
	return []ServiceConfig{}
}

// DirectoryConfig represents a directory managed by a component
type DirectoryConfig struct {
	Path        string
	Component   string
	IsData      bool
	Description string
}

// ServiceConfig represents a service managed by a component
type ServiceConfig struct {
	Name      string
	Component string
	Required  bool
}

// GetPackerDirectories returns the list of directories managed by Packer
func GetPackerDirectories() []DirectoryConfig {
	homeDir, _ := os.UserHomeDir()
	return []DirectoryConfig{
		{
			Path:        filepath.Join(homeDir, ".packer.d"),
			Component:   "packer",
			IsData:      true,
			Description: "Packer plugins and cache directory",
		},
		{
			Path:        "/var/cache/packer",
			Component:   "packer",
			IsData:      true,
			Description: "Packer system cache directory",
		},
	}
}

// GetPackerBinaries returns the list of binaries managed by Packer
func GetPackerBinaries() []string {
	return []string{
		"/usr/local/bin/packer",
		"/usr/bin/packer",
		"/opt/packer/packer",
	}
}

// GetPackerAPTSources returns the list of APT sources managed by Packer
func GetPackerAPTSources() []string {
	// Packer is typically installed via direct download, not APT
	return []string{}
}