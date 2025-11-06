package terraform

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

// RemoveTerraformCompletely removes Terraform from the system completely
func RemoveTerraformCompletely(rc *eos_io.RuntimeContext, keepData bool) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting comprehensive Terraform removal", zap.Bool("keep_data", keepData))

	// ASSESS - Check current Terraform state
	state := assessTerraformState(rc)
	logger.Info("Terraform assessment completed",
		zap.Bool("binary_exists", state.BinaryExists),
		zap.Bool("config_exists", state.ConfigExists))

	// INTERVENE - Remove Terraform components
	if err := removeTerraformComponents(rc, state, keepData); err != nil {
		return fmt.Errorf("failed to remove Terraform components: %w", err)
	}

	// EVALUATE - Verify removal
	if err := verifyTerraformRemoval(rc); err != nil {
		logger.Warn("Terraform removal verification had issues", zap.Error(err))
		// Don't fail - partial removal is better than none
	}

	logger.Info("Terraform removal completed successfully")
	return nil
}

// TerraformState represents the current state of Terraform installation
type TerraformState struct {
	BinaryExists bool
	ConfigExists bool
}

// assessTerraformState checks the current state of Terraform
func assessTerraformState(rc *eos_io.RuntimeContext) *TerraformState {
	state := &TerraformState{}

	// Check if binary exists
	binaries := GetTerraformBinaries()
	for _, binary := range binaries {
		if _, err := os.Stat(binary); err == nil {
			state.BinaryExists = true
			break
		}
	}

	// Check if config exists
	homeDir, _ := os.UserHomeDir()
	if _, err := os.Stat(filepath.Join(homeDir, ".terraform")); err == nil {
		state.ConfigExists = true
	}
	if _, err := os.Stat(filepath.Join(homeDir, ".terraform.d")); err == nil {
		state.ConfigExists = true
	}

	return state
}

// removeTerraformComponents removes all Terraform components
func removeTerraformComponents(rc *eos_io.RuntimeContext, state *TerraformState, keepData bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Remove binaries
	if state.BinaryExists {
		logger.Info("Removing Terraform binaries")
		for _, binary := range GetTerraformBinaries() {
			if err := os.Remove(binary); err != nil && !os.IsNotExist(err) {
				logger.Debug("Failed to remove binary", zap.String("path", binary), zap.Error(err))
			}
		}
	}

	// Remove directories
	logger.Info("Removing Terraform directories")
	for _, dir := range GetTerraformDirectories() {
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

// verifyTerraformRemoval verifies that Terraform has been removed
func verifyTerraformRemoval(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Verifying Terraform removal")

	var issues []string

	// Check binaries are removed
	for _, binary := range GetTerraformBinaries() {
		if _, err := os.Stat(binary); err == nil {
			issues = append(issues, fmt.Sprintf("binary still exists: %s", binary))
		}
	}

	// Check terraform command doesn't work
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "terraform",
		Args:    []string{"version"},
		Capture: true,
		Timeout: 5 * time.Second,
	})
	if err == nil {
		issues = append(issues, "terraform command still works")
	}

	if len(issues) > 0 {
		return fmt.Errorf("terraform removal incomplete: %v", issues)
	}

	logger.Info("Terraform removal verified successfully")
	return nil
}

// GetTerraformServices returns the list of services managed by Terraform
func GetTerraformServices() []ServiceConfig {
	// Terraform doesn't run as a service
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

// GetTerraformDirectories returns the list of directories managed by Terraform
func GetTerraformDirectories() []DirectoryConfig {
	homeDir, _ := os.UserHomeDir()
	return []DirectoryConfig{
		{
			Path:        filepath.Join(homeDir, ".terraform"),
			Component:   "terraform",
			IsData:      true,
			Description: "Terraform user configuration directory",
		},
		{
			Path:        filepath.Join(homeDir, ".terraform.d"),
			Component:   "terraform",
			IsData:      true,
			Description: "Terraform plugins directory",
		},
		{
			Path:        "/etc/terraform",
			Component:   "terraform",
			IsData:      false,
			Description: "Terraform system configuration directory",
		},
	}
}

// GetTerraformBinaries returns the list of binaries managed by Terraform
func GetTerraformBinaries() []string {
	return []string{
		"/usr/local/bin/terraform",
		"/usr/bin/terraform",
		"/opt/terraform/terraform",
	}
}

// GetTerraformAPTSources returns the list of APT sources managed by Terraform
func GetTerraformAPTSources() []string {
	// Terraform is typically installed via direct download, not APT
	return []string{}
}
