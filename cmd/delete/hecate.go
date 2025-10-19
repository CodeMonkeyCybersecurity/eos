// cmd/delete/hecate.go

package delete

import (
	"fmt"
	"os"
	"os/exec"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/hashicorp/consul/api"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	forceDelete bool
	keepData    bool
)

func init() {
	hecateCmd.Flags().BoolVarP(&forceDelete, "force", "f", false, "Skip confirmation prompts")
	hecateCmd.Flags().BoolVar(&keepData, "keep-data", false, "Keep Consul KV data (only remove containers and files)")
	
	// Register with delete command
	DeleteCmd.AddCommand(hecateCmd)
}

var hecateCmd = &cobra.Command{
	Use:   "hecate",
	Short: "Delete Hecate deployment",
	Long: `Completely removes Hecate deployment including:
  - Docker containers and volumes
  - Configuration files in /opt/hecate
  - Consul KV data (unless --keep-data is specified)

Examples:
  eos delete hecate              # Interactive deletion with confirmation
  eos delete hecate --force      # Skip confirmation prompts
  eos delete hecate --keep-data  # Keep Consul configuration data`,
	RunE: eos.Wrap(runDeleteHecate),
}

func runDeleteHecate(rc *eos_io.RuntimeContext, _ *cobra.Command, _ []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting Hecate deletion process")

	// Confirmation prompt unless --force
	if !forceDelete {
		logger.Info("")
		logger.Info("terminal prompt: ⚠️  WARNING: This will delete:")
		logger.Info("terminal prompt:   - All Docker containers and volumes")
		logger.Info("terminal prompt:   - Configuration files in /opt/hecate")
		if !keepData {
			logger.Info("terminal prompt:   - All Consul KV data (routes, DNS, auth policies, etc.)")
		}
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: Are you sure you want to continue? [y/N]:")

		confirm := interaction.PromptYesNo(rc.Ctx, "Are you sure you want to continue?", false)

		if !confirm {
			logger.Info("Deletion cancelled by user")
			return nil
		}
	}

	// Step 1: Stop and remove Docker containers
	logger.Info("")
	logger.Info("[1/4] Stopping Docker containers...")
	if err := stopDockerContainers(rc); err != nil {
		logger.Warn("Failed to stop containers", zap.Error(err))
		// Continue anyway
	}

	// Step 2: Remove Docker volumes
	logger.Info("[2/4] Removing Docker volumes...")
	if err := removeDockerVolumes(rc); err != nil {
		logger.Warn("Failed to remove volumes", zap.Error(err))
		// Continue anyway
	}

	// Step 3: Clean up Consul KV data
	if !keepData {
		logger.Info("[3/4] Cleaning Consul KV data...")
		if err := cleanConsulData(rc); err != nil {
			logger.Warn("Failed to clean Consul data", zap.Error(err))
			// Continue anyway
		}
	} else {
		logger.Info("[3/4] Skipping Consul KV cleanup (--keep-data specified)")
	}

	// Step 4: Remove files
	logger.Info("[4/4] Removing configuration files...")
	if err := removeHecateFiles(rc); err != nil {
		logger.Warn("Failed to remove files", zap.Error(err))
		// Continue anyway
	}

	logger.Info("")
	logger.Info("terminal prompt: ✓ Hecate deletion completed successfully")
	logger.Info("")

	return nil
}

// stopDockerContainers stops and removes all Hecate containers
func stopDockerContainers(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if docker compose is available
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("docker not found in PATH: %w", err)
	}

	// Check if /opt/hecate exists
	if _, err := os.Stat(hecate.BaseDir); os.IsNotExist(err) {
		logger.Info("Hecate directory not found, skipping container cleanup",
			zap.String("directory", hecate.BaseDir))
		return nil
	}

	// Stop and remove containers
	cmd := exec.Command("docker", "compose", "down", "-v")
	cmd.Dir = hecate.BaseDir
	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Debug("Docker compose down output", zap.String("output", string(output)))
		return fmt.Errorf("failed to stop containers: %w", err)
	}

	logger.Info("Docker containers stopped and removed")
	return nil
}

// removeDockerVolumes removes Hecate Docker volumes
func removeDockerVolumes(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// List of volumes to remove
	volumes := []string{
		"hecate_database",
		"hecate_redis",
		"hecate_caddy_data",
		"hecate_caddy_config",
	}

	for _, volume := range volumes {
		cmd := exec.Command("docker", "volume", "rm", volume)
		if output, err := cmd.CombinedOutput(); err != nil {
			logger.Debug("Failed to remove volume (may not exist)",
				zap.String("volume", volume),
				zap.String("output", string(output)))
		} else {
			logger.Info("Removed Docker volume", zap.String("volume", volume))
		}
	}

	return nil
}

// cleanConsulData removes all Hecate-related data from Consul KV
func cleanConsulData(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Connect to Consul
	config := api.DefaultConfig()
	config.Address = "localhost:8500"
	consulClient, err := api.NewClient(config)
	if err != nil {
		return fmt.Errorf("failed to connect to Consul: %w", err)
	}

	// List of Hecate KV prefixes to delete
	prefixes := []string{
		"hecate/routes/",
		"hecate/dns/",
		"hecate/auth-policies/",
		"hecate/vault-policies/",
		"hecate/streams/",
		"hecate/stream-operations/",
		"hecate/dns-operations/",
		"hecate/dns-reconciler/",
		"hecate/hybrid/",
		"hecate/backends/",
		"hecate/config/",
	}

	for _, prefix := range prefixes {
		_, err := consulClient.KV().DeleteTree(prefix, &api.WriteOptions{})
		if err != nil {
			logger.Warn("Failed to delete Consul KV tree",
				zap.String("prefix", prefix),
				zap.Error(err))
		} else {
			logger.Info("Deleted Consul KV tree", zap.String("prefix", prefix))
		}
	}

	return nil
}

// removeHecateFiles removes all Hecate configuration files
func removeHecateFiles(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if directory exists
	if _, err := os.Stat(hecate.BaseDir); os.IsNotExist(err) {
		logger.Info("Hecate directory not found, nothing to remove",
			zap.String("directory", hecate.BaseDir))
		return nil
	}

	// Remove entire directory
	if err := os.RemoveAll(hecate.BaseDir); err != nil {
		return fmt.Errorf("failed to remove Hecate directory: %w", err)
	}

	logger.Info("Removed Hecate directory", zap.String("directory", hecate.BaseDir))
	return nil
}
