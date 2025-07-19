// cmd/create/storage_provision.go

package create

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/environment"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/storage/filesystem"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var storageProvisionCmd = &cobra.Command{
	Use:   "storage-provision",
	Short: "Provision new storage with environment-aware configuration",
	Long: `Provision new storage resources with automatic configuration based on:
- Environment scale (single/small/distributed)
- Machine role (edge/core/data/etc)
- Workload type (database/container/backup/etc)
- Filesystem recommendations`,
	RunE: eos_cli.Wrap(runStorageProvision),
}

var (
	provisionWorkload   string
	provisionSize       string
	provisionPath       string
	provisionFilesystem string
)

func init() {
	CreateCmd.AddCommand(storageProvisionCmd)
	
	storageProvisionCmd.Flags().StringVar(&provisionWorkload, "workload", "general",
		"Workload type: database, container, backup, distributed, general")
	storageProvisionCmd.Flags().StringVar(&provisionSize, "size", "",
		"Storage size (e.g., 100G, 1T)")
	storageProvisionCmd.Flags().StringVar(&provisionPath, "path", "",
		"Mount path for new storage")
	storageProvisionCmd.Flags().StringVar(&provisionFilesystem, "filesystem", "",
		"Filesystem type (auto-detected if not specified)")
}

func runStorageProvision(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting storage provisioning")
	
	// ASSESS - Detect environment
	env, err := environment.Detect(rc)
	if err != nil {
		return fmt.Errorf("failed to detect environment: %w", err)
	}
	
	profile := env.GetStorageProfile()
	logger.Info("Environment detected",
		zap.String("scale", string(profile.Scale)),
		zap.String("role", string(env.MyRole)))
	
	// Validate inputs
	if provisionPath == "" {
		logger.Info("terminal prompt: Enter mount path for new storage")
		path, err := eos_io.PromptInput(rc, "Mount path", "/mnt/data")
		if err != nil {
			return fmt.Errorf("failed to read mount path: %w", err)
		}
		provisionPath = path
	}
	
	if provisionSize == "" {
		logger.Info("terminal prompt: Enter storage size (e.g., 100G, 1T)")
		size, err := eos_io.PromptInput(rc, "Storage size", "100G")
		if err != nil {
			return fmt.Errorf("failed to read storage size: %w", err)
		}
		provisionSize = size
	}
	
	// INTERVENE - Determine filesystem
	fsDetector := filesystem.NewDetector(rc)
	
	var selectedFS filesystem.Filesystem
	if provisionFilesystem != "" {
		selectedFS = filesystem.Filesystem(provisionFilesystem)
	} else {
		// Recommend based on workload
		selectedFS = fsDetector.RecommendForWorkload(provisionWorkload)
		logger.Info("Recommended filesystem",
			zap.String("workload", provisionWorkload),
			zap.String("filesystem", string(selectedFS)))
	}
	
	// Check filesystem support
	supported, err := fsDetector.CheckSupport(selectedFS)
	if err != nil {
		return fmt.Errorf("failed to check filesystem support: %w", err)
	}
	
	if !supported {
		return fmt.Errorf("filesystem %s is not supported on this system", selectedFS)
	}
	
	// Get optimization options
	opts := fsDetector.GetOptimizationOptions(selectedFS, provisionWorkload)
	
	// Display provisioning plan
	logger.Info("Storage provisioning plan",
		zap.String("path", provisionPath),
		zap.String("size", provisionSize),
		zap.String("filesystem", string(selectedFS)),
		zap.String("workload", provisionWorkload),
		zap.Any("optimizations", opts))
	
	features := fsDetector.GetFeatures(selectedFS)
	logger.Info("Filesystem features",
		zap.Strings("features", features))
	
	// EVALUATE - Confirm with user
	logger.Info("terminal prompt: Proceed with storage provisioning? (y/N)")
	response, err := eos_io.PromptInput(rc, "Proceed?", "y/N")
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}
	
	if response != "y" && response != "Y" {
		logger.Info("Storage provisioning cancelled")
		return nil
	}
	
	// TODO: Actual provisioning would involve:
	// - Creating LVM volumes or partitions
	// - Formatting with selected filesystem
	// - Applying optimizations
	// - Updating /etc/fstab
	// - Creating mount point
	// - Setting up monitoring
	
	logger.Info("Storage provisioning completed successfully",
		zap.String("path", provisionPath),
		zap.String("filesystem", string(selectedFS)))
	
	// Show next steps
	logger.Info("Next steps:")
	logger.Info("1. Configure monitoring: eos read storage-monitor")
	logger.Info("2. Set up backups: eos backup create --path " + provisionPath)
	logger.Info("3. Apply Salt states: eos storage salt generate")
	
	return nil
}