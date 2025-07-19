// cmd/update/storage_cleanup.go

package update

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/environment"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/storage/threshold"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var storageCleanupCmd = &cobra.Command{
	Use:   "storage-cleanup",
	Short: "Clean up storage based on threshold levels",
	Long: `Perform storage cleanup operations at various levels:
- compress: Compress old logs and files
- cleanup: Remove expendable files and caches  
- aggressive: Stop non-critical services and aggressive cleanup
- emergency: Emergency recovery mode to free space immediately`,
	RunE: eos_cli.Wrap(runStorageCleanup),
}

var (
	cleanupLevel string
	cleanupPath  string
	cleanupForce bool
)

func init() {
	UpdateCmd.AddCommand(storageCleanupCmd)
	
	storageCleanupCmd.Flags().StringVar(&cleanupLevel, "level", "cleanup", 
		"Cleanup level: compress, cleanup, aggressive, emergency")
	storageCleanupCmd.Flags().StringVar(&cleanupPath, "path", "/", 
		"Mount point to clean up")
	storageCleanupCmd.Flags().BoolVar(&cleanupForce, "force", false,
		"Force cleanup without confirmation")
}

func runStorageCleanup(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting storage cleanup",
		zap.String("level", cleanupLevel),
		zap.String("path", cleanupPath))
	
	// ASSESS - Validate cleanup level
	var action threshold.Action
	switch strings.ToLower(cleanupLevel) {
	case "compress":
		action = threshold.ActionCompress
	case "cleanup":
		action = threshold.ActionCleanup
	case "aggressive", "degrade":
		action = threshold.ActionDegrade
	case "emergency":
		action = threshold.ActionEmergency
	default:
		return fmt.Errorf("invalid cleanup level: %s", cleanupLevel)
	}
	
	// Detect environment for context
	env, err := environment.Detect(rc)
	if err != nil {
		logger.Warn("Failed to detect environment, continuing with defaults", zap.Error(err))
	} else {
		logger.Info("Environment context",
			zap.String("scale", string(env.GetScale())),
			zap.String("role", string(env.MyRole)))
	}
	
	// Confirm with user unless forced
	if !cleanupForce && (action == threshold.ActionDegrade || action == threshold.ActionEmergency) {
		logger.Info("terminal prompt: This will perform aggressive cleanup and may stop services. Continue? (y/N)")
		
		response, err := eos_io.PromptInput(rc, "Continue?", "y/N")
		if err != nil {
			return fmt.Errorf("failed to read user response: %w", err)
		}
		
		if !strings.HasPrefix(strings.ToLower(response), "y") {
			logger.Info("Cleanup cancelled by user")
			return nil
		}
	}
	
	// INTERVENE - Execute cleanup
	executor := threshold.NewActionExecutor(rc)
	
	logger.Info("Executing cleanup action",
		zap.String("action", string(action)),
		zap.String("description", threshold.GetActionDescription(action)))
	
	if err := executor.Execute(action, cleanupPath); err != nil {
		return fmt.Errorf("cleanup failed: %w", err)
	}
	
	// EVALUATE - Check results
	logger.Info("Cleanup completed successfully",
		zap.String("level", cleanupLevel),
		zap.String("path", cleanupPath))
	
	// TODO: Show before/after disk usage
	
	return nil
}