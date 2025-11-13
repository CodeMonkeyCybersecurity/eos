package rollback

import (
	"fmt"
	"strings"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/storage"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/verify"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Command flags
var (
	rollbackDryRun   bool
	forceRollback    bool
	showPlan         bool
	skipConfirmation bool
)

// DiskOperationCmd handles rollback of disk operations
var DiskOperationCmd = &cobra.Command{
	Use:   "disk-operation [journal-id]",
	Short: "Rollback a disk operation using its journal ID",
	Long: `Rollback a disk operation using available recovery methods.

This command will attempt to rollback a disk operation using:
1. LVM snapshots (if available) - Fastest and safest method
2. Reverse operations - For simple operations like LV creation
3. Manual instructions - When automatic rollback isn't possible

The rollback plan is generated based on the operation journal and
available recovery data. Safety validations are performed before
any rollback operations are executed.

Examples:
  eos rollback disk-operation abc123-def456-ghi789     # Rollback operation
  eos rollback disk-operation abc123 --show-plan      # Show rollback plan only
  eos rollback disk-operation abc123 --dry-run        # Test rollback process
  eos rollback disk-operation abc123 --force          # Skip safety validations`,

	Args: cobra.ExactArgs(1),
	RunE: eos.Wrap(runRollbackDiskOperation),
}

func init() {
	DiskOperationCmd.Flags().BoolVar(&rollbackDryRun, "dry-run", false, "Show what rollback would do without executing")
	DiskOperationCmd.Flags().BoolVar(&forceRollback, "force", false, "Skip safety validations and force rollback")
	DiskOperationCmd.Flags().BoolVar(&showPlan, "show-plan", false, "Display rollback plan and exit")
	DiskOperationCmd.Flags().BoolVar(&skipConfirmation, "yes", false, "Skip confirmation prompts")
}

func runRollbackDiskOperation(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	journalID := args[0]
	logger := otelzap.Ctx(rc.Ctx)

	// CRITICAL: Detect flag-like args (P0-1 fix)
	if err := verify.ValidateNoFlagLikeArgs(args); err != nil {
		return err
	}

	logger.Info("Starting disk operation rollback",
		zap.String("journal_id", journalID),
		zap.Bool("dry_run", rollbackDryRun),
		zap.Bool("force", forceRollback),
		zap.Bool("show_plan", showPlan))

	// Initialize rollback components
	journal, err := storage.NewJournalStorage()
	if err != nil {
		return fmt.Errorf("initialize journal: %w", err)
	}

	snapshots := storage.NewSnapshotManager(journal)
	rollbackManager := storage.NewRollbackManager(journal, snapshots)

	// Load the operation journal
	entry, err := journal.Load(journalID)
	if err != nil {
		return fmt.Errorf("load operation journal: %w", err)
	}

	// Display operation summary
	logger.Info("terminal prompt:", zap.String("output", "=== OPERATION DETAILS ==="))
	logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("Journal ID: %s", entry.ID)))
	logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("Operation: %s", entry.OperationType)))
	logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("Target: %s", entry.Target.Device)))
	logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("Status: %s", entry.Status)))
	logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("Started: %s", entry.StartTime.Format(time.RFC3339))))
	if entry.EndTime != nil {
		logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("Ended: %s", entry.EndTime.Format(time.RFC3339))))
	}
	logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("User: %s", entry.User)))

	if entry.Error != "" {
		logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("Error: %s", entry.Error)))
	}

	// Generate rollback plan
	logger.Info("terminal prompt:", zap.String("output", "\n=== GENERATING ROLLBACK PLAN ==="))
	plan, err := rollbackManager.CreateRollbackPlan(rc.Ctx, journalID)
	if err != nil {
		return fmt.Errorf("create rollback plan: %w", err)
	}

	// Display rollback plan
	logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("Rollback Method: %s", string(plan.Method))))
	logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("Estimated Duration: %s", plan.EstimatedTime.Round(time.Second))))
	logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("Description: %s", plan.Description)))

	if len(plan.Commands) > 0 {
		logger.Info("terminal prompt:", zap.String("output", "\nCommands to execute:"))
		for i, cmd := range plan.Commands {
			logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("  %d. %s %s", i+1, cmd.Command, strings.Join(cmd.Args, " "))))
			if cmd.Description != "" {
				logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("     → %s", cmd.Description)))
			}
		}
	}

	// If only showing plan, exit here
	if showPlan {
		logger.Info("terminal prompt:", zap.String("output", "\nUse --dry-run to test the rollback or remove --show-plan to execute."))
		return nil
	}

	// Safety validations (unless forced)
	if !forceRollback {
		logger.Info("terminal prompt:", zap.String("output", "\n=== SAFETY VALIDATIONS ==="))
		if err := rollbackManager.ValidateRollbackSafety(rc.Ctx, plan, journalID); err != nil {
			logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("✗ Safety validation failed: %s", err.Error())))
			logger.Info("terminal prompt:", zap.String("output", "\nUse --force to skip safety validations (DANGEROUS)."))
			return fmt.Errorf("rollback safety validation failed: %w", err)
		}
		logger.Info("terminal prompt:", zap.String("output", "✓ Safety validations passed"))
	} else {
		logger.Info("terminal prompt:", zap.String("output", "\nSKIPPING SAFETY VALIDATIONS (--force enabled)"))
	}

	// Get user confirmation (unless skipped)
	if !skipConfirmation && !rollbackDryRun {
		logger.Info("terminal prompt:", zap.String("output", "\n=== CONFIRMATION ==="))
		if err := getRollbackConfirmation(rc, plan); err != nil {
			return err
		}
	}

	// Handle dry-run mode
	if rollbackDryRun {
		logger.Info("terminal prompt:", zap.String("output", "\n=== DRY RUN ==="))
		logger.Info("terminal prompt:", zap.String("output", "✓ Dry-run mode: Would execute rollback plan but taking no action"))
		logger.Info("terminal prompt:", zap.String("output", "✓ All safety checks passed"))
		logger.Info("terminal prompt:", zap.String("output", "✓ Rollback plan is valid and ready for execution"))
		logger.Info("terminal prompt:", zap.String("output", "\nRemove --dry-run flag to execute the actual rollback."))
		return nil
	}

	// Execute rollback
	logger.Info("terminal prompt:", zap.String("output", "\n=== EXECUTING ROLLBACK ==="))
	startTime := time.Now()

	err = rollbackManager.ExecuteRollback(rc.Ctx, plan, journalID)
	duration := time.Since(startTime)

	if err != nil {
		logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("✗ Rollback failed after %s: %s", duration.Round(time.Second), err.Error())))
		logger.Error("Rollback execution failed",
			zap.String("journal_id", journalID),
			zap.Duration("duration", duration),
			zap.Error(err))
		return fmt.Errorf("rollback execution failed: %w", err)
	}

	// Success
	logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("✓ Rollback completed successfully in %s", duration.Round(time.Second))))

	// Display final status
	updatedEntry, _ := journal.Load(journalID)
	if updatedEntry != nil {
		logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("\nFinal Status: %s", updatedEntry.Status)))
	}

	logger.Info("Disk operation rollback completed successfully",
		zap.String("journal_id", journalID),
		zap.Duration("duration", duration),
		zap.String("method", string(plan.Method)))

	// Additional information based on rollback method
	switch plan.Method {
	case storage.RollbackSnapshot:
		logger.Info("terminal prompt:", zap.String("output", "\nNOTE: Snapshot merge initiated. A system reboot may be required"))
		logger.Info("terminal prompt:", zap.String("output", "for the merge to complete if the logical volume is currently in use."))
	case storage.RollbackReverse:
		logger.Info("terminal prompt:", zap.String("output", "\nVerify that your system is functioning correctly after the rollback."))
	case storage.RollbackManual:
		logger.Info("terminal prompt:", zap.String("output", "\nManual intervention was required. Please review the operation log"))
		logger.Info("terminal prompt:", zap.String("output", "and verify your system state manually."))
	}

	return nil
}

// getRollbackConfirmation prompts user for rollback confirmation
func getRollbackConfirmation(rc *eos_io.RuntimeContext, plan *storage.RollbackPlan) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("This will rollback the operation using: %s", string(plan.Method))))
	logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("Estimated time: %s", plan.EstimatedTime.Round(time.Second))))

	switch plan.Method {
	case storage.RollbackSnapshot:
		logger.Info("terminal prompt:", zap.String("output", "\nWARNING: Snapshot rollback will restore the volume to its"))
		logger.Info("terminal prompt:", zap.String("output", "previous state, potentially losing any changes made after the snapshot."))
	case storage.RollbackReverse:
		logger.Info("terminal prompt:", zap.String("output", "\nWARNING: Reverse operations will attempt to undo the changes."))
		logger.Info("terminal prompt:", zap.String("output", "This may involve shrinking volumes or removing created resources."))
	}

	logger.Info("terminal prompt: \nDo you want to proceed with the rollback? (yes/no): ")

	var response string
	if _, err := fmt.Scanln(&response); err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	response = strings.ToLower(strings.TrimSpace(response))
	if response != "yes" && response != "y" {
		return fmt.Errorf("rollback cancelled by user")
	}

	return nil
}
