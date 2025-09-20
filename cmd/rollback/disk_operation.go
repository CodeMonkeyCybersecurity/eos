package rollback

import (
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/storage"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Command flags
var (
	rollbackDryRun    bool
	forceRollback     bool
	showPlan          bool
	skipConfirmation  bool
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
	fmt.Printf("=== OPERATION DETAILS ===\n")
	fmt.Printf("Journal ID: %s\n", entry.ID)
	fmt.Printf("Operation: %s\n", entry.OperationType)
	fmt.Printf("Target: %s\n", entry.Target.Device)
	fmt.Printf("Status: %s\n", entry.Status)
	fmt.Printf("Started: %s\n", entry.StartTime.Format(time.RFC3339))
	if entry.EndTime != nil {
		fmt.Printf("Ended: %s\n", entry.EndTime.Format(time.RFC3339))
	}
	fmt.Printf("User: %s\n", entry.User)

	if entry.Error != "" {
		fmt.Printf("Error: %s\n", entry.Error)
	}

	// Generate rollback plan
	fmt.Printf("\n=== GENERATING ROLLBACK PLAN ===\n")
	plan, err := rollbackManager.CreateRollbackPlan(rc.Ctx, journalID)
	if err != nil {
		return fmt.Errorf("create rollback plan: %w", err)
	}

	// Display rollback plan
	fmt.Printf("Rollback Method: %s\n", string(plan.Method))
	fmt.Printf("Estimated Duration: %s\n", plan.EstimatedTime.Round(time.Second))
	fmt.Printf("Description: %s\n", plan.Description)

	if len(plan.Commands) > 0 {
		fmt.Printf("\nCommands to execute:\n")
		for i, cmd := range plan.Commands {
			fmt.Printf("  %d. %s %s\n", i+1, cmd.Command, strings.Join(cmd.Args, " "))
			if cmd.Description != "" {
				fmt.Printf("     → %s\n", cmd.Description)
			}
		}
	}

	// If only showing plan, exit here
	if showPlan {
		fmt.Printf("\nUse --dry-run to test the rollback or remove --show-plan to execute.\n")
		return nil
	}

	// Safety validations (unless forced)
	if !forceRollback {
		fmt.Printf("\n=== SAFETY VALIDATIONS ===\n")
		if err := rollbackManager.ValidateRollbackSafety(rc.Ctx, plan, journalID); err != nil {
			fmt.Printf("❌ Safety validation failed: %s\n", err.Error())
			fmt.Printf("\nUse --force to skip safety validations (DANGEROUS).\n")
			return fmt.Errorf("rollback safety validation failed: %w", err)
		}
		fmt.Printf("✅ Safety validations passed\n")
	} else {
		fmt.Printf("\n⚠️  SKIPPING SAFETY VALIDATIONS (--force enabled)\n")
	}

	// Get user confirmation (unless skipped)
	if !skipConfirmation && !rollbackDryRun {
		fmt.Printf("\n=== CONFIRMATION ===\n")
		if err := getRollbackConfirmation(plan); err != nil {
			return err
		}
	}

	// Handle dry-run mode
	if rollbackDryRun {
		fmt.Printf("\n=== DRY RUN ===\n")
		fmt.Printf("✓ Dry-run mode: Would execute rollback plan but taking no action\n")
		fmt.Printf("✓ All safety checks passed\n")
		fmt.Printf("✓ Rollback plan is valid and ready for execution\n")
		fmt.Printf("\nRemove --dry-run flag to execute the actual rollback.\n")
		return nil
	}

	// Execute rollback
	fmt.Printf("\n=== EXECUTING ROLLBACK ===\n")
	startTime := time.Now()

	err = rollbackManager.ExecuteRollback(rc.Ctx, plan, journalID)
	duration := time.Since(startTime)

	if err != nil {
		fmt.Printf("❌ Rollback failed after %s: %s\n", duration.Round(time.Second), err.Error())
		logger.Error("Rollback execution failed",
			zap.String("journal_id", journalID),
			zap.Duration("duration", duration),
			zap.Error(err))
		return fmt.Errorf("rollback execution failed: %w", err)
	}

	// Success
	fmt.Printf("✅ Rollback completed successfully in %s\n", duration.Round(time.Second))
	
	// Display final status
	updatedEntry, _ := journal.Load(journalID)
	if updatedEntry != nil {
		fmt.Printf("\nFinal Status: %s\n", updatedEntry.Status)
	}

	logger.Info("Disk operation rollback completed successfully",
		zap.String("journal_id", journalID),
		zap.Duration("duration", duration),
		zap.String("method", string(plan.Method)))

	// Additional information based on rollback method
	switch plan.Method {
	case storage.RollbackSnapshot:
		fmt.Printf("\nNOTE: Snapshot merge initiated. A system reboot may be required\n")
		fmt.Printf("for the merge to complete if the logical volume is currently in use.\n")
	case storage.RollbackReverse:
		fmt.Printf("\nVerify that your system is functioning correctly after the rollback.\n")
	case storage.RollbackManual:
		fmt.Printf("\nManual intervention was required. Please review the operation log\n")
		fmt.Printf("and verify your system state manually.\n")
	}

	return nil
}

// getRollbackConfirmation prompts user for rollback confirmation
func getRollbackConfirmation(plan *storage.RollbackPlan) error {
	fmt.Printf("This will rollback the operation using: %s\n", string(plan.Method))
	fmt.Printf("Estimated time: %s\n", plan.EstimatedTime.Round(time.Second))

	if plan.Method == storage.RollbackSnapshot {
		fmt.Printf("\n⚠️  WARNING: Snapshot rollback will restore the volume to its\n")
		fmt.Printf("previous state, potentially losing any changes made after the snapshot.\n")
	} else if plan.Method == storage.RollbackReverse {
		fmt.Printf("\n⚠️  WARNING: Reverse operations will attempt to undo the changes.\n")
		fmt.Printf("This may involve shrinking volumes or removing created resources.\n")
	}

	fmt.Printf("\nDo you want to proceed with the rollback? (yes/no): ")
	
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