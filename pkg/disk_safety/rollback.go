package disk_safety

import (
	"context"
	"fmt"
	"os/exec"
	"time"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// RollbackManager handles rollback operations
type RollbackManager struct {
	journal   *JournalStorage
	snapshots *SnapshotManager
}

// NewRollbackManager creates a new rollback manager
func NewRollbackManager(journal *JournalStorage, snapshots *SnapshotManager) *RollbackManager {
	return &RollbackManager{
		journal:   journal,
		snapshots: snapshots,
	}
}

// CreateRollbackPlan generates a rollback plan for a failed operation
func (rm *RollbackManager) CreateRollbackPlan(ctx context.Context, journalID string) (*RollbackPlan, error) {
	logger := otelzap.Ctx(ctx)

	entry, err := rm.journal.Load(journalID)
	if err != nil {
		return nil, fmt.Errorf("load journal entry: %w", err)
	}

	logger.Info("Creating rollback plan",
		zap.String("journal_id", journalID),
		zap.String("operation_type", entry.OperationType))

	plan := &RollbackPlan{
		Description: fmt.Sprintf("Rollback for %s operation on %s",
			entry.OperationType, entry.Target.GetDevice()),
	}

	// Check if we have a snapshot available
	if entry.Snapshot != nil {
		logger.Debug("Snapshot available for rollback",
			zap.String("snapshot_name", entry.Snapshot.Name))

		plan.Method = RollbackSnapshot
		plan.SnapshotID = entry.Snapshot.GetID()
		plan.EstimatedTime = 30 * time.Second // Snapshot rollback is fast
		plan.Commands = []RollbackCommand{
			{
				Command:     "lvconvert",
				Args:        []string{"--merge", fmt.Sprintf("%s/%s", entry.Snapshot.SourceVG, entry.Snapshot.Name)},
				Description: "Merge snapshot to restore original state",
				Critical:    true,
			},
		}
		return plan, nil
	}

	// Try to generate reverse commands
	reverseCommands, err := rm.generateReverseCommands(ctx, entry)
	if err == nil && len(reverseCommands) > 0 {
		logger.Debug("Generated reverse commands for rollback",
			zap.Int("command_count", len(reverseCommands)))

		plan.Method = RollbackReverse
		plan.Commands = reverseCommands
		plan.EstimatedTime = rm.estimateReverseDuration(reverseCommands)
		return plan, nil
	}

	// Manual rollback required
	logger.Warn("No automatic rollback method available")
	plan.Method = RollbackManual
	plan.EstimatedTime = 0 // Unknown
	plan.Description += " - Manual intervention required"

	return plan, nil
}

// ExecuteRollback executes a rollback plan
func (rm *RollbackManager) ExecuteRollback(ctx context.Context, plan *RollbackPlan, journalID string) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("Executing rollback plan",
		zap.String("journal_id", journalID),
		zap.String("method", string(plan.Method)))

	// Update journal status
	if err := rm.journal.UpdateStatus(journalID, StatusInProgress); err != nil {
		logger.Warn("Failed to update journal status", zap.Error(err))
	}

	var err error

	switch plan.Method {
	case RollbackSnapshot:
		err = rm.rollbackViaSnapshot(ctx, plan, journalID)
	case RollbackReverse:
		err = rm.rollbackViaReverse(ctx, plan, journalID)
	case RollbackManual:
		err = fmt.Errorf("manual intervention required - no automatic rollback available")
	default:
		err = fmt.Errorf("unknown rollback method: %s", plan.Method)
	}

	// Update journal status based on result
	if err != nil {
		_ = rm.journal.UpdateStatus(journalID, StatusFailed)
		return fmt.Errorf("rollback failed: %w", err)
	}

	_ = rm.journal.UpdateStatus(journalID, StatusRolledBack)
	logger.Info("Rollback completed successfully", zap.String("journal_id", journalID))
	return nil
}

// rollbackViaSnapshot performs rollback using LVM snapshot merge
func (rm *RollbackManager) rollbackViaSnapshot(ctx context.Context, plan *RollbackPlan, journalID string) error {
	logger := otelzap.Ctx(ctx)

	if len(plan.Commands) == 0 {
		return fmt.Errorf("no snapshot commands in rollback plan")
	}

	// Execute the snapshot merge command
	for _, rollbackCmd := range plan.Commands {
		logger.Info("Executing rollback command",
			zap.String("command", rollbackCmd.Command),
			zap.Strings("args", rollbackCmd.Args))

		cmd := exec.CommandContext(ctx, rollbackCmd.Command, rollbackCmd.Args...)
		output, err := cmd.CombinedOutput()

		// Record the command execution in journal
		execCmd := &exec.Cmd{Path: rollbackCmd.Command, Args: append([]string{rollbackCmd.Command}, rollbackCmd.Args...)}
		if recordErr := rm.journal.RecordCommand(journalID, execCmd, output, err); recordErr != nil {
			logger.Warn("Failed to record rollback command", zap.Error(recordErr))
		}

		if err != nil {
			logger.Error("Rollback command failed",
				zap.Error(err),
				zap.String("output", string(output)))
			return fmt.Errorf("rollback command failed: %s: %w", string(output), err)
		}

		logger.Info("Rollback command completed successfully",
			zap.String("output", string(output)))
	}

	logger.Warn("Snapshot merge initiated - system reboot may be required for completion",
		zap.String("journal_id", journalID))

	return nil
}

// rollbackViaReverse performs rollback using reverse operations
func (rm *RollbackManager) rollbackViaReverse(ctx context.Context, plan *RollbackPlan, journalID string) error {
	logger := otelzap.Ctx(ctx)

	if len(plan.Commands) == 0 {
		return fmt.Errorf("no reverse commands in rollback plan")
	}

	// Execute reverse commands in order
	for i, rollbackCmd := range plan.Commands {
		logger.Info("Executing reverse command",
			zap.Int("step", i+1),
			zap.Int("total_steps", len(plan.Commands)),
			zap.String("command", rollbackCmd.Command),
			zap.Strings("args", rollbackCmd.Args))

		cmd := exec.CommandContext(ctx, rollbackCmd.Command, rollbackCmd.Args...)
		output, err := cmd.CombinedOutput()

		// Record the command execution in journal
		execCmd := &exec.Cmd{Path: rollbackCmd.Command, Args: append([]string{rollbackCmd.Command}, rollbackCmd.Args...)}
		if recordErr := rm.journal.RecordCommand(journalID, execCmd, output, err); recordErr != nil {
			logger.Warn("Failed to record reverse command", zap.Error(recordErr))
		}

		if err != nil {
			logger.Error("Reverse command failed",
				zap.Error(err),
				zap.String("output", string(output)))

			if rollbackCmd.Critical {
				return fmt.Errorf("critical reverse command failed: %s: %w", string(output), err)
			}

			logger.Warn("Non-critical reverse command failed, continuing",
				zap.String("command", rollbackCmd.Command))
		} else {
			logger.Info("Reverse command completed successfully",
				zap.String("output", string(output)))
		}
	}

	return nil
}

// generateReverseCommands attempts to generate commands to reverse an operation
func (rm *RollbackManager) generateReverseCommands(ctx context.Context, entry *JournalEntry) ([]RollbackCommand, error) {
	var commands []RollbackCommand

	switch entry.OperationType {
	case "extend_lv", "safe_extend_lv":
		// LV extension can be reversed by shrinking back to original size
		if entry.PreState != nil && entry.PostState != nil {
			if lvState, ok := entry.PreState.LVMState.LogicalVolumes[entry.Target.LogicalVol]; ok {
				commands = append(commands, RollbackCommand{
					Command: "lvreduce",
					Args: []string{
						"-f", // Force (dangerous but necessary for rollback)
						"-L", fmt.Sprintf("%dB", lvState.Size),
						fmt.Sprintf("%s/%s", entry.Target.VolumeGroup, entry.Target.LogicalVol),
					},
					Description: fmt.Sprintf("Shrink LV back to original size (%d bytes)", lvState.Size),
					Critical:    true,
				})

				// Also need to shrink the filesystem first
				commands = []RollbackCommand{
					{
						Command: "resize2fs",
						Args: []string{
							entry.Target.GetDevice(),
							fmt.Sprintf("%dK", lvState.Size/1024), // Convert to KB for resize2fs
						},
						Description: "Shrink filesystem before LV shrink",
						Critical:    true,
					},
					commands[0], // The LV shrink command
				}
			}
		}

	case "create_lv":
		// LV creation can be reversed by removal
		commands = append(commands, RollbackCommand{
			Command: "lvremove",
			Args: []string{
				"-f",
				fmt.Sprintf("%s/%s", entry.Target.VolumeGroup, entry.Target.LogicalVol),
			},
			Description: "Remove created LV",
			Critical:    true,
		})

	case "create_vg":
		// VG creation can be reversed by removal
		commands = append(commands, RollbackCommand{
			Command: "vgremove",
			Args: []string{
				"-f",
				entry.Target.VolumeGroup,
			},
			Description: "Remove created VG",
			Critical:    true,
		})

	case "extend_vg":
		// VG extension can be reversed by removing the PV that was added
		// This requires knowing which PV was added, which should be in the journal
		if len(entry.Commands) > 0 {
			for _, cmd := range entry.Commands {
				if cmd.Command == "vgextend" && len(cmd.Args) >= 2 {
					// Last arg should be the PV that was added
					pvToRemove := cmd.Args[len(cmd.Args)-1]
					commands = append(commands, RollbackCommand{
						Command: "vgreduce",
						Args: []string{
							entry.Target.VolumeGroup,
							pvToRemove,
						},
						Description: fmt.Sprintf("Remove PV %s from VG", pvToRemove),
						Critical:    true,
					})
				}
			}
		}

	default:
		return nil, fmt.Errorf("no reverse commands available for operation type: %s", entry.OperationType)
	}

	return commands, nil
}

// estimateReverseDuration estimates how long reverse operations will take
func (rm *RollbackManager) estimateReverseDuration(commands []RollbackCommand) time.Duration {
	// Simple estimation based on command types
	var totalDuration time.Duration

	for _, cmd := range commands {
		switch cmd.Command {
		case "lvremove", "vgremove":
			totalDuration += 10 * time.Second // Quick operations
		case "lvreduce":
			totalDuration += 60 * time.Second // More time for shrinking
		case "resize2fs":
			totalDuration += 120 * time.Second // Filesystem operations are slow
		case "vgreduce":
			totalDuration += 30 * time.Second // Medium duration
		default:
			totalDuration += 30 * time.Second // Default estimate
		}
	}

	return totalDuration
}

// ValidateRollbackSafety checks if rollback is safe to perform
func (rm *RollbackManager) ValidateRollbackSafety(ctx context.Context, plan *RollbackPlan, journalID string) error {
	logger := otelzap.Ctx(ctx)

	entry, err := rm.journal.Load(journalID)
	if err != nil {
		return fmt.Errorf("load journal entry: %w", err)
	}

	logger.Debug("Validating rollback safety",
		zap.String("journal_id", journalID),
		zap.String("method", string(plan.Method)))

	// Check if enough time has passed since the operation
	if time.Since(entry.StartTime) > 24*time.Hour {
		return fmt.Errorf("operation is too old for safe rollback (>24h)")
	}

	// For snapshot rollbacks, verify snapshot still exists
	if plan.Method == RollbackSnapshot {
		if entry.Snapshot == nil {
			return fmt.Errorf("snapshot not available for rollback")
		}

		// Check if snapshot still exists in LVM
		cmd := exec.CommandContext(ctx, "lvs", "--noheadings",
			fmt.Sprintf("%s/%s", entry.Snapshot.SourceVG, entry.Snapshot.Name))
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("snapshot %s no longer exists", entry.Snapshot.Name)
		}
	}

	// For reverse operations, check if the current state matches expected post-state
	if plan.Method == RollbackReverse {
		if entry.PostState == nil {
			return fmt.Errorf("no post-state available to validate current state")
		}

		// This would involve checking current LVM state against recorded post-state
		// For now, we'll skip this complex validation
	}

	return nil
}

// GetRollbackHistory returns the rollback history for analysis
func (rm *RollbackManager) GetRollbackHistory(limit int) ([]*JournalEntry, error) {
	// This would query the journal for entries with StatusRolledBack
	// Implementation depends on journal query capabilities
	return nil, fmt.Errorf("not yet implemented")
}

// Emergency rollback for critical situations
func (rm *RollbackManager) EmergencyRollback(ctx context.Context, journalID string) error {
	logger := otelzap.Ctx(ctx)

	logger.Warn("Initiating emergency rollback",
		zap.String("journal_id", journalID))

	// Create rollback plan
	plan, err := rm.CreateRollbackPlan(ctx, journalID)
	if err != nil {
		return fmt.Errorf("create emergency rollback plan: %w", err)
	}

	// Skip safety validations in emergency
	logger.Warn("Skipping safety validations for emergency rollback")

	// Execute immediately
	return rm.ExecuteRollback(ctx, plan, journalID)
}
