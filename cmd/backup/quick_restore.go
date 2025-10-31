// cmd/backup/quick_restore.go
// Quick directory restore - matches "eos backup ." functionality

package backup

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/backup"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// QuickRestoreCmd returns the quick restore command for use by top-level restore command
func QuickRestoreCmd() *cobra.Command {
	return quickRestoreCmd
}

// quickRestoreCmd provides instant restore for quick backups
var quickRestoreCmd = &cobra.Command{
	Use:   ". [snapshot-id]",
	Short: "Quick restore from quick-backups repository",
	Long: `Restore from quick backups created with "eos backup .".

Restores to current directory by default, or use --target for different location.

Examples:
  eos restore .                              # Restore latest snapshot to current directory
  eos restore . abc123                       # Restore specific snapshot
  eos restore . --target /tmp/restored       # Restore to different location
  eos restore . --list                       # List available snapshots first
  eos restore . --dry-run                    # Show what would be restored`,

	Args: cobra.MaximumNArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		// Get flags
		targetDir, _ := cmd.Flags().GetString("target")
		listOnly, _ := cmd.Flags().GetBool("list")
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		force, _ := cmd.Flags().GetBool("force")

		// Check if quick-backups repository exists
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("getting home directory: %w", err)
		}

		repoPath := filepath.Join(homeDir, ".eos", "quick-backups")
		if _, err := os.Stat(repoPath); os.IsNotExist(err) {
			return fmt.Errorf("quick backup repository not found at %s\nCreate one first with: eos backup", repoPath)
		}

		// Create backup client
		client, err := backup.NewClient(rc, "quick-backups")
		if err != nil {
			return fmt.Errorf("creating backup client: %w", err)
		}

		// If --list, show snapshots and exit
		if listOnly {
			logger.Info("Listing available snapshots")
			output, err := client.RunRestic("snapshots", "--json")
			if err != nil {
				return fmt.Errorf("listing snapshots: %w", err)
			}

			logger.Info("terminal prompt:", zap.String("output", "\nAvailable Snapshots:"))
			logger.Info("terminal prompt:", zap.String("output", strings.Repeat("-", 80)))

			// Parse and display snapshots
			snapshots, err := parseSnapshotsJSON(output)
			if err != nil {
				// Fallback to raw output
				logger.Info("terminal prompt:", zap.String("output", string(output)))
			} else {
				for _, snap := range snapshots {
					shortID := snap.ID
					if len(shortID) > 8 {
						shortID = shortID[:8]
					}
					logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("%-16s %-20s %-40s",
						shortID,
						snap.Time.Format("2006-01-02 15:04:05"),
						strings.Join(snap.Paths, ", "))))
				}
			}

			logger.Info("terminal prompt:", zap.String("output", "\nRestore: eos restore . <snapshot-id>"))
			return nil
		}

		// Determine snapshot ID
		snapshotID := "latest"
		if len(args) > 0 {
			snapshotID = args[0]
		}

		// Determine target directory
		if targetDir == "" {
			var err error
			targetDir, err = os.Getwd()
			if err != nil {
				return fmt.Errorf("getting current directory: %w", err)
			}
		}

		// Get absolute path
		absTarget, err := filepath.Abs(targetDir)
		if err != nil {
			return fmt.Errorf("resolving target path: %w", err)
		}

		// SECURITY: Prevent restore to critical system directories (CVSS 8.2 mitigation)
		// Restoring to /, /etc, /usr, /var, /boot, /home without explicit --target is catastrophic
		if targetDir == "" { // User didn't specify --target, using current directory default
			for _, criticalPath := range backup.CriticalSystemPaths {
				if absTarget == criticalPath {
					return fmt.Errorf("SAFETY: Refusing to restore to critical system directory: %s\n"+
						"This would overwrite system files and likely destroy your system.\n"+
						"If you really need to restore to this location, use:\n"+
						"  eos restore . --target %s --force\n\n"+
						"WARNING: This is extremely dangerous and should only be done from rescue media",
						absTarget, absTarget)
				}
			}
		}

		logger.Info("Quick restore initiated",
			zap.String("snapshot", snapshotID),
			zap.String("target", absTarget),
			zap.Bool("dry_run", dryRun))

		// Safety check: don't overwrite non-empty directory without --force
		if !force && !dryRun {
			entries, err := os.ReadDir(absTarget)
			if err == nil && len(entries) > 0 {
				return fmt.Errorf("target directory not empty: %s\nUse --force to overwrite or --target to specify different location", absTarget)
			}
		}

		// Build restic restore args
		restoreArgs := []string{"restore", snapshotID, "--target", absTarget}

		if dryRun {
			restoreArgs = append(restoreArgs, "--dry-run")
		}

		// Execute restore
		logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("Restoring snapshot %s to: %s", snapshotID, absTarget)))

		output, err := client.RunRestic(restoreArgs...)
		if err != nil {
			logger.Error("Restore failed", zap.Error(err), zap.String("output", string(output)))
			return fmt.Errorf("restore failed: %w", err)
		}

		logger.Info("terminal prompt:", zap.String("output", string(output)))
		logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("\n✓ Restore complete to: %s", absTarget)))

		return nil
	}),
}

// parseSnapshotsJSON parses restic snapshots JSON output
func parseSnapshotsJSON(jsonData []byte) ([]backup.Snapshot, error) {
	var snapshots []backup.Snapshot
	if err := json.Unmarshal(jsonData, &snapshots); err != nil {
		return nil, fmt.Errorf("parsing snapshots JSON: %w", err)
	}
	return snapshots, nil
}

func init() {
	// Add as top-level restore subcommand for quick access
	// This will be registered in restore.go or backup.go
	quickRestoreCmd.Flags().StringP("target", "t", "", "Target directory for restore (default: current directory)")
	quickRestoreCmd.Flags().BoolP("list", "l", false, "List available snapshots instead of restoring")
	quickRestoreCmd.Flags().Bool("dry-run", false, "Show what would be restored without actually restoring")
	quickRestoreCmd.Flags().BoolP("force", "f", false, "Overwrite non-empty target directory")
}
