// cmd/backup/delete.go

package backup

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/backup"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/spf13/cobra"
)

var deleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete backup resources",
}

var deleteSnapshotCmd = &cobra.Command{
	Use:   "snapshot <id>",
	Short: "Delete a specific snapshot",
	Args:  cobra.ExactArgs(1),
	RunE:  eos.Wrap(backup.DeleteSnapshot),
}

var deleteProfileCmd = &cobra.Command{
	Use:   "profile <name>",
	Short: "Delete a backup profile",
	Args:  cobra.ExactArgs(1),
	RunE:  eos.Wrap(backup.DeleteProfile),
}

var pruneCmd = &cobra.Command{
	Use:   "prune",
	Short: "Prune old snapshots according to retention policy",
	Long: `Remove old snapshots based on retention policies.

Examples:
  # Prune using profile's retention policy
  eos backup delete prune --profile system
  
  # Prune with custom retention
  eos backup delete prune --repo remote --keep-last 5 --keep-daily 7
  
  # Dry run to see what would be deleted
  eos backup delete prune --profile system --dry-run`,
	RunE: eos.Wrap(backup.PruneSnapshots),
}

func init() {
	deleteCmd.AddCommand(deleteSnapshotCmd)
	deleteCmd.AddCommand(deleteProfileCmd)
	deleteCmd.AddCommand(pruneCmd)

	// Delete snapshot flags
	deleteSnapshotCmd.Flags().String("repo", "", "Repository containing the snapshot")
	deleteSnapshotCmd.Flags().Bool("force", false, "Force deletion without confirmation")

	// Delete profile flags
	deleteProfileCmd.Flags().Bool("force", false, "Force deletion without confirmation")

	// Prune flags
	pruneCmd.Flags().String("repo", "", "Repository to prune")
	pruneCmd.Flags().String("profile", "", "Use retention policy from profile")
	pruneCmd.Flags().Int("keep-last", 0, "Keep last N snapshots")
	pruneCmd.Flags().Int("keep-daily", 0, "Keep N daily snapshots")
	pruneCmd.Flags().Int("keep-weekly", 0, "Keep N weekly snapshots")
	pruneCmd.Flags().Int("keep-monthly", 0, "Keep N monthly snapshots")
	pruneCmd.Flags().Int("keep-yearly", 0, "Keep N yearly snapshots")
	pruneCmd.Flags().Bool("dry-run", false, "Show what would be deleted without doing it")
}
