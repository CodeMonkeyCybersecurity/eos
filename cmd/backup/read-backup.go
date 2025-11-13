// cmd/backup/read.go

package backup

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/backup"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/spf13/cobra"
)

var readCmd = &cobra.Command{
	Use:   "read",
	Short: "Read backup information",
}

var readRepoCmd = &cobra.Command{
	Use:   "repository <name>",
	Short: "Show detailed repository information",
	Args:  cobra.ExactArgs(1),
	RunE:  eos.Wrap(backup.ReadRepository),
}

var readProfileCmd = &cobra.Command{
	Use:   "profile <name>",
	Short: "Show detailed profile information",
	Args:  cobra.ExactArgs(1),
	RunE:  eos.Wrap(backup.ReadProfile),
}

var readSnapshotCmd = &cobra.Command{
	Use:   "snapshot <id>",
	Short: "Show detailed snapshot information",
	Args:  cobra.ExactArgs(1),
	RunE:  eos.Wrap(backup.ReadSnapshot),
}

func init() {
	readCmd.AddCommand(readRepoCmd)
	readCmd.AddCommand(readProfileCmd)
	readCmd.AddCommand(readSnapshotCmd)

	// Snapshot read flags
	readSnapshotCmd.Flags().String("repo", "", "Repository containing the snapshot")
}
