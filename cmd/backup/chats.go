// cmd/backup/chats.go
//
// Convenience alias: "eos backup chats" routes to the same business
// logic as "eos create chat-archive". Thin orchestration only.

package backup

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/chatarchive"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/parse"
	"github.com/spf13/cobra"
)

var chatsCmd = &cobra.Command{
	Use:   "chats",
	Short: "Backup and deduplicate chat transcripts (alias for 'create chat-archive')",
	Long: `Find transcript-like files (jsonl/json/html), copy unique files into one archive,
and write an index manifest with duplicate mappings.

This is a convenience alias for 'eos create chat-archive'.
Works across Ubuntu, macOS, and Windows.

Examples:
  eos backup chats
  eos backup chats --source ~/.claude --source ~/dev
  eos backup chats --dry-run`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, _ []string) error {
		sources, _ := cmd.Flags().GetStringSlice("source")
		dest, _ := cmd.Flags().GetString("dest")
		dryRun, _ := cmd.Flags().GetBool("dry-run")

		result, err := chatarchive.Archive(rc, chatarchive.Options{
			Sources: chatarchive.ExpandSources(sources),
			Dest:    parse.ExpandHome(dest),
			DryRun:  dryRun,
		})
		if err != nil {
			return err
		}

		if dryRun {
			fmt.Printf("Dry run complete. %d unique files, %d duplicates.\n",
				result.UniqueFiles, result.Duplicates)
		} else {
			fmt.Printf("Archive complete. %d unique files copied, %d duplicates mapped.\n",
				result.UniqueFiles, result.Duplicates)
			fmt.Printf("Manifest: %s\n", result.ManifestPath)
		}
		return nil
	}),
}

func init() {
	BackupCmd.AddCommand(chatsCmd)
	chatsCmd.Flags().StringSlice("source", chatarchive.DefaultSources(), "Source directories to scan")
	chatsCmd.Flags().String("dest", chatarchive.DefaultDest(), "Destination archive directory")
	chatsCmd.Flags().Bool("dry-run", false, "Show what would be archived without copying files")
}
