// cmd/create/chat_archive.go
//
// Thin orchestration layer for chat-archive. Business logic lives in
// pkg/chatarchive/ per the cmd/ vs pkg/ enforcement rule.

package create

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/chatarchive"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/parse"
	"github.com/spf13/cobra"
)

// CreateChatArchiveCmd copies and deduplicates chat transcripts.
var CreateChatArchiveCmd = &cobra.Command{
	Use:   "chat-archive",
	Short: "Copy and deduplicate chat transcripts into a local archive",
	Long: `Find transcript-like files (jsonl/json/html), copy unique files into one archive,
and write an index manifest with duplicate mappings.

Examples:
  eos create chat-archive
  eos create chat-archive --source ~/.claude --source ~/dev
  eos create chat-archive --dest ~/Dev/eos/outputs/chat-archive --dry-run
  eos backup chats  (alias)`,
	RunE: eos.Wrap(runCreateChatArchive),
}

func init() {
	CreateCmd.AddCommand(CreateChatArchiveCmd)
	CreateChatArchiveCmd.Flags().StringSlice("source", chatarchive.DefaultSources(), "Source directories to scan")
	CreateChatArchiveCmd.Flags().String("dest", chatarchive.DefaultDest(), "Destination archive directory")
	CreateChatArchiveCmd.Flags().Bool("dry-run", false, "Show what would be archived without copying files")
}

func runCreateChatArchive(rc *eos_io.RuntimeContext, cmd *cobra.Command, _ []string) error {
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
}
