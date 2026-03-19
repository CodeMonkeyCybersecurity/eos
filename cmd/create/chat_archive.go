// cmd/create/chat_archive.go
//
// Thin orchestration layer for chat-archive. Business logic lives in
// pkg/chatarchive/ per the cmd/ vs pkg/ enforcement rule.

package create

import (
	"github.com/CodeMonkeyCybersecurity/eos/internal/chatarchivecmd"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
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
	chatarchivecmd.BindFlags(CreateChatArchiveCmd)
}

func runCreateChatArchive(rc *eos_io.RuntimeContext, cmd *cobra.Command, _ []string) error {
	return chatarchivecmd.Run(rc, cmd)
}
