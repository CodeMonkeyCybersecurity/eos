// cmd/backup/chats.go
//
// Convenience alias: "eos backup chats" routes to the same business
// logic as "eos create chat-archive". Thin orchestration only.

package backup

import (
	"github.com/CodeMonkeyCybersecurity/eos/internal/chatarchivecmd"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
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
  eos backup chats --exclude conversation-api --dry-run`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, _ []string) error {
		return chatarchivecmd.Run(rc, cmd)
	}),
}

func init() {
	BackupCmd.AddCommand(chatsCmd)
	chatarchivecmd.BindFlags(chatsCmd)
}
