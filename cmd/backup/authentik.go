// cmd/backup/authentik.go
package backup

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
)

// AuthentikCmd represents the 'eos backup authentik' command
var AuthentikCmd = &cobra.Command{
	Use:   "authentik [flags]",
	Short: "Create a backup of your Authentik installation",
	Long: `Create a comprehensive backup of your Authentik installation including:
- Database dump
- Configuration files
- Media and custom templates
- Encryption keys

Backups are stored with timestamps for easy identification and restoration.`,
	RunE: eos.Wrap(backupAuthentik),
}

func init() {
	authentikFlags := AuthentikCmd.Flags()
	authentikFlags.StringP("output", "o", "", "Output directory for the backup (default: ./backups/authentik-<timestamp>)")
	authentikFlags.BoolP("compress", "c", true, "Compress the backup into a single archive")
	authentikFlags.Bool("include-media", true, "Include media files in the backup")
	authentikFlags.Bool("include-certs", true, "Include SSL certificates in the backup")
	authentikFlags.StringP("path", "p", "/opt/hecate", "Path to Authentik installation")

	// Register command
	BackupCmd.AddCommand(AuthentikCmd)
}

func backupAuthentik(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	// Implementation will be moved from the backup functionality
	// This is a placeholder that matches the expected function signature
	return fmt.Errorf("not implemented")
}
