// cmd/delete/bionicgpt.go
package delete

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/bionicgpt"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/spf13/cobra"
)

var deleteBionicGPTCmd = &cobra.Command{
	Use:   "bionicgpt",
	Short: "Delete BionicGPT installation and optionally backup data",
	Long: `Safely delete BionicGPT installation with optional data backup.

This command will:
1. Stop all BionicGPT containers
2. Optionally backup the data volumes to /opt/bionicgpt/backups/
3. Remove all Docker containers
4. Remove all Docker volumes (contains all user data, documents, and embeddings)
5. Remove all Docker images
6. Remove installation directory /opt/bionicgpt

WARNING: This will delete ALL BionicGPT data including:
- PostgreSQL database (user accounts, teams, settings)
- Uploaded documents
- Document embeddings and vector database
- Chat history
- Azure OpenAI configuration

Examples:
  # Delete with backup (recommended)
  sudo eos delete bionicgpt

  # Delete without backup (faster, no recovery possible)
  sudo eos delete bionicgpt --skip-backup

  # Force delete even if already partially removed
  sudo eos delete bionicgpt --force

Code Monkey Cybersecurity - "Cybersecurity. With humans."`,
	RunE: eos.Wrap(bionicgpt.RunDeleteBionicGPT),
}

func init() {
	deleteBionicGPTCmd.Flags().BoolVar(&bionicgpt.BionicgptDeleteSkipBackup, "skip-backup", false,
		"Skip backup before deletion (not recommended)")
	deleteBionicGPTCmd.Flags().BoolVar(&bionicgpt.BionicgptDeleteForce, "force", false,
		"Force deletion even if components already removed")

	DeleteCmd.AddCommand(deleteBionicGPTCmd)
}
