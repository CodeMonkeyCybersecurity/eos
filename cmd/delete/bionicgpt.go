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

DEPRECATION NOTICE:
This command only works for Docker Compose-based BionicGPT installations.
If you deployed BionicGPT with Nomad orchestration (default in recent versions),
you must manually delete using Nomad commands:

  # Stop Nomad jobs
  nomad job stop default-bionicgpt
  nomad job stop default-bionicgpt-postgres
  nomad job stop default-litellm     # If Azure configured
  nomad job stop default-ollama      # If local embeddings

  # Purge jobs (removes from history)
  nomad job purge default-bionicgpt
  nomad job purge default-bionicgpt-postgres
  nomad job purge default-litellm
  nomad job purge default-ollama

  # Remove Vault secrets
  vault kv delete secret/bionicgpt/oauth
  vault kv delete secret/bionicgpt/db
  vault kv delete secret/bionicgpt/litellm

  # Remove Authentik configuration manually via Authentik UI

For Docker Compose deployments, this command will:
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
