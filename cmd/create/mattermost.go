// cmd/create/mattermost.go
package create

import (
	eoscli "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/mattermost"
	"github.com/spf13/cobra"
)

// CreateMattermostCmd deploys Mattermost via Docker Compose.
var CreateMattermostCmd = &cobra.Command{
	Use:     "mattermost",
	Short:   "Deploy Mattermost via Docker Compose",
	Long:    "Clones the Mattermost Docker repo, patches .env, sets up volumes, and starts Mattermost on port 8017.",
	Example: "  eos create mattermost\n  eos create mattermost --domain m.company.local",
	RunE: eoscli.Wrap(func(rc *eos_io.RuntimeContext, _ *cobra.Command, _ []string) error {
		return mattermost.OrchestrateMattermostInstall(rc)
	}),
}

func init() {
	// Attach this subcommand to the `create` (deploy) parent
	CreateCmd.AddCommand(CreateMattermostCmd)
}
