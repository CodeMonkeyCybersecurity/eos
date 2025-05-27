// cmd/create/mattermost.go

package create

import (
	"github.com/spf13/cobra"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/mattermost"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// CreateMattermostCmd installs and deploys Mattermost via Docker Compose.
var CreateMattermostCmd = &cobra.Command{
	Use:   "mattermost",
	Short: "Deploy Mattermost via Docker Compose",
	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, _ *cobra.Command, _ []string) error {
		return mattermost.OrchestrateMattermostInstall(rc)
	}),
}