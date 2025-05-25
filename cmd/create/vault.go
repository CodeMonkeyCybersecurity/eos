// cmd/create/vault.go
package create

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
)

var CreateVaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Installs Vault with TLS, systemd service, and initial configuration",
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {

		err := vault.OrchestrateVaultCreate(rc.Ctx)
		if err != nil {
			return logger.LogErrAndWrap("vault create failed: %w", err)
		}

		return nil
	}),
}

func init() {
	CreateCmd.AddCommand(CreateVaultCmd)
}
