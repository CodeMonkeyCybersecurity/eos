// cmd/create/vault.go
package create

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var CreateVaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Installs and initializes HashiCorp Vault in production mode",
	RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {
		log := zap.L()

		if err := platform.RequireLinuxDistro([]string{"debian", "rhel"}, log); err != nil {
			log.Fatal("Unsupported OS/distro for Vault deployment", zap.Error(err))
		}

		log.Info("🔐 Running full Vault setup via EnsureVault(...)")
		if err := vault.EnsureVault("bootstrap/test", map[string]string{"status": "ok"}, log); err != nil {
			log.Fatal("Vault setup failed", zap.Error(err))
		}

		return nil
	},
	)}

func init() {
	CreateCmd.AddCommand(CreateVaultCmd)
}
