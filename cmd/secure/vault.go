// cmd/secure/vault.go

package secure

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var SecureVaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Secures Vault by revoking the root token and elevating admin privileges",
	Long: `This command secures your Vault setup after "github.com/CodeMonkeyCybersecurity/eos enable vault" has been run.
It reads the stored initialization data (vault_init.json), prompts you to confirm that you have securely 
distributed the unseal keys and root token, then revokes the root token and updates the admin user to have
full (root-level) privileges. Finally, it deletes the stored initialization file.
Please follow up by configuring MFA via your organization's preferred integration method.`,
	RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {
		// Set the Vault environment (VAULT_ADDR, etc.)
		vault.SetVaultEnv()

		// Create a Vault client using the Vault API.
		client, err := vault.NewClient()
		if err != nil {
			log.Fatal("Failed to create Vault client", zap.Error(err))
		}
		log.Info("✅ Created new vault client")

		log.Info("Loading the stored initialization data and EOS user credentials...")
		initRes, creds, storedHashes, hashedRoot := vault.LoadVaultSecureData(client)
		vault.CheckVaultSecrets(storedHashes, hashedRoot)
		log.Info("✅ Loaded the stored initialization data and EOS user credentials")

		log.Info("Applying permissive policy (eos-full) via the API for eos system user...")
		vault.ApplyAdminPolicy(creds, client)
		log.Info("✅ Policy applied")

		log.Info("Revoking the root token now that the Eos admin user has been configured....")
		vault.RevokeRootToken(client, initRes.RootToken)
		log.Info("✅ Done")

		log.Info("Cleaning up the stored initialization file...")
		platform.CleanupFile("vault_init.json")
		log.Info("✅ Done")

		log.Info("Informing the user of the next steps...")
		vault.PrintNextSteps()
		log.Info("✅ Done")

		return nil
	}),
}

func init() {
	SecureCmd.AddCommand(SecureVaultCmd)
}
