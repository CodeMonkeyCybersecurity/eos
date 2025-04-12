/* cmd/secure/vault.go */

package secure

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
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
		addr, err := vault.SetVaultEnv()
		if err != nil {
			log.Error("Failed to set Vault environment", zap.Error(err))
			return err
		}
		log.Info("Vault environment set", zap.String("VAULT_ADDR", addr))

		// Create a Vault client using the Vault API.
		client, err := vault.NewClient()
		if err != nil {
			log.Fatal("Failed to create Vault client", zap.Error(err))
		}
		log.Info("✅ Created new vault client")

		vault.SetVaultClient(client)

		// Prompt the user (or reuse saved) unseal keys and root token
		keys, rootToken, err := vault.PromptOrRecallUnsealKeys()
		if err != nil {
			log.Error("Failed to retrieve unseal keys or root token", zap.Error(err))
			return err
		}

		// Unseal Vault
		log.Info("🔐 Vault appears sealed — requesting manual unseal keys and root token...")
		for i, key := range keys {
			resp, err := client.Sys().Unseal(key)
			if err != nil {
				log.Error("Unseal failed", zap.Int("index", i+1), zap.Error(err))
				return err
			}
			if !resp.Sealed {
				log.Info("✅ Vault unsealed after key %d\n", zap.Int("index", i+1))
				break
			}
		}
		client.SetToken(rootToken)
		log.Info("✅ Vault unsealed and authenticated as eos admin")

		log.Info("Loading the stored initialization data and EOS user credentials...")
		initRes, creds, storedHashes, hashedRoot := eos.ReadVaultSecureData(client)
		vault.CheckVaultSecrets(storedHashes, hashedRoot)
		log.Info("✅ Loaded the stored initialization data and EOS user credentials")

		log.Info("Applying permissive policy (eos-full) via the API for eos system user...")
		if err := vault.ApplyAdminPolicy(creds, client); err != nil {
			log.Error("Failed to apply admin policy", zap.Error(err))
			return err
		}
		log.Info("✅ Policy applied")

		log.Info("Revoking the root token now that the Eos admin user has been configured....")
		if err := vault.RevokeRootToken(client, initRes.RootToken); err != nil {
			log.Error("Failed to revoke root token", zap.Error(err))
			return err
		}
		log.Info("✅ Done")

		log.Info("Cleaning up the stored initialization file...")
		system.Rm("vault_init.json", "vault_init.json")
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
