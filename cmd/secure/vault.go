/* cmd/secure/vault.go */

package secure

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var revokeRoot bool

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
		addr, err := vault.EnsureVaultAddr(log)
		if err != nil {
			log.Error("Failed to set Vault environment", zap.Error(err))
			return err
		}
		log.Info("Vault environment set", zap.String("VAULT_ADDR", addr))

		// Create a Vault client using the Vault API.
		client, err := vault.NewClient(log)
		if err != nil {
			log.Fatal("Failed to create Vault client", zap.Error(err))
		}
		log.Info("✅ Created new vault client")

		vault.SetVaultClient(client, log)

		// Prompt the user (or reuse saved) unseal keys and root token
		// Reuse secured Vault data (no prompt)
		initRes, creds, storedHashes, hashedRoot := eos.ReadVaultSecureData(client, log)
		client.SetToken(initRes.RootToken)

		log.Info("✅ Vault unsealed and authenticated as eos admin")

		log.Info("Loading the stored initialization data and eos user credentials...")
		vault.Check(client, log, storedHashes, hashedRoot)
		log.Info("✅ Loaded the stored initialization data and eos user credentials")

		/* Start Vault Agent (writes HCL, unit, starts service) */
		if err := vault.EnsureVaultAgent(client, creds.Password, log); err != nil {
			log.Error("Failed to set up Vault Agent", zap.Error(err))
			return err
		}
		log.Info("✅ Vault Agent setup complete")

		log.Info("Applying permissive policy (eos-policy) via the API for eos system user...")
		if err := vault.ApplyAdminPolicy(creds, client, log); err != nil {
			log.Error("Failed to apply admin policy", zap.Error(err))
			return err
		}
		log.Info("✅ Policy applied")

		if revokeRoot {
			log.Info("Revoking the root token now that the eos admin user has been configured...")
			if err := vault.RevokeRootToken(client, initRes.RootToken, log); err != nil {
				log.Error("Failed to revoke root token", zap.Error(err))
				return err
			}
			log.Info("✅ Root token revoked")
		} else {
			log.Info("Skipping root token revocation — use --revoke-root to enable this step")
			log.Info("🔐 Root token is still valid. Run `eos secure vault --revoke-root` when you're ready to revoke it.")
		}

		log.Info("Cleaning up the stored initialization file...")
		system.Rm(vault.DiskPath("vault_init", log), "Vault init file", log)
		log.Info("✅ Done")

		log.Info("Informing the user of the next steps...")
		vault.PrintNextSteps()
		log.Info("✅ Done")

		return nil
	}),
}

func init() {
	SecureCmd.AddCommand(SecureVaultCmd)
	SecureVaultCmd.Flags().BoolVar(&revokeRoot, "revoke-root", false, "Revoke the root token after securing Vault")
}
