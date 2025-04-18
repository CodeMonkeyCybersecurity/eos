/* cmd/enable/vault */

package enable

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var revokeRoot bool
var forceRecreate bool
var refreshCreds bool

var EnableVaultCmd = &cobra.Command{
	Use:     "vault",
	Aliases: []string{"Pandora"},
	Short:   "Enables Vault with sane and secure defaults",
	Long: `This command assumes "github.com/CodeMonkeyCybersecurity/eos install vault" has been run.
It initializes and unseals Vault, sets up auditing, KV v2, 
AppRole, userpass, and creates an eos user with a random password.`,

	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
		log.Info("[0/7] Starting Vault enable workflow")

		if err := vault.EnsureVault(vault.VaultTestPath, map[string]string{"status": "working"}, log); err != nil {
			log.Error("Failed to initialize Vault lifecycle", zap.Error(err))
			return err
		}

		// Set VAULT_ADDR from hostname
		addr, err := vault.EnsureVaultAddr(log)
		if err != nil {
			log.Error("Failed to set VAULT_ADDR", zap.Error(err))
			return err
		}
		log.Info("Set VAULT_ADDR from hostname", zap.String("VAULT_ADDR", addr))

		/* Write agent config HCL only */
		if err := vault.EnsureAgentConfig(addr, log); err != nil {
			log.Error("Failed to write Vault Agent config", zap.Error(err))
			return err
		}

		/* Create root client → SetupVault() */
		vault.EnsureVaultClient(log)

		client, err := vault.GetVaultClient(log)
		if err != nil {
			log.Fatal("❌ Vault client could not be retrieved after EnsureVaultClient", zap.Error(err))
		}

		client, initRes, err := vault.SetupVault(client, log)
		if err != nil {
			log.Error("Failed to initialize and unseal Vault", zap.Error(err))
			return err
		}

		if initRes == nil {
			log.Warn("Vault already initialized — attempting to load existing credentials")
			initRes, _, _, _ = vault.ReadVaultSecureData(client, log)
		}

		// Prompt the user (or reuse saved) unseal keys and root token
		// Reuse secured Vault data (no prompt)
		var (
			storedHashes []string
			hashedRoot   string
		)

		fallbackInitRes, rawCreds, storedHashes, hashedRoot := vault.ReadVaultSecureData(client, log)
		if initRes == nil {
			initRes = fallbackInitRes
		}
		client.SetToken(initRes.RootToken)

		if rawCreds.Password == "" {
			log.Warn("No stored credentials found — prompting for Vault eos password")
			promptedCreds, err := vault.PromptForEosPassword(log)
			if err != nil {
				log.Error("Failed to get eos password from prompt", zap.Error(err))
				return err
			}
			if promptedCreds != nil {
				rawCreds = *promptedCreds
			}
		}

		client.SetToken(initRes.RootToken)

		log.Info("✅ Vault unsealed and authenticated as eos admin")

		log.Info("Loading the stored initialization data and eos user credentials...")
		vault.Check(client, log, storedHashes, hashedRoot)
		log.Info("✅ Loaded the stored initialization data and eos user credentials")

		/* Run EnsureVaultAgent with known password (not just check) */
		if err := vault.EnsureAgent(client, rawCreds.Password, log, vault.DefaultAppRoleOptions()); err != nil {
			opts := vault.DefaultAppRoleOptions()
			opts.ForceRecreate = forceRecreate
			opts.RefreshCreds = refreshCreds

			if err := vault.EnsureAgent(client, rawCreds.Password, log, opts); err != nil {
				log.Error("Failed to set up Vault Agent", zap.Error(err))
				return err
			}
		}
		log.Info("✅ Vault Agent setup complete")

		/* Create client via agent token sink */
		vault.SetVaultClient(client, log)

		/* Apply audit, KV, AppRole, userpass, etc. */
		log.Info("Enabling file audit")
		if err := vault.EnableFileAudit(client, log); err != nil {
			log.Error("Failed to enable file audit", zap.Error(err))
			return err
		}
		log.Info("✅ File audit enabled successfully")

		log.Info("[2/7] Enabling KV v2 secrets engine")
		if err := vault.EnableKV2(client, log); err != nil {
			log.Error("KV v2 setup failed", zap.Error(err))
		}

		log.Info("[3/7] Testing KV put/get")
		report, _ := vault.Check(client, log, nil, "")
		if report == nil || !report.KVWorking {
			log.Error("KV secret test failed or unavailable")
		}

		log.Info("[4/7] Ensuring AppRole auth method")
		if err := vault.EnsureAppRole(client, log, vault.DefaultAppRoleOptions()); err != nil {
			log.Error("AppRole setup failed", zap.Error(err))
			return err
		}

		log.Info("[5/7] Enabling userpass auth method")
		if err := vault.EnableUserPass(client); err != nil {
			log.Error("Userpass setup failed", zap.Error(err))
			return err
		}

		log.Info("[6/7] Ensuring eos user exists and storing secrets")
		if err := vault.EnsureEosVaultUser(client, log); err != nil {
			log.Error("Failed to create eos user or store secrets", zap.Error(err))
			return err
		}

		log.Info("[7/7] Vault enable workflow complete")
		fmt.Println("\n✅ Vault enable steps completed successfully!")

		/* Apply admin policy */
		log.Info("Applying permissive policy (eos-policy) via the API for eos system user...")
		if err := vault.ApplyAdminPolicy(rawCreds, client, log); err != nil {
			log.Error("Failed to apply admin policy", zap.Error(err))
			return err
		}
		log.Info("✅ Policy applied")

		/* Optionally revoke root token */
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

		/*  Clean up vault_init file */
		log.Info("Cleaning up the stored initialization file...")
		system.Rm(vault.DiskPath("vault_init", log), "Vault init file", log)
		log.Info("✅ Done")

		/* Print next steps */
		log.Info("Informing the user of the next steps...")
		vault.PrintNextSteps()
		log.Info("✅ Done")

		return nil
	}),
}

func init() {
	EnableCmd.AddCommand(EnableVaultCmd)
	EnableCmd.Flags().BoolVar(&revokeRoot, "revoke-root", false, "Revoke the root token after securing Vault")
	EnableVaultCmd.Flags().BoolVar(&forceRecreate, "force-recreate", false, "Force AppRole recreation even if credentials exist")
	EnableVaultCmd.Flags().BoolVar(&refreshCreds, "refresh-creds", false, "Regenerate AppRole credentials if already present")
}
