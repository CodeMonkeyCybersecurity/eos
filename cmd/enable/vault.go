package enable

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// EnableVaultCmd initializes, unseals, and enables Vault for EOS.
var EnableVaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Initializes, unseals, and enables Vault (AppRole + policy)",
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := zap.L()

		log.Info("🔌 Connecting to Vault")
		client, err := vault.EnsureVaultReady(log)
		if err != nil {
			return logger.LogErrAndWrap(log, "enable vault: connect", err)
		}

		// 1️⃣ Initialize Vault (if needed)
		log.Info("🔍 Checking initialization state")
		initialized, err := vault.IsVaultInitialized(client, log)
		if err != nil {
			return logger.LogErrAndWrap(log, "enable vault: check init", err)
		}
		if !initialized {
			log.Info("⚙️ Initializing Vault (first-time setup)")
			initRes, err := vault.InitVault(client, log)
			if err != nil {
				return logger.LogErrAndWrap(log, "enable vault: init", err)
			}
			if err := vault.SaveInitResult(initRes, log); err != nil {
				return logger.LogErrAndWrap(log, "enable vault: save init result", err)
			}
			nonInteractive, _ := cmd.Flags().GetBool("non-interactive")
			if !nonInteractive {
				if err := vault.ConfirmUnsealMaterialSaved(initRes, log); err != nil {
					return logger.LogErrAndWrap(log, "enable vault: confirm save", err)
				}
			}
		}

		// 2️⃣ Unseal Vault
		sealed := vault.IsVaultSealed(client, log)
		if sealed {
			log.Info("🔐 Unsealing Vault")
			initRes, err := vault.LoadInitResultOrPrompt(client, log)
			if err != nil {
				return logger.LogErrAndWrap(log, "enable vault: load init", err)
			}
			if err := vault.UnsealVault(client, initRes, log); err != nil {
				return logger.LogErrAndWrap(log, "enable vault: unseal", err)
			}
		} else {
			log.Info("🟢 Vault is already unsealed — skipping unseal step")
		}

		// 3️⃣ Prompt and validate root token
		log.Info("🔑 Validating root token")
		token, err := vault.PromptRootToken(log)
		if err != nil {
			return logger.LogErrAndWrap(log, "enable vault: prompt token", err)
		}
		if err := vault.ValidateRootToken(client, token); err != nil {
			return logger.LogErrAndWrap(log, "enable vault: invalid token", err)
		}
		vault.SetVaultToken(client, token)

		// 4️⃣ Enable auth methods and upload policy
		log.Info("📜 Enabling userpass & uploading eos-policy")
		if err := vault.EnableUserPass(client); err != nil {
			return logger.LogErrAndWrap(log, "enable vault: enable userpass", err)
		}
		if err := vault.EnsurePolicy(client, log); err != nil {
			return logger.LogErrAndWrap(log, "enable vault: ensure policy", err)
		}
		creds, err := vault.PromptForEosPassword(log)
		if err != nil {
			return logger.LogErrAndWrap(log, "enable vault: prompt creds", err)
		}
		if err := vault.ApplyAdminPolicy(*creds, client, log); err != nil {
			return logger.LogErrAndWrap(log, "enable vault: apply policy", err)
		}

		// 5️⃣ Create AppRole
		log.Info("🔧 Creating AppRole (eos-approle)")
		roleID, secretID, err := vault.EnsureAppRole(client, log, vault.DefaultAppRoleOptions())
		if err != nil {
			return logger.LogErrAndWrap(log, "enable vault: AppRole", err)
		}
		if err := vault.WriteAppRoleFiles(roleID, secretID, log); err != nil {
			return logger.LogErrAndWrap(log, "enable vault: write creds", err)
		}
		// TODO: Support --rotate / --force here

		// 6️⃣ Start Vault Agent & validate token
		log.Info("🤖 Starting Vault Agent and waiting for token")
		if err := vault.EnsureAgent(client, "", log, vault.DefaultAppRoleOptions()); err != nil {
			return logger.LogErrAndWrap(log, "enable vault: agent setup", err)
		}
		tokenPath := shared.VaultTokenSinkPath
		tokenOut, err := vault.WaitForAgentToken(tokenPath, log)
		if err != nil {
			return logger.LogErrAndWrap(log, "enable vault: agent token", err)
		}

		log.Info("🧪 Validating Vault Agent token")
		if err := vault.ValidateRootToken(client, tokenOut); err != nil {
			log.Warn("Agent token appeared but failed validation", zap.Error(err))
			return fmt.Errorf("agent token invalid: %w", err)
		}
		vault.SetVaultToken(client, tokenOut)

		log.Info("✅ Vault is fully initialized, unsealed, and ready for secure use")
		log.Info("ℹ️ Next: run `eos secure vault` to revoke root token and lock down secrets access")
		return nil
	}),
}

func init() {
	EnableVaultCmd.Flags().Bool("non-interactive", false, "Run without interactive prompts")
	EnableCmd.AddCommand(EnableVaultCmd)
}
