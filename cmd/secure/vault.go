package secure

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// SecureVaultCmd performs post-init hardening of Vault.
// This includes AppRole setup, Vault Agent token validation,
// and optional root token revocation.
var SecureVaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Applies hardening and provisioning to a running Vault instance",
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := zap.L()

		log.Info("🔐 Connecting to Vault")
		client, err := vault.EnsureVaultReady(log)
		if err != nil {
			return logger.LogErrAndWrap(log, "secure vault: connect failed", err)
		}

		if vault.IsVaultSealed(client, log) {
			return fmt.Errorf("Vault is sealed — please run `eos enable vault` before `secure vault`")
		}

		// 1️⃣ Ensure EOS Policy
		log.Info("📜 Ensuring eos-policy exists")
		if err := vault.EnsurePolicy(client, log); err != nil {
			return logger.LogErrAndWrap(log, "secure vault: ensure policy", err)
		}

		// 2️⃣ Ensure AppRole method is mounted
		log.Info("🪪 Ensuring approle auth method is enabled")
		if err := vault.EnsureAppRoleAuth(client, log); err != nil {
			return logger.LogErrAndWrap(log, "secure vault: enable approle", err)
		}

		// 3️⃣ Re-provision AppRole (idempotent)
		log.Info("🔁 Re-confirming eos-approle settings")
		roleID, secretID, err := vault.EnsureAppRole(client, log, vault.DefaultAppRoleOptions())
		if err != nil {
			return logger.LogErrAndWrap(log, "secure vault: create approle", err)
		}
		if err := vault.WriteAppRoleFiles(roleID, secretID, log); err != nil {
			return logger.LogErrAndWrap(log, "secure vault: write approle creds", err)
		}
		log.Info("✅ AppRole written", zap.String("role_id", roleID), zap.String("secret_id", secretID))

		// 4️⃣ Validate Vault Agent Token
		log.Info("🤖 Validating Vault Agent token")
		token, err := vault.WaitForAgentToken(shared.VaultTokenSinkPath, log)
		if err != nil {
			log.Warn("🚨 Vault Agent token is missing or unreadable. Check ownership/permissions", zap.Error(err))
			return fmt.Errorf("vault-agent token check failed: %w", err)
		}
		if err := vault.ValidateRootToken(client, token); err != nil {
			log.Warn("🚨 Token retrieved, but failed Vault authentication", zap.Error(err))
			return fmt.Errorf("invalid agent token: %w", err)
		}
		vault.SetVaultToken(token)

		// 5️⃣ Optionally revoke root token
		if ctx.Flags.ShouldRevokeRoot {
			log.Warn("🚨 Revoking root token (irreversible)")
			if err := vault.RevokeRootToken(client, "", log); err != nil {
				return logger.LogErrAndWrap(log, "secure vault: revoke root", err)
			}
		}

		// 6️⃣ Done!
		log.Info("🔒 Vault is now fully hardened and ready for production")
		// TODO: Add eos.PrintNextSteps("vault") or eos.InspectVaultSummary(client)

		return nil
	}),
}

func init() {
	SecureCmd.AddCommand(SecureVaultCmd)
}
