// cmd/create/vault.go
package create

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var CreateVaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Installs Vault with TLS and systemd service (no init/unseal)",
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := ctx.Log.Named("create-vault")

		log.Info("📦 [1/6] Ensuring Vault binary is installed")
		if err := vault.PhaseInstallVault(log); err != nil {
			return logger.LogErrAndWrap(log, "create vault: install vault", err)
		}

		log.Info("Configuring Vault server")
		if err := vault.PhasePatchVaultConfigIfNeeded(log); err != nil {
			return fmt.Errorf("configure vault: %w", err)
		}

		log.Info("🌍 Resolving Vault environment address")
		addr, err := vault.EnsureVaultEnv(log)
		if err != nil {
			return logger.LogErrAndWrap(log, "create vault: set VAULT_ADDR", err)
		}

		log.Info("Initializing Vault")
		client, err := vault.NewClient(log)
		if err != nil {
			return fmt.Errorf("create client: %w", err)
		}

		client, err = vault.PhaseInitAndUnsealVault(client, log)
		if err != nil {
			log.Error("init and unseal vault failed", zap.Error(err))
			return fmt.Errorf("init and unseal vault: %w", err)
		}

		// Placeholder values - these need to be set properly
		kvPath := "secret/config"
		kvData := map[string]string{"example_key": "example_value"}

		log.Info("Bootstrapping Vault secrets")
		if err := vault.PhaseApplyCoreSecrets(client, kvPath, kvData, log); err != nil {
			return fmt.Errorf("bootstrap vault secrets: %w", err)
		}

		log.Info("✅ VAULT_ADDR resolved", zap.String("VAULT_ADDR", addr))

		log.Info("👤 [2/6] Ensuring eos system user")
		if err := system.EnsureEosUser(true, false, log); err != nil {
			return logger.LogErrAndWrap(log, "create vault: ensure eos user", err)
		}

		log.Info("📁 [3/6] Preparing Vault filesystem")
		if err := vault.EnsureVaultDirs(log); err != nil {
			return logger.LogErrAndWrap(log, "create vault: ensure dirs", err)
		}

		log.Info("🔐 [4/6] Generating TLS certificates")
		log.Warn("⚠️ Vault TLS cert will be self-signed. Use --cert/--key to override.")
		log.Warn("⚠️ This certificate is valid only for local development. Do not use in production.")
		if err := vault.GenerateVaultTLSCert(log); err != nil {
			return logger.LogErrAndWrap(log, "create vault: generate TLS", err)
		}
		if err := vault.TrustVaultCA(log); err != nil {
			return logger.LogErrAndWrap(log, "create vault: trust CA", err)
		}

		log.Info("⚙️ [5/6] Writing vault.hcl config")
		if err := vault.WriteVaultHCL(log); err != nil {
			return logger.LogErrAndWrap(log, "create vault: write config", err)
		}

		log.Info("🧱 Validating Vault service configuration")
		if err := vault.ValidateVaultConfig(log); err != nil {
			return logger.LogErrAndWrap(log, "create vault: validate config", err)
		}

		log.Info("🧱 [6/6] Starting Vault systemd service")
		if err := vault.StartVaultService(log); err != nil {
			return logger.LogErrAndWrap(log, "create vault: start service", err)
		}

		log.Info("🩺 Verifying Vault health after service start")
		if status, err := vault.CheckVaultHealth(log); err != nil {
			log.Error("🚨 Vault service started but health check failed", zap.String("status", status), zap.Error(err))
			return fmt.Errorf("vault health check: %w", err)
		}

		log.Info("ℹ️ Vault is running, but may still need manual initialization/unsealing if required.")

		log.Info("✅ Vault installation complete — ready for secure provisioning.")
		return nil
	}),
}

func init() {
	CreateCmd.AddCommand(CreateVaultCmd)
}