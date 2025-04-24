// cmd/create/vault.go
package create

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var CreateVaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Installs and initializes HashiCorp Vault in production mode",
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := zap.L()

		// 0️⃣  Must be Debian or RHEL
		if err := platform.RequireLinuxDistro([]string{"debian", "rhel"}, log); err != nil {
			log.Fatal("Unsupported OS/distro for Vault deployment", zap.Error(err))
		}

		// 1️⃣  Auto‐detect & export VAULT_ADDR
		addr, err := vault.EnsureVaultEnv(log)
		if err != nil {
			log.Error("Failed to set VAULT_ADDR", zap.Error(err))
			return err
		}
		log.Info("✅ VAULT_ADDR resolved", zap.String("VAULT_ADDR", addr))

		log.Info("👤 Ensuring system user ‘eos’ exists")
		if err := platform.EnsureSystemUser("eos" /*noLogin=*/, true, log); err != nil {
			return fmt.Errorf("ensure eos user: %w", err)
		}

		log.Info("🧼 Preparing all Vault directories, files, and ownership")
		if err := vault.EnsureVaultDirs(log); err != nil {
			return fmt.Errorf("prepare vault dirs: %w", err)
		}

		// 4️⃣  Fire off the full Vault installation+init
		// Includes now   GenerateVaultTLSCert(log) TrustVaultCA(log) as first and second calls
		//

		// 5️⃣ Provision & start Vault Agent (AppRole, creds, HCL, systemd)
		client, err := vault.EnsureVault("bootstrap/test", map[string]string{"status": "ok"}, log)
		if err != nil {
			log.Error("Vault setup failed", zap.Error(err))
			return err
		}

		log.Info("🚀 Setting up Vault Agent (AppRole, systemd, token sink)")
		if err := vault.EnsureAgent(client, "", log, vault.DefaultAppRoleOptions()); err != nil {
			log.Error("❌ Vault Agent provisioning failed", zap.Error(err))
			return err
		}
		log.Info("🔑 Vault Agent token will be available at", zap.String("sink", vault.VaultTokenSinkPath))

		port := vault.VaultDefaultPort + "/tcp"
		if err := platform.AllowPorts(log, []string{port}); err != nil {
			log.Error("Vault port allowing failed", zap.Error(err))
			return fmt.Errorf("failed to open Vault web UI port: %w", err)
		}

		log.Info("✅ Vault Web UI should now be reachable on port 8179")

		log.Info("✅ Vault install & initialization complete")
		return nil
	}),
}

func init() {
	CreateCmd.AddCommand(CreateVaultCmd)
}
