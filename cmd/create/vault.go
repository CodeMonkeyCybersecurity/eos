// cmd/create/vault.go
package create

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
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

		// TODO:
		// ## 2. Detect and Set Vault Environment
		// `EnsureVaultEnv(log *zap.Logger) (string, error)`   // Just resolves VAULT_ADDR

		// ### Decision: EOS Internal Privilege Escalation

		// - EOS CLI will internally use `sudo -u eos` when privileged actions are required (e.g., unseal Vault, access token sink, start systemd units).
		// - EOS will only attempt to read the agent token once Vault Agent is confirmed active and the token file exists with mode 0600 and user `eos`.
		// - In cases where token reading fails, CLI will report and fallback to prompting for manual root token (with `--force` override if needed).

		// - Users **should not** be required to prefix `sudo eos ...`.
		// - This model mirrors the ergonomic style of `docker`, but avoids persistent daemons and overexposed sockets.
		// - Privilege boundaries are enforced in code (e.g., `RunAsEos(...)`) and can be audited centrally.
		// - CLI fallback or override (`--no-sudo`, `--as-user=...`) may be added later for advanced users.
		// - EOS uses `exec.Command("sudo", "-u", shared.EosIdentity, ...)` for privileged actions.
		// - The password prompt, permission checks, and session expiry logic are all handled by `sudo`, not EOS.
		// - EOS never sees or stores user credentials.
		// - Users may be prompted for their password (by the shell) if their sudo timestamp is expired.
		// - EOS will provide optional log lines to explain "why" escalation is occurring (for transparency).
		// - This approach keeps EOS minimal, idiomatic, and fully in line with Unix principles.

		// alice ALL=(eos) NOPASSWD: /usr/bin/systemctl start vault*, /bin/cat /etc/vault-agent-eos.token
		// 	•	Fine-grained access can be granted by restricting allowed commands eg.:
		// alice ALL=(eos) NOPASSWD: /usr/bin/systemctl start vault*, /bin/cat /etc/vault-agent-eos.token

		// 	•	EOS CLI uses sudo -u eos internally; all permission enforcement and password prompting are delegated to the operating system.
		// 	•	No group-based permissions are used or required, avoiding the risks of group-based privilege escalation (as seen with the docker group).
		// 	•	Root users retain full access but should still delegate to the eos user when operating EOS, to maintain consistent privilege boundaries.
		// ---

		// 	✅ This ensures that **every elevation boundary is explicit and auditable**, and EOS remains thin and Unix-idiomatic.

		// ---

		// ### Decision: vault.hcl Configuration
		// - **Port**: Use `8179` as the Vault listener port.
		//   - Reason: Avoid conflicts with default `8200`, fits into a prime-number port scheme.
		// - **Listener Address**: Bind to `0.0.0.0`, but firewall access by default.
		//   - Allows LAN/local trust zone use while maintaining sensible defaults.
		// - **Storage Backend**: Use file backend, stored under `/opt/pandora/data` (EOS Vault home).
		// - **Log Level**: Use `debug` logging by default for now.
		//   - Intentional for early-stage troubleshooting across EOS CLI.
		//   - Will disable/override in future `eos bootstrap` or packaging command.
		// - **Templating**: Decision pending — requires clarification between "Go templating" and "static embedding".

		// -------

		// 1️⃣  Auto‐detect & export VAULT_ADDR
		addr, err := vault.EnsureVaultEnv(log)
		if err != nil {
			log.Error("Failed to set VAULT_ADDR", zap.Error(err))
			return err
		}
		log.Info("✅ VAULT_ADDR resolved", zap.String("VAULT_ADDR", addr))

		log.Info("👤 Ensuring system user ‘eos’ exists")
		if err := system.EnsureEosUser(shared.EosIdentity /*noLogin=*/ true log); err != nil { // TODO: crack out a func EnsureSystemUser()
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

		port := shared.VaultDefaultPort + "/tcp"
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

/**/
