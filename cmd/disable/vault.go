/* cmd/disable/disable.go */

package disable

import (
	"os"
	"os/exec"
	"strconv"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var StopVaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Stops the Vault Agent and cleans up residual files",
	Long: `Stops the vault-agent-eos.service, kills anything still bound to port 8179,
and removes leftover files including config, runtime, and token sink artifacts.`,
	RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {
		log.Info("🛑 Stopping Vault Agent and cleaning up...")

		// Step 1: Stop systemd service
		if err := exec.Command("systemctl", "disable", "--now", "vault-agent-eos.service").Run(); err != nil {
			log.Warn("Failed to disable vault-agent-eos.service", zap.Error(err))
		} else {
			log.Info("✅ Vault Agent service stopped and disabled")
		}

		// Step 2: Kill any process using port 8179
		out, err := exec.Command("lsof", "-i", ":8179", "-t").Output()
		if err == nil && len(out) > 0 {
			for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
				if pid, err := strconv.Atoi(line); err == nil {
					if killErr := exec.Command("kill", "-9", strconv.Itoa(pid)).Run(); killErr == nil {
						log.Info("✅ Killed process using port 8179", zap.Int("pid", pid))
					}
				}
			}
		} else {
			log.Info("ℹ️  No process found using port 8179")
		}

		// Step 3: Remove config and runtime artifacts
		paths := []string{
			"/etc/vault-agent-eos.hcl",
			"/etc/vault-agent-eos.pass",
			"/etc/systemd/system/vault-agent-eos.service",
			"/etc/vault/role_id",
			"/etc/vault/secret_id",
			"/etc/vault",
			"/run/eos",
			"/var/lib/eos",
		}

		for _, path := range paths {
			if err := os.RemoveAll(path); err == nil {
				log.Info("🧹 Removed", zap.String("path", path))
			}
		}

		// Step 4: Reload systemd
		if err := exec.Command("systemctl", "daemon-reexec").Run(); err == nil {
			log.Info("🔄 systemd reexec complete")
		}
		if err := exec.Command("systemctl", "daemon-reload").Run(); err == nil {
			log.Info("🔄 systemd reload complete")
		}

		log.Info("✅ Vault Agent stopped and cleaned up.")
		return nil
	}),
}

func init() {
	DisableCmd.AddCommand(StopVaultCmd)
}
