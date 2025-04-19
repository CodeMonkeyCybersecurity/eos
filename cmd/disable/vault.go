// cmd/disable/vault.go
package disable

import (
	"os/exec"
	"strconv"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var StopVaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Stops the Vault Agent and cleans residual files",
	Long:  "Disables vault‑agent‑eos.service, kills anything on port 8179, then purges Vault runtime artefacts.",
	RunE:  eos.Wrap(runStopVault),
}

func init() { DisableCmd.AddCommand(StopVaultCmd) }

// -----------------------------------------------------------------------------
// implementation helpers
// -----------------------------------------------------------------------------

func runStopVault(ctx *eos.RuntimeContext, _ *cobra.Command, _ []string) error {
	log := ctx.Log
	log.Info("🛑 Stopping Vault Agent and cleaning up…")

	// ① stop+disable the systemd unit
	if err := systemctl("disable", "--now", vault.VaultAgentService); err != nil {
		log.Warn("Failed to disable service", zap.String("unit", vault.VaultAgentService), zap.Error(err))
	} else {
		log.Info("✅ Service stopped & disabled", zap.String("unit", vault.VaultAgentService))
	}

	// ② kill anything still bound to VaultDefaultPort
	if killed := killByPort(vault.VaultDefaultPort, log); killed == 0 {
		log.Info("ℹ️  No process bound to "+vault.VaultDefaultPort, zap.String("port", vault.VaultDefaultPort))
	}

	// ③ purge runtime/config files via existing helper
	removed, errs := vault.Purge("rhel", log) // distro param only matters for repo files
	log.Info("🧹  File purge summary",
		zap.Int("removed", len(removed)),
		zap.Int("errors", len(errs)),
	)

	// ④ reload systemd once at the end
	_ = systemctl("daemon-reexec")
	_ = systemctl("daemon-reload")

	log.Info("✅ Vault Agent stopped and cleaned")
	return nil
}

// ------------------------ util helpers ---------------------------------------

func systemctl(args ...string) error { return exec.Command("systemctl", args...).Run() }

func killByPort(port string, log *zap.Logger) int {
	out, err := exec.Command("lsof", "-i", ":"+port, "-t").Output()
	if err != nil || len(out) == 0 {
		return 0
	}
	pids := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, p := range pids {
		if pid, _ := strconv.Atoi(p); pid != 0 {
			_ = exec.Command("kill", "-9", strconv.Itoa(pid)).Run()
			log.Info("🔪 Killed process on port "+port, zap.Int("pid", pid))
		}
	}
	return len(pids)
}
