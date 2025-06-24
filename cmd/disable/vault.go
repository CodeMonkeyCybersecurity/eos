// cmd/disable/vault.go
package disable

import (
	"os/exec"
	"strconv"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
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

func runStopVault(rc *eos_io.RuntimeContext, _ *cobra.Command, _ []string) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info("🛑 Stopping Vault Agent and cleaning up…")

	// ① stop+disable the systemd unit
	if err := systemctl("disable", "--now", shared.VaultAgentService); err != nil {
		log.Warn("Failed to disable service", zap.String("unit", shared.VaultAgentService), zap.Error(err))
	} else {
		log.Info(" Service stopped & disabled", zap.String("unit", shared.VaultAgentService))
	}

	// ② kill anything still bound to VaultDefaultPort
	if killed := killByPort(rc, shared.VaultDefaultPort); killed == 0 {
		log.Info("  No process bound to "+shared.VaultDefaultPort, zap.String("port", shared.VaultDefaultPort))
	}

	// ③ purge runtime/config files via existing helper
	removed, errs := vault.Purge(rc, "rhel") // distro param only matters for repo files
	log.Info("🧹  File purge summary",
		zap.Int("removed", len(removed)),
		zap.Int("errors", len(errs)),
	)

	// ④ reload systemd once at the end
	_ = systemctl("daemon-reexec")
	_ = systemctl("daemon-reload")

	log.Info(" Vault Agent stopped and cleaned")
	return nil
}

// ------------------------ util helpers ---------------------------------------

func systemctl(args ...string) error { return exec.Command("systemctl", args...).Run() }

func killByPort(rc *eos_io.RuntimeContext, port string) int {
	out, err := exec.Command("lsof", "-i", ":"+port, "-t").Output()
	if err != nil || len(out) == 0 {
		return 0
	}
	pids := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, p := range pids {
		if pid, _ := strconv.Atoi(p); pid != 0 {
			_ = exec.Command("kill", "-9", strconv.Itoa(pid)).Run()
			otelzap.Ctx(rc.Ctx).Info("🔪 Killed process on port "+port, zap.Int("pid", pid))
		}
	}
	return len(pids)
}
