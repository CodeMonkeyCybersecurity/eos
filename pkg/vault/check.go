package vault

import (
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/utils"
	"go.uber.org/zap"
)

// CheckVaultProcesses logs if any Vault-related processes are still running.
func CheckVaultProcesses(log *zap.Logger) {
	output, err := utils.GrepProcess("vault")
	if err != nil {
		log.Warn("Failed to check Vault processes", zap.Error(err))
		return
	}

	if strings.TrimSpace(output) != "" {
		log.Warn("Potential Vault processes still running", zap.String("output", output))
	} else {
		log.Info("No Vault processes detected — system appears clean.")
	}
}

// IsVaultAvailable returns true if Vault is installed and initialized.
func isAvailable() bool {
	return isInstalled() && isInitialized()
}

func isInstalled() bool {
	_, err := exec.LookPath("vault")
	return err == nil
}

func isInitialized() bool {
	out, err := exec.Command("vault", "status", "-format=json").CombinedOutput()
	return err == nil && strings.Contains(string(out), `"initialized": true`)
}
