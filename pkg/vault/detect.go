// pkg/vault/detect.go
package vault

import (
	"os/exec"
	"strings"
)

// isVaultAvailable returns true if Vault is installed and running.
func isAvailable() bool {
	return isVaultInstalled() && isVaultRunning()
}

// isVaultInstalled checks if the Vault binary is present in $PATH.
func isVaultInstalled() bool {
	_, err := exec.LookPath("vault")
	return err == nil
}

// isVaultRunning runs `vault status` and checks for initialization.
func isVaultRunning() bool {
	out, err := exec.Command("vault", "status", "-format=json").CombinedOutput()
	return err == nil && strings.Contains(string(out), `"initialized": true`)
}
