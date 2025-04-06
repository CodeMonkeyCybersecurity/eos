// pkg/vault/detect.go
package vault

import (
	"os/exec"
	"strings"
)

// IsVaultInstalled checks if the `vault` binary is present in PATH
func IsVaultInstalled() bool {
	_, err := exec.LookPath("vault")
	return err == nil
}

// IsVaultRunning tries a `vault status` call
func IsVaultRunning() bool {
	cmd := exec.Command("vault", "status", "-format=json")
	output, err := cmd.CombinedOutput()
	return err == nil && strings.Contains(string(output), `"initialized": true`)
}
