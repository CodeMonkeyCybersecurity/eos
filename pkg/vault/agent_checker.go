/* pkg/vault/agent_checker.go */

package vault

import (
	"fmt"
	"os"
	"os/exec"
)

func EnsureVaultAgentRunning() error {
	if err := checkAppRoleFiles(); err != nil {
		return err
	}

	cmd := exec.Command("systemctl", "is-active", "--quiet", "vault-agent-eos.service")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("vault agent service is not active")
	}
	if _, err := os.Stat(VaultAgentTokenPath); err != nil {
		return fmt.Errorf("vault token sink is missing")
	}
	return nil
}

func checkAppRoleFiles() error {
	paths := []string{"/etc/vault/role_id", "/etc/vault/secret_id"}
	for _, path := range paths {
		if _, err := os.Stat(path); err != nil {
			return fmt.Errorf("required AppRole file missing: %s", path)
		}
	}
	return nil
}
