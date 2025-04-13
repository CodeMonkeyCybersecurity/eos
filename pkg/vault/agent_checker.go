/* pkg/vault/agent_checker.go */

package vault

import (
	"fmt"
	"os"
	"os/exec"
)

func EnsureVaultAgentRunning() error {
	cmd := exec.Command("systemctl", "is-active", "--quiet", "vault-agent-eos.service")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("vault agent service is not active")
	}
	if _, err := os.Stat("/run/eos/.vault-token"); err != nil {
		return fmt.Errorf("vault token sink is missing")
	}
	return nil
}
