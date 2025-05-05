// pkg/vault/ phase12_start_agent_validate.go

package vault

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

//--------------------------------------------------------------------
// 12. Start Vault Agent Service and Validate Token
//--------------------------------------------------------------------

// PHASE 12 — PhaseStartVaultAgentAndValidate()
//            └── StartVaultAgentService()
//            └── WaitForAgentToken()
//            └── readTokenFromSink()
//            └── SetVaultToken()

// PhaseStartVaultAgentAndValidate starts the vault-agent-eos.service and validates the agent token.
func PhaseStartVaultAgentAndValidate(client *api.Client) error {
	zap.L().Info("🚀 [Phase 12] Starting Vault Agent and validating token")

	if err := StartVaultAgentService(); err != nil {
		return fmt.Errorf("start vault agent service: %w", err)
	}

	tokenPath := shared.AgentToken

	token, err := WaitForAgentToken(tokenPath)
	if err != nil {
		return fmt.Errorf("wait for agent token: %w", err)
	}

	SetVaultToken(client, token)

	zap.L().Info("✅ Vault Agent token acquired and client updated")
	return nil
}

// StartVaultAgentService installs, enables, and starts the Vault AGENT (vault-agent-eos.service).
func StartVaultAgentService() error {
	zap.L().Info("🛠️ Writing Vault AGENT systemd unit file")
	if err := WriteAgentSystemdUnit(); err != nil {
		return fmt.Errorf("write agent systemd unit: %w", err)
	}

	zap.L().Info("🔄 Reloading systemd daemon and enabling vault-agent-eos.service")
	if err := system.ReloadDaemonAndEnable(shared.VaultAgentService); err != nil {
		return fmt.Errorf("reload/enable vault-agent-eos.service: %w", err)
	}

	zap.L().Info("✅ Vault agent systemd service installed and started")
	return nil
}

// WaitForAgentToken polls for a token to appear at a given path, with a timeout.
func WaitForAgentToken(path string) (string, error) {
	zap.L().Info("⏳ Waiting for Vault agent token", zap.String("path", path))

	start := time.Now()

	for time.Since(start) < shared.MaxWait {
		content, err := os.ReadFile(path)
		if err == nil && len(content) > 0 {
			token := strings.TrimSpace(string(content))
			zap.L().Info("✅ Agent token found", zap.String("token_path", path))
			return token, nil
		}
		time.Sleep(shared.Interval)
	}
	return "", fmt.Errorf("agent token not found after %s", shared.MaxWait)
}

// readTokenFromSink reads the Vault Agent token (run as 'eos' system user)
func readTokenFromSink(path string) (string, error) {
	if path == "" {
		path = shared.AgentToken
	}
	out, err := exec.Command("cat", path).Output()
	if err != nil {
		return "", fmt.Errorf("failed to read token from Vault Agent sink at %s: %w", path, err)
	}
	return strings.TrimSpace(string(out)), nil
}
