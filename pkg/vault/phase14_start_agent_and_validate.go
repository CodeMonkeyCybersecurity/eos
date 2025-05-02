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
func PhaseStartVaultAgentAndValidate(client *api.Client, log *zap.Logger) error {
	log.Info("🚀 [Phase 12] Starting Vault Agent and validating token")

	if err := StartVaultAgentService(log); err != nil {
		return fmt.Errorf("start vault agent service: %w", err)
	}

	tokenPath := shared.VaultAgentTokenPath

	token, err := WaitForAgentToken(tokenPath, log)
	if err != nil {
		return fmt.Errorf("wait for agent token: %w", err)
	}

	SetVaultToken(client, token)

	log.Info("✅ Vault Agent token acquired and client updated")
	return nil
}

// StartVaultAgentService installs, enables, and starts the Vault AGENT (vault-agent-eos.service).
func StartVaultAgentService(log *zap.Logger) error {
	log.Info("🛠️ Writing Vault AGENT systemd unit file")
	if err := WriteAgentSystemdUnit(log); err != nil {
		return fmt.Errorf("write agent systemd unit: %w", err)
	}

	log.Info("🔄 Reloading systemd daemon and enabling vault-agent-eos.service")
	if err := system.ReloadDaemonAndEnable(log, shared.VaultAgentService); err != nil {
		return fmt.Errorf("reload/enable vault-agent-eos.service: %w", err)
	}

	log.Info("✅ Vault agent systemd service installed and started")
	return nil
}

// WaitForAgentToken polls for a token to appear at a given path, with a timeout.
func WaitForAgentToken(path string, log *zap.Logger) (string, error) {
	log.Info("⏳ Waiting for Vault agent token", zap.String("path", path))

	const maxWait = 30 * time.Second
	const interval = 500 * time.Millisecond
	start := time.Now()

	for time.Since(start) < maxWait {
		content, err := os.ReadFile(path)
		if err == nil && len(content) > 0 {
			token := strings.TrimSpace(string(content))
			log.Info("✅ Agent token found", zap.String("token_path", path))
			return token, nil
		}
		time.Sleep(interval)
	}
	return "", fmt.Errorf("agent token not found after %s", maxWait)
}

// readTokenFromSink reads the Vault Agent token (run as 'eos' system user)
func readTokenFromSink(path string) (string, error) {
	if path == "" {
		path = shared.VaultAgentTokenPath
	}
	out, err := exec.Command("cat", path).Output()
	if err != nil {
		return "", fmt.Errorf("failed to read token from Vault Agent sink at %s: %w", path, err)
	}
	return strings.TrimSpace(string(out)), nil
}
