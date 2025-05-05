// pkg/vault/ phase14_start_agent__and_verify.go

package vault

import (
	"errors"
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
	zap.L().Info("🚀 [Phase 14] Starting Vault Agent and validating token")

	zap.L().Debug("About to install & start systemd unit", zap.String("unit", shared.VaultAgentService))
	if err := StartVaultAgentService(); err != nil {
		zap.L().Error("Failed to start Vault Agent service", zap.String("unit", shared.VaultAgentService), zap.Error(err))
		return fmt.Errorf("start vault agent service (%s): %w", shared.VaultAgentService, err)

	}

	tokenPath := shared.AgentToken
	zap.L().Info("Looking for agent token file", zap.String("path", tokenPath))

	token, err := WaitForAgentToken(tokenPath)
	if err != nil {
		zap.L().Error("Timeout waiting for Vault Agent token", zap.String("path", tokenPath), zap.Error(err))
		return fmt.Errorf("wait for agent token at %s: %w", tokenPath, err)
	}

	zap.L().Debug("Raw token content", zap.String("token_sample", func() string {
		if len(token) > 8 {
			return token[:8] + "…"
		}
		return token
	}()))

	SetVaultToken(client, token)

	zap.L().Info("✅ Vault Agent token acquired and client updated",
		zap.String("token_path", tokenPath),
		zap.Int("token_length", len(token)),
	)
	return nil
}

// StartVaultAgentService installs, enables, and starts the Vault AGENT (vault-agent-eos.service).
func StartVaultAgentService() error {
	zap.L().Info("🛠️ Writing Vault AGENT systemd unit file")
	if err := WriteAgentSystemdUnit(); err != nil {
		zap.L().Error("Failed to render systemd unit file", zap.String("path", shared.VaultAgentServicePath), zap.Error(err))
		return fmt.Errorf("write agent systemd unit file (%s): %w", shared.VaultAgentServicePath, err)
	}

	zap.L().Info("🔄 Reloading systemd daemon & enabling service", zap.String("unit", shared.VaultAgentService))
	if err := system.ReloadDaemonAndEnable(shared.VaultAgentService); err != nil {
		// systemctl output often contains both stdout/stderr
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			zap.L().Error("systemctl reload/enable failed", zap.String("unit", shared.VaultAgentService), zap.ByteString("output", exitErr.Stderr))
		} else {
			zap.L().Error("systemctl reload/enable error", zap.String("unit", shared.VaultAgentService), zap.Error(err))
		}
		return fmt.Errorf("reload/enable %s: %w", shared.VaultAgentService, err)
	}

	zap.L().Info("✅ Vault agent systemd service installed and started")
	return nil
}

// WaitForAgentToken polls for a token to appear at a given path, with a timeout.
func WaitForAgentToken(path string) (string, error) {
	zap.L().Info("⏳ Waiting for Vault agent token", zap.String("path", path), zap.Duration("timeout", shared.MaxWait))

	start := time.Now()

	for time.Since(start) < shared.MaxWait {
		content, err := os.ReadFile(path)
		if err != nil {
			zap.L().Debug("Token file not yet ready", zap.String("path", path), zap.Error(err))
		} else if len(content) == 0 {
			zap.L().Debug("Token file empty, retrying", zap.String("path", path))
		} else {
			token := strings.TrimSpace(string(content))
			zap.L().Info("✅ Agent token found", zap.String("token_path", path))
			return token, nil
		}
		time.Sleep(shared.Interval)
	}
	return "", fmt.Errorf("agent token not found after %s (looked at %s)", shared.MaxWait, path)
}

// readTokenFromSink reads the Vault Agent token (run as 'eos' system user)
func readTokenFromSink(path string) (string, error) {
	zap.L().Debug("Reading Vault Agent token from sink", zap.String("path", path))
	if path == "" {
		path = shared.AgentToken
	}
	out, err := exec.Command("cat", path).Output()
	if err != nil {
		zap.L().Error("Failed to read token via shell", zap.String("path", path), zap.Error(err))
		return "", fmt.Errorf("failed to read token from Vault Agent sink at %s: %w", path, err)
	}
	token := strings.TrimSpace(string(out))
	zap.L().Debug("Token read via shell", zap.Int("length", len(token)))

	return token, nil
}
