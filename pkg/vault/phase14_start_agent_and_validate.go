// pkg/vault/ phase14_start_agent__and_verify.go

package vault

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
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

func PhaseStartVaultAgentAndValidate(rc *eos_io.RuntimeContext, client *api.Client) error {
	otelzap.Ctx(rc.Ctx).Info("🚀 Starting Vault Agent and validating token")

	// Ensure runtime directory exists before starting service
	if err := ensureRuntimeDirectory(rc); err != nil {
		return fmt.Errorf("ensure runtime directory: %w", err)
	}

	if err := startVaultAgentService(rc); err != nil {
		// Enhanced error handling - get systemd logs to help with troubleshooting
		if logErr := logSystemdServiceStatus(rc, shared.VaultAgentService); logErr != nil {
			otelzap.Ctx(rc.Ctx).Warn("⚠️ Failed to retrieve service logs", zap.Error(logErr))
		}
		return fmt.Errorf("start agent service: %w", err)
	}

	tokenPath := shared.AgentToken
	token, err := WaitForAgentToken(tokenPath, shared.MaxWait)
	if err != nil {
		// Enhanced error handling - get systemd logs when token acquisition fails
		if logErr := logSystemdServiceStatus(rc, shared.VaultAgentService); logErr != nil {
			otelzap.Ctx(rc.Ctx).Warn("⚠️ Failed to retrieve service logs for token wait failure", zap.Error(logErr))
		}
		return fmt.Errorf("wait for agent token: %w", err)
	}
	SetVaultToken(rc, client, token)

	otelzap.Ctx(rc.Ctx).Info("✅ Vault Agent token acquired", zap.String("path", tokenPath))
	return nil
}

// startVaultAgentService just does one thing: reload → enable & start.
func startVaultAgentService(rc *eos_io.RuntimeContext) error {
	unit := shared.VaultAgentService
	otelzap.Ctx(rc.Ctx).Info("🔄 Enabling and starting service", zap.String("unit", unit))
	if err := eos_unix.ReloadDaemonAndEnable(rc.Ctx, unit); err != nil {
		return err
	}
	return nil
}

// waitForAgentToken polls until the sink file contains non-empty content.
// Runs as the eos user to avoid permission issues with /run/eos directory.
func WaitForAgentToken(path string, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		// Use sudo -u eos to read the token file since /run/eos is owned by eos user
		cmd := exec.Command("sudo", "-u", shared.EosID, "cat", path)
		if data, err := cmd.Output(); err == nil && len(data) > 0 {
			return strings.TrimSpace(string(data)), nil
		}
		time.Sleep(shared.Interval)
	}
	return "", fmt.Errorf("token not found at %s after %s", path, timeout)
}

// readTokenFromSink reads the Vault Agent token (run as 'eos' system user)
func readTokenFromSink(rc *eos_io.RuntimeContext, path string) (string, error) {
	otelzap.Ctx(rc.Ctx).Debug("Reading Vault Agent token from sink", zap.String("path", path))
	if path == "" {
		path = shared.AgentToken
	}
	out, err := exec.Command("cat", path).Output()
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error("Failed to read token via shell", zap.String("path", path), zap.Error(err))
		return "", fmt.Errorf("failed to read token from Vault Agent sink at %s: %w", path, err)
	}
	token := strings.TrimSpace(string(out))
	otelzap.Ctx(rc.Ctx).Debug("Token read via shell", zap.Int("length", len(token)))

	return token, nil
}

// ensureRuntimeDirectory creates /run/eos directory with proper permissions before starting Vault Agent
func ensureRuntimeDirectory(rc *eos_io.RuntimeContext) error {
	runDir := "/run/eos"
	
	// Create directory if it doesn't exist
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		return fmt.Errorf("create runtime directory %s: %w", runDir, err)
	}
	
	// Set proper ownership (eos user)
	uid, gid, err := eos_unix.LookupUser(rc.Ctx, shared.EosID)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Warn("⚠️ Could not lookup eos user, using root ownership", zap.Error(err))
		return nil // Continue with root ownership rather than failing
	}
	
	if err := os.Chown(runDir, uid, gid); err != nil {
		otelzap.Ctx(rc.Ctx).Warn("⚠️ Could not change ownership of runtime directory", zap.String("dir", runDir), zap.Error(err))
		return nil // Continue rather than failing
	}
	
	otelzap.Ctx(rc.Ctx).Info("✅ Runtime directory prepared", zap.String("path", runDir))
	return nil
}

// logSystemdServiceStatus retrieves and logs systemd service status and recent journal entries for troubleshooting
func logSystemdServiceStatus(rc *eos_io.RuntimeContext, serviceName string) error {
	log := otelzap.Ctx(rc.Ctx)
	
	// Get service status
	statusCmd := exec.CommandContext(rc.Ctx, "systemctl", "status", serviceName, "--no-pager")
	statusOutput, statusErr := statusCmd.CombinedOutput()
	if statusErr != nil {
		log.Info("🔍 Service status (may be failing)", 
			zap.String("service", serviceName),
			zap.String("output", string(statusOutput)))
	} else {
		log.Info("🔍 Service status", 
			zap.String("service", serviceName),
			zap.String("output", string(statusOutput)))
	}
	
	// Get recent journal entries
	journalCmd := exec.CommandContext(rc.Ctx, "journalctl", "-u", serviceName, "--no-pager", "-n", "20")
	journalOutput, journalErr := journalCmd.CombinedOutput()
	if journalErr != nil {
		log.Warn("⚠️ Failed to get journal logs", zap.String("service", serviceName), zap.Error(journalErr))
	} else {
		log.Info("📋 Recent journal entries", 
			zap.String("service", serviceName),
			zap.String("logs", string(journalOutput)))
	}
	
	return nil
}
