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
	otelzap.Ctx(rc.Ctx).Info(" Starting Vault Agent and validating token")

	// Ensure runtime directory exists before starting service
	if err := ensureRuntimeDirectory(rc); err != nil {
		return fmt.Errorf("ensure runtime directory: %w", err)
	}

	if err := startVaultAgentService(rc); err != nil {
		// Enhanced error handling - get systemd logs to help with troubleshooting
		if logErr := logSystemdServiceStatus(rc, shared.VaultAgentService); logErr != nil {
			otelzap.Ctx(rc.Ctx).Warn("Failed to retrieve service logs", zap.Error(logErr))
		}
		return fmt.Errorf("start agent service: %w", err)
	}

	// Wait a moment for the service to fully start and begin authentication
	otelzap.Ctx(rc.Ctx).Info(" Allowing time for Vault Agent service to start and authenticate")
	// SECURITY P2 #7: Use context-aware sleep to respect cancellation
	agentStartupWait := 3 * time.Second
	select {
	case <-time.After(agentStartupWait):
		// Continue to token wait
	case <-rc.Ctx.Done():
		return fmt.Errorf("vault agent startup wait cancelled: %w", rc.Ctx.Err())
	}

	tokenPath := shared.AgentToken
	token, err := WaitForAgentToken(rc, tokenPath, shared.MaxWait)
	if err != nil {
		// Enhanced error handling - get systemd logs when token acquisition fails
		if logErr := logSystemdServiceStatus(rc, shared.VaultAgentService); logErr != nil {
			otelzap.Ctx(rc.Ctx).Warn("Failed to retrieve service logs for token wait failure", zap.Error(logErr))
		}
		return fmt.Errorf("wait for agent token: %w", err)
	}
	SetVaultToken(rc, client, token)

	otelzap.Ctx(rc.Ctx).Info(" Vault Agent token acquired", zap.String("path", tokenPath))
	return nil
}

// startVaultAgentService just does one thing: reload → enable & start.
func startVaultAgentService(rc *eos_io.RuntimeContext) error {
	unit := shared.VaultAgentService
	log := otelzap.Ctx(rc.Ctx)

	log.Info(" Reloading systemd daemon and enabling Vault Agent service", zap.String("unit", unit))

	// Check current service status before restart
	if statusCmd := exec.Command("systemctl", "is-active", unit); statusCmd.Run() == nil {
		log.Info(" Service is currently active - it will be restarted", zap.String("unit", unit))
	} else {
		log.Info(" Service is not currently active - it will be started", zap.String("unit", unit))
	}

	if err := eos_unix.ReloadDaemonAndEnable(rc.Ctx, unit); err != nil {
		log.Error(" Failed to reload daemon and enable service",
			zap.String("unit", unit),
			zap.Error(err))
		return err
	}

	log.Info(" Service reload and enable completed", zap.String("unit", unit))
	return nil
}

// waitForAgentToken polls until the sink file contains non-empty content.
// Runs as the eos user to avoid permission issues with /run/eos directory.
func WaitForAgentToken(rc *eos_io.RuntimeContext, path string, timeout time.Duration) (string, error) {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Waiting for Vault Agent token",
		zap.String("path", path),
		zap.Duration("timeout", timeout))

	deadline := time.Now().Add(timeout)
	attempt := 0

	for time.Now().Before(deadline) {
		attempt++

		// Check file and directory status on each attempt for detailed debugging
		parentDir := "/run/eos"
		if dirStat, err := os.Stat(parentDir); err != nil {
			if os.IsNotExist(err) {
				log.Warn(" Parent directory does not exist",
					zap.Int("attempt", attempt),
					zap.String("dir", parentDir),
					zap.Error(err))
			}
		} else {
			log.Debug(" Parent directory status",
				zap.Int("attempt", attempt),
				zap.String("dir", parentDir),
				zap.String("mode", dirStat.Mode().String()))
		}

		if stat, err := os.Stat(path); err != nil {
			if os.IsNotExist(err) {
				log.Debug(" Token file does not exist yet",
					zap.Int("attempt", attempt),
					zap.String("path", path),
					zap.Error(err))
			} else {
				log.Warn(" Cannot stat token file",
					zap.Int("attempt", attempt),
					zap.String("path", path),
					zap.Error(err))
			}
		} else {
			log.Info(" Token file found",
				zap.Int("attempt", attempt),
				zap.String("path", path),
				zap.String("mode", stat.Mode().String()),
				zap.Int64("size", stat.Size()))
		}

		// Use sudo -u vault to read the token file since /run/eos is now owned by vault user
		cmd := exec.Command("sudo", "-u", "vault", "cat", path)
		if data, err := cmd.Output(); err == nil && len(data) > 0 {
			log.Info(" Token acquired successfully",
				zap.Int("attempt", attempt),
				zap.String("path", path),
				zap.Int("token_length", len(data)))
			return strings.TrimSpace(string(data)), nil
		} else {
			if attempt%10 == 1 || attempt <= 5 { // Log first 5 attempts and every 10th after
				log.Warn(" Failed to read token",
					zap.Int("attempt", attempt),
					zap.String("path", path),
					zap.Error(err))
			}
		}

		time.Sleep(shared.Interval)
	}

	log.Error(" Timeout waiting for token",
		zap.String("path", path),
		zap.Duration("timeout", timeout),
		zap.Int("total_attempts", attempt))
	return "", fmt.Errorf("token not found at %s after %s", path, timeout)
}

// readTokenFromSink reads the Vault Agent token (run as 'eos' system user)
func readTokenFromSink(rc *eos_io.RuntimeContext, path string) (string, error) {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Reading Vault Agent token from sink", zap.String("path", path))

	if path == "" {
		path = shared.AgentToken
	}

	// Check file existence and permissions before attempting to read
	if stat, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			log.Error(" Token file does not exist",
				zap.String("path", path),
				zap.Error(err))
		} else {
			log.Error(" Cannot stat token file",
				zap.String("path", path),
				zap.Error(err))
		}
		return "", fmt.Errorf("token file not accessible at %s: %w", path, err)
	} else {
		log.Info(" Token file exists",
			zap.String("path", path),
			zap.String("mode", stat.Mode().String()),
			zap.Int64("size", stat.Size()),
			zap.Time("mod_time", stat.ModTime()))
	}

	// Check parent directory permissions
	parentDir := "/run/eos"
	if dirStat, err := os.Stat(parentDir); err != nil {
		log.Error(" Cannot stat parent directory",
			zap.String("dir", parentDir),
			zap.Error(err))
	} else {
		log.Info(" Parent directory status",
			zap.String("dir", parentDir),
			zap.String("mode", dirStat.Mode().String()))
	}

	out, err := exec.Command("cat", path).Output()
	if err != nil {
		log.Error(" Failed to read token via shell",
			zap.String("path", path),
			zap.Error(err))
		return "", fmt.Errorf("failed to read token from Vault Agent sink at %s: %w", path, err)
	}
	token := strings.TrimSpace(string(out))
	log.Info(" Token read successfully via shell",
		zap.String("path", path),
		zap.Int("token_length", len(token)))

	return token, nil
}

// ensureRuntimeDirectory creates /run/eos directory with proper permissions before starting Vault Agent
func ensureRuntimeDirectory(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)
	runDir := "/run/eos"

	log.Info(" Ensuring runtime directory exists", zap.String("path", runDir))

	// Check if directory already exists
	if stat, err := os.Stat(runDir); err == nil {
		log.Info(" Runtime directory already exists",
			zap.String("path", runDir),
			zap.String("mode", stat.Mode().String()))

		// Verify ownership
		// Use vault user instead of deprecated eos user
		uid, gid, userErr := eos_unix.LookupUser(rc.Ctx, "vault")
		if userErr == nil {
			if chownErr := os.Chown(runDir, uid, gid); chownErr != nil {
				log.Warn("Could not update ownership of existing runtime directory",
					zap.String("dir", runDir),
					zap.Error(chownErr))
			} else {
				log.Info(" Runtime directory ownership verified")
			}
		}
		return nil
	}

	// Create directory if it doesn't exist
	log.Info(" Creating runtime directory", zap.String("path", runDir))
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		log.Error(" Failed to create runtime directory",
			zap.String("path", runDir),
			zap.Error(err))
		return fmt.Errorf("create runtime directory %s: %w", runDir, err)
	}

	// Set proper ownership (eos user)
	// Use vault user instead of deprecated eos user
	uid, gid, err := eos_unix.LookupUser(rc.Ctx, "vault")
	if err != nil {
		log.Warn("Could not lookup eos user, using root ownership", zap.Error(err))
		return nil // Continue with root ownership rather than failing
	}

	if err := os.Chown(runDir, uid, gid); err != nil {
		log.Warn("Could not change ownership of runtime directory",
			zap.String("dir", runDir),
			zap.String("user", "vault"),
			zap.Error(err))
		return nil // Continue rather than failing
	}

	log.Info(" Runtime directory created and configured",
		zap.String("path", runDir),
		zap.String("owner", "vault"),
		zap.String("mode", "0755"))
	return nil
}

// logSystemdServiceStatus retrieves and logs systemd service status and recent journal entries for troubleshooting
func logSystemdServiceStatus(rc *eos_io.RuntimeContext, serviceName string) error {
	log := otelzap.Ctx(rc.Ctx)

	// Get service status
	statusCmd := exec.CommandContext(rc.Ctx, "systemctl", "status", serviceName, "--no-pager")
	statusOutput, statusErr := statusCmd.CombinedOutput()
	if statusErr != nil {
		log.Info(" Service status (may be failing)",
			zap.String("service", serviceName),
			zap.String("output", string(statusOutput)))
	} else {
		log.Info(" Service status",
			zap.String("service", serviceName),
			zap.String("output", string(statusOutput)))
	}

	// Get recent journal entries
	journalCmd := exec.CommandContext(rc.Ctx, "journalctl", "-u", serviceName, "--no-pager", "-n", "20")
	journalOutput, journalErr := journalCmd.CombinedOutput()
	if journalErr != nil {
		log.Warn("Failed to get journal logs", zap.String("service", serviceName), zap.Error(journalErr))
	} else {
		log.Info(" Recent journal entries",
			zap.String("service", serviceName),
			zap.String("logs", string(journalOutput)))
	}

	return nil
}
