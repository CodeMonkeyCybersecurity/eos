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
// P0-5: FAIL FAST on deterministic errors (TLS cert issues, config errors)
func WaitForAgentToken(rc *eos_io.RuntimeContext, path string, timeout time.Duration) (string, error) {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Waiting for Vault Agent token",
		zap.String("path", path),
		zap.Duration("timeout", timeout))

	deadline := time.Now().Add(timeout)
	attempt := 0

	for time.Now().Before(deadline) {
		attempt++

		// P0-5: Check systemd logs for deterministic failures BEFORE retrying
		// Check every 5 attempts to avoid excessive log reads
		if attempt%5 == 0 || attempt == 1 {
			if agentErr := checkVaultAgentErrors(rc); agentErr != nil {
				log.Error(" Vault Agent has deterministic error - failing fast",
					zap.Int("attempt", attempt),
					zap.Error(agentErr),
					zap.String("remediation", "Fix the configuration error and retry"))
				return "", fmt.Errorf("vault agent failed with configuration error (attempt %d): %w", attempt, agentErr)
			}
		}

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

	// Final check of agent logs before declaring timeout
	if agentErr := checkVaultAgentErrors(rc); agentErr != nil {
		log.Error(" Vault Agent has deterministic error after timeout",
			zap.Error(agentErr))
		return "", fmt.Errorf("vault agent failed: %w", agentErr)
	}

	log.Error(" Timeout waiting for token",
		zap.String("path", path),
		zap.Duration("timeout", timeout),
		zap.Int("total_attempts", attempt))
	return "", fmt.Errorf("token not found at %s after %s", path, timeout)
}

// readTokenFromSink reads the Vault Agent token (run as 'eos' system user)
// Prefixed with underscore to indicate it's intentionally unused (reserved for future token reading)
//
//nolint:unused
func _readTokenFromSink(rc *eos_io.RuntimeContext, path string) (string, error) {
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

	// SECURITY P0 #1: Use os.ReadFile instead of exec.Command("cat") to prevent command injection
	tokenBytes, err := os.ReadFile(path)
	if err != nil {
		log.Error(" Failed to read token file",
			zap.String("path", path),
			zap.Error(err))
		return "", fmt.Errorf("failed to read token from Vault Agent sink at %s: %w", path, err)
	}
	token := strings.TrimSpace(string(tokenBytes))
	log.Info(" Token read successfully",
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

// checkVaultAgentErrors examines systemd journal logs for deterministic errors (TLS, config, etc)
// Returns an error if a non-retryable failure is detected, nil if agent is still attempting auth
// P0-5: FAIL FAST on deterministic errors instead of retrying for 30 seconds
func checkVaultAgentErrors(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)
	serviceName := shared.VaultAgentService

	// Get recent journal entries (last 50 lines to catch errors)
	journalCmd := exec.CommandContext(rc.Ctx, "journalctl", "-u", serviceName, "--no-pager", "-n", "50")
	journalOutput, err := journalCmd.CombinedOutput()
	if err != nil {
		// If we can't read logs, don't fail - let the retry continue
		log.Debug(" Could not read agent journal logs (non-fatal)",
			zap.String("service", serviceName),
			zap.Error(err))
		return nil
	}

	logText := string(journalOutput)

	// Deterministic error patterns that indicate configuration issues
	deterministicPatterns := []struct {
		pattern     string
		description string
		remediation string
	}{
		{
			pattern:     "x509: certificate signed by unknown authority",
			description: "TLS certificate not trusted",
			remediation: "Vault CA certificate is missing or incorrect at /etc/vault.d/ca.crt",
		},
		{
			pattern:     "tls: failed to verify certificate",
			description: "TLS certificate verification failed",
			remediation: "Check that Vault CA certificate is properly copied to /etc/vault.d/ca.crt",
		},
		{
			pattern:     "no such file or directory",
			description: "Required file missing (likely role_id or secret_id)",
			remediation: "AppRole credentials not properly written to /etc/vault.d/",
		},
		{
			pattern:     "permission denied",
			description: "File permission issue",
			remediation: "Check ownership and permissions on /etc/vault.d/ and /run/eos/",
		},
		{
			pattern:     "invalid configuration",
			description: "Agent configuration file has errors",
			remediation: "Check /etc/vault.d/agent-config.hcl for syntax errors",
		},
		{
			pattern:     "failed to parse",
			description: "Configuration parsing failed",
			remediation: "Check HCL syntax in /etc/vault.d/agent-config.hcl",
		},
		{
			pattern:     "role_id is empty",
			description: "AppRole role_id is missing",
			remediation: "Check that /etc/vault.d/role_id contains valid data",
		},
		{
			pattern:     "secret_id is empty",
			description: "AppRole secret_id is missing",
			remediation: "Check that /etc/vault.d/secret_id contains valid data",
		},
	}

	// CRITICAL: Check for SUCCESS indicators first - if agent succeeded, ignore old error messages
	hasAuthSuccess := strings.Contains(logText, "authentication successful")
	hasTokenWritten := strings.Contains(logText, "token written")

	if hasAuthSuccess && hasTokenWritten {
		log.Debug(" Vault Agent has successfully authenticated and written token - ignoring any old error messages",
			zap.Bool("auth_success", hasAuthSuccess),
			zap.Bool("token_written", hasTokenWritten))
		return nil // Agent is working correctly
	}

	for _, pattern := range deterministicPatterns {
		if strings.Contains(logText, pattern.pattern) {
			log.Error(" Vault Agent deterministic error detected",
				zap.String("error_type", pattern.description),
				zap.String("pattern", pattern.pattern),
				zap.String("remediation", pattern.remediation))

			return fmt.Errorf("%s: %s (fix: %s)",
				pattern.description,
				pattern.pattern,
				pattern.remediation)
		}
	}

	// No deterministic errors found - agent is still trying or having transient issues
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
