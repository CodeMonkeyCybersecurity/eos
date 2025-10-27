// pkg/vault/agent_update.go
// Vault Agent update and recovery operations
//
// This module provides automated Vault Agent health checking and recovery:
// - Assess Agent health (service status, token validity, credentials, permissions)
// - Intervene to fix issues (restart service, fix permissions, renew token)
// - Evaluate results (verify Agent is working, test token permissions)
//
// Code Monkey Cybersecurity - "Cybersecurity. With humans."
package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// AgentUpdateConfig configures Vault Agent update operations
type AgentUpdateConfig struct {
	ForceRestart      bool // Force restart even if service appears healthy
	FixPermissions    bool // Fix credential file permissions
	UpdatePolicies    bool // Update Agent policies (future feature)
	DryRun            bool // Preview changes without applying
	WaitForRenewal    bool // Wait for token renewal after restart
	MaxWaitSeconds    int  // Maximum seconds to wait for token renewal (default: 30)
}

// AgentHealthStatus represents the health assessment of Vault Agent
type AgentHealthStatus struct {
	ServiceRunning       bool
	TokenFileExists      bool
	TokenFilePopulated   bool
	TokenValid           bool
	TokenTTL             int64
	TokenExpired         bool
	TokenExpiresSoon     bool // TTL < 5 minutes
	TokenIsPeriodic      bool   // Token has period set (auto-renewable)
	AppRoleHasPeriod     bool   // AppRole config has token_period set
	ConfigMismatch       bool   // Token config doesn't match AppRole config (needs restart)
	CredentialsExist     bool
	CredentialsReadable  bool
	PermissionsCorrect   bool
	Issues               []string
}

// UpdateAgent performs comprehensive Vault Agent health check and recovery
// Follows Assess → Intervene → Evaluate pattern
func UpdateAgent(rc *eos_io.RuntimeContext, config *AgentUpdateConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting Vault Agent update")

	// Set defaults
	if config.MaxWaitSeconds == 0 {
		config.MaxWaitSeconds = 30
	}

	// ASSESS - Check current Agent health
	logger.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	logger.Info("ASSESS: Checking Vault Agent health")
	logger.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	status, err := assessAgentHealth(rc)
	if err != nil {
		return fmt.Errorf("health assessment failed: %w", err)
	}

	// Display current status
	displayAgentStatus(rc, status)

	// If healthy and not forcing restart, we're done
	if isHealthy(status) && !config.ForceRestart {
		logger.Info("✓ Vault Agent is healthy - no action needed")
		return nil
	}

	// INTERVENE - Fix identified issues
	logger.Info("")
	logger.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	logger.Info("INTERVENE: Fixing identified issues")
	logger.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	if config.DryRun {
		logger.Info("DRY RUN: Would perform the following actions:")
		displayPlannedActions(rc, status, config)
		return nil
	}

	if err := performInterventions(rc, status, config); err != nil {
		return fmt.Errorf("interventions failed: %w", err)
	}

	// EVALUATE - Verify Agent is now healthy
	logger.Info("")
	logger.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	logger.Info("EVALUATE: Verifying Vault Agent health")
	logger.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	newStatus, err := assessAgentHealth(rc)
	if err != nil {
		return fmt.Errorf("post-intervention assessment failed: %w", err)
	}

	displayAgentStatus(rc, newStatus)

	if !isHealthy(newStatus) {
		logger.Error("⚠ Vault Agent still has issues after intervention")
		logger.Info("")
		logger.Info("Recommended next steps:")
		logger.Info("  1. Check Vault Agent logs: sudo journalctl -u vault-agent-eos -n 100")
		logger.Info("  2. Run detailed diagnostics: sudo eos debug vault --agent")
		logger.Info("  3. Check Vault server is unsealed: vault status")
		logger.Info("  4. Verify AppRole credentials exist: ls -la /var/lib/eos/secret/")
		return fmt.Errorf("agent still unhealthy after intervention - manual investigation required")
	}

	logger.Info("✓ Vault Agent is now healthy")
	return nil
}

// assessAgentHealth performs comprehensive health assessment
func assessAgentHealth(rc *eos_io.RuntimeContext) (*AgentHealthStatus, error) {
	logger := otelzap.Ctx(rc.Ctx)
	status := &AgentHealthStatus{
		Issues: []string{},
	}

	// Check 1: Service running
	logger.Debug("Checking Vault Agent service status")
	cmd := exec.CommandContext(rc.Ctx, "systemctl", "is-active", "--quiet", shared.VaultAgentService)
	if err := cmd.Run(); err != nil {
		status.ServiceRunning = false
		status.Issues = append(status.Issues, "Service not running")
		logger.Debug("✗ Service not running")
	} else {
		status.ServiceRunning = true
		logger.Debug("✓ Service running")
	}

	// Check 2: Token file exists and populated
	logger.Debug("Checking token file", zap.String("path", shared.AgentToken))
	tokenStat, err := os.Stat(shared.AgentToken)
	if os.IsNotExist(err) {
		status.TokenFileExists = false
		status.Issues = append(status.Issues, "Token file missing")
		logger.Debug("✗ Token file does not exist")
	} else if err != nil {
		status.TokenFileExists = false
		status.Issues = append(status.Issues, fmt.Sprintf("Cannot stat token file: %v", err))
		logger.Debug("✗ Cannot stat token file", zap.Error(err))
	} else {
		status.TokenFileExists = true
		logger.Debug("✓ Token file exists")

		if tokenStat.Size() == 0 {
			status.TokenFilePopulated = false
			status.Issues = append(status.Issues, "Token file empty (Agent not authenticated)")
			logger.Debug("✗ Token file empty")
		} else {
			status.TokenFilePopulated = true
			logger.Debug("✓ Token file populated", zap.Int64("size", tokenStat.Size()))
		}
	}

	// Check 3: Token validity (if file exists and populated)
	if status.TokenFilePopulated {
		logger.Debug("Validating token with Vault")
		tokenData, err := os.ReadFile(shared.AgentToken)
		if err != nil {
			status.Issues = append(status.Issues, fmt.Sprintf("Cannot read token: %v", err))
			logger.Debug("✗ Cannot read token file", zap.Error(err))
		} else {
			token := strings.TrimSpace(string(tokenData))

			// Create Vault client and validate token
			client, err := GetVaultClient(rc)
			if err != nil {
				status.Issues = append(status.Issues, fmt.Sprintf("Cannot create Vault client: %v", err))
				logger.Debug("✗ Cannot create Vault client", zap.Error(err))
			} else {
				client.SetToken(token)
				tokenInfo, err := client.Auth().Token().LookupSelf()
				if err != nil {
					status.TokenValid = false
					status.TokenExpired = true
					status.Issues = append(status.Issues, "Token invalid or expired")
					logger.Debug("✗ Token validation failed", zap.Error(err))
				} else {
					status.TokenValid = true
					logger.Debug("✓ Token valid")

					// Extract TTL
					if ttlRaw, ok := tokenInfo.Data["ttl"]; ok {
						var ttlSeconds int64
						switch v := ttlRaw.(type) {
						case json.Number:
							ttlSeconds, _ = v.Int64()
						case float64:
							ttlSeconds = int64(v)
						case int:
							ttlSeconds = int64(v)
						case int64:
							ttlSeconds = v
						}

						status.TokenTTL = ttlSeconds
						logger.Debug("Token TTL", zap.Int64("seconds", ttlSeconds))

						// Check if expires soon (< 5 minutes)
						if ttlSeconds > 0 && ttlSeconds < 300 {
							status.TokenExpiresSoon = true
							status.Issues = append(status.Issues, fmt.Sprintf("Token expires soon (%d seconds)", ttlSeconds))
							logger.Debug("⚠ Token expires soon", zap.Int64("ttl_seconds", ttlSeconds))
						}

						if ttlSeconds == 0 {
							status.TokenExpired = true
							status.Issues = append(status.Issues, "Token expired (TTL=0)")
							logger.Debug("✗ Token expired")
						}
					}
				}
			}
		}
	}

	// Check 4: AppRole credentials exist and readable
	logger.Debug("Checking AppRole credentials")
	roleIDPath := shared.AppRolePaths.RoleID
	secretIDPath := shared.AppRolePaths.SecretID

	roleIDExists := false
	secretIDExists := false

	if _, err := os.Stat(roleIDPath); err == nil {
		roleIDExists = true
	}
	if _, err := os.Stat(secretIDPath); err == nil {
		secretIDExists = true
	}

	status.CredentialsExist = roleIDExists && secretIDExists

	if !status.CredentialsExist {
		missing := []string{}
		if !roleIDExists {
			missing = append(missing, "role_id")
		}
		if !secretIDExists {
			missing = append(missing, "secret_id")
		}
		status.Issues = append(status.Issues, fmt.Sprintf("Missing AppRole credentials: %s", strings.Join(missing, ", ")))
		logger.Debug("✗ AppRole credentials incomplete", zap.Strings("missing", missing))
	} else {
		logger.Debug("✓ AppRole credentials exist")

		// Check if vault user can read them
		testCmd := exec.CommandContext(rc.Ctx, "sudo", "-u", "vault", "test", "-r", roleIDPath)
		canReadRoleID := testCmd.Run() == nil

		testCmd = exec.CommandContext(rc.Ctx, "sudo", "-u", "vault", "test", "-r", secretIDPath)
		canReadSecretID := testCmd.Run() == nil

		status.CredentialsReadable = canReadRoleID && canReadSecretID

		if !status.CredentialsReadable {
			status.Issues = append(status.Issues, "Vault user cannot read AppRole credentials (permissions issue)")
			logger.Debug("✗ Credentials not readable by vault user")
		} else {
			logger.Debug("✓ Credentials readable by vault user")
		}

		status.PermissionsCorrect = status.CredentialsReadable
	}

	// Check 5: AppRole configuration vs current token (detect config drift)
	// CRITICAL: If AppRole config has changed (e.g., token_period added), Agent needs restart
	// to get a NEW token with the NEW configuration
	logger.Debug("Checking for AppRole configuration drift")
	if status.TokenValid {
		// Get current AppRole configuration from Vault
		client, err := GetVaultClient(rc)
		if err == nil {
			appRoleResp, err := client.Logical().Read("auth/approle/role/eos-approle")
			if err != nil {
				logger.Debug("Cannot read AppRole config", zap.Error(err))
			} else if appRoleResp != nil && appRoleResp.Data != nil {
				// Check if AppRole has token_period configured
				if tokenPeriod, ok := appRoleResp.Data["token_period"].(json.Number); ok {
					periodInt, _ := tokenPeriod.Int64()
					status.AppRoleHasPeriod = periodInt > 0

					// Now check if current token has period
					// Get token info again
					tokenData, _ := os.ReadFile(shared.AgentToken)
					token := strings.TrimSpace(string(tokenData))
					client.SetToken(token)

					tokenInfo, err := client.Auth().Token().LookupSelf()
					if err == nil && tokenInfo.Data != nil {
						// Check token's period
						if period, ok := tokenInfo.Data["period"].(json.Number); ok {
							periodSec, _ := period.Int64()
							status.TokenIsPeriodic = periodSec > 0
						}

						// DETECT MISMATCH: AppRole has period but token doesn't (or vice versa)
						if status.AppRoleHasPeriod != status.TokenIsPeriodic {
							status.ConfigMismatch = true
							if status.AppRoleHasPeriod && !status.TokenIsPeriodic {
								status.Issues = append(status.Issues,
									"AppRole config changed: token_period added but current token is not periodic (restart needed)")
								logger.Debug("✗ Token config mismatch: AppRole has period but token doesn't")
							} else if !status.AppRoleHasPeriod && status.TokenIsPeriodic {
								status.Issues = append(status.Issues,
									"AppRole config changed: token_period removed but current token is periodic (restart recommended)")
								logger.Debug("⚠ Token config mismatch: Token is periodic but AppRole period removed")
							}
						} else {
							logger.Debug("✓ Token config matches AppRole config",
								zap.Bool("has_period", status.AppRoleHasPeriod))
						}
					}
				}
			}
		}
	}

	logger.Debug("Health assessment complete",
		zap.Int("issue_count", len(status.Issues)),
		zap.Bool("config_mismatch", status.ConfigMismatch))

	return status, nil
}

// displayAgentStatus shows current Agent health status
func displayAgentStatus(rc *eos_io.RuntimeContext, status *AgentHealthStatus) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Vault Agent Health Status:")
	logger.Info(fmt.Sprintf("  Service Running:     %s", boolToStatus(status.ServiceRunning)))
	logger.Info(fmt.Sprintf("  Token File Exists:   %s", boolToStatus(status.TokenFileExists)))
	logger.Info(fmt.Sprintf("  Token Populated:     %s", boolToStatus(status.TokenFilePopulated)))
	logger.Info(fmt.Sprintf("  Token Valid:         %s", boolToStatus(status.TokenValid)))
	if status.TokenTTL > 0 {
		logger.Info(fmt.Sprintf("  Token TTL:           %d seconds (%s)", status.TokenTTL, formatSeconds(status.TokenTTL)))
	}
	if status.TokenValid {
		logger.Info(fmt.Sprintf("  Token Is Periodic:   %s", boolToStatus(status.TokenIsPeriodic)))
		logger.Info(fmt.Sprintf("  AppRole Has Period:  %s", boolToStatus(status.AppRoleHasPeriod)))
		if status.ConfigMismatch {
			logger.Info("  Config Mismatch:     ⚠️  YES (restart needed)")
		}
	}
	logger.Info(fmt.Sprintf("  Credentials Exist:   %s", boolToStatus(status.CredentialsExist)))
	logger.Info(fmt.Sprintf("  Credentials Readable:%s", boolToStatus(status.CredentialsReadable)))

	if len(status.Issues) > 0 {
		logger.Info("")
		logger.Info("Issues found:")
		for i, issue := range status.Issues {
			logger.Info(fmt.Sprintf("  %d. %s", i+1, issue))
		}
	}
}

// isHealthy returns true if Agent is fully healthy
func isHealthy(status *AgentHealthStatus) bool {
	return status.ServiceRunning &&
		status.TokenFileExists &&
		status.TokenFilePopulated &&
		status.TokenValid &&
		!status.TokenExpired &&
		!status.TokenExpiresSoon &&
		status.CredentialsExist &&
		status.CredentialsReadable
}

// displayPlannedActions shows what would be done (dry-run mode)
func displayPlannedActions(rc *eos_io.RuntimeContext, status *AgentHealthStatus, config *AgentUpdateConfig) {
	logger := otelzap.Ctx(rc.Ctx)

	actions := []string{}

	if !status.ServiceRunning || config.ForceRestart {
		actions = append(actions, "Restart Vault Agent service")
	}

	if config.FixPermissions && !status.PermissionsCorrect {
		actions = append(actions, "Fix AppRole credential permissions")
	}

	if status.TokenExpired || status.TokenExpiresSoon || !status.TokenValid {
		actions = append(actions, "Wait for token renewal after service restart")
	}

	if len(actions) == 0 {
		logger.Info("  No actions needed")
		return
	}

	for i, action := range actions {
		logger.Info(fmt.Sprintf("  %d. %s", i+1, action))
	}
}

// performInterventions executes recovery actions
func performInterventions(rc *eos_io.RuntimeContext, status *AgentHealthStatus, config *AgentUpdateConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Intervention 1: Fix permissions if needed
	if config.FixPermissions && !status.PermissionsCorrect {
		logger.Info("Fixing AppRole credential permissions...")
		if err := fixCredentialPermissions(rc); err != nil {
			logger.Error("Failed to fix permissions", zap.Error(err))
			// Non-fatal - continue with restart
		} else {
			logger.Info("✓ Permissions fixed")
		}
	}

	// Intervention 2: Pre-flight check - if token expires soon but service is running, wait for auto-renewal
	if status.ServiceRunning && status.TokenExpiresSoon && !status.TokenExpired && !config.ForceRestart {
		logger.Info("⚠ Token expires soon, waiting for Vault Agent to auto-renew...")
		logger.Info(fmt.Sprintf("Current TTL: %d seconds", status.TokenTTL))
		logger.Info("Vault Agent should renew automatically in the next 30 seconds...")

		// Wait up to 60 seconds for auto-renewal
		if err := waitForTokenRenewal(rc, 60); err != nil {
			logger.Warn("Auto-renewal did not complete, will restart Agent", zap.Error(err))
			// Fall through to restart logic below
		} else {
			logger.Info("✓ Token auto-renewed successfully - no restart needed")
			return nil // Success! No need to restart
		}
	}

	// Intervention 3: Restart service if not running or forced
	if !status.ServiceRunning || config.ForceRestart || status.TokenExpired || status.TokenExpiresSoon {
		logger.Info("Restarting Vault Agent service...")
		cmd := exec.CommandContext(rc.Ctx, "systemctl", "restart", shared.VaultAgentService)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to restart service: %w", err)
		}
		logger.Info("✓ Service restarted")

		// Wait for service to start
		logger.Info("Waiting for service to start...")
		time.Sleep(2 * time.Second)

		// Intervention 4: Wait for token renewal if configured
		if config.WaitForRenewal {
			logger.Info("Waiting for token renewal...")
			if err := waitForTokenRenewal(rc, config.MaxWaitSeconds); err != nil {
				logger.Warn("Token renewal wait timed out", zap.Error(err))
				logger.Info("Service restarted but token renewal may still be in progress")
				logger.Info("Check logs: sudo journalctl -u vault-agent-eos -f")
			} else {
				logger.Info("✓ Token renewed successfully")
			}
		}
	}

	return nil
}

// fixCredentialPermissions ensures vault user can read AppRole credentials
func fixCredentialPermissions(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	roleIDPath := shared.AppRolePaths.RoleID
	secretIDPath := shared.AppRolePaths.SecretID

	// Ensure vault user can traverse parent directories
	// /var/lib/eos must have x permission for vault user
	logger.Debug("Fixing directory permissions")
	cmd := exec.CommandContext(rc.Ctx, "chmod", "755", "/var/lib/eos")
	if err := cmd.Run(); err != nil {
		logger.Warn("Failed to fix /var/lib/eos permissions", zap.Error(err))
	}

	cmd = exec.CommandContext(rc.Ctx, "chmod", "755", "/var/lib/eos/secret")
	if err := cmd.Run(); err != nil {
		logger.Warn("Failed to fix /var/lib/eos/secret permissions", zap.Error(err))
	}

	// Fix credential file permissions (owner=root, group=vault, mode=640)
	logger.Debug("Fixing credential file permissions")
	for _, path := range []string{roleIDPath, secretIDPath} {
		// Set group to vault
		cmd = exec.CommandContext(rc.Ctx, "chgrp", "vault", path)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to chgrp %s: %w", path, err)
		}

		// Set permissions to 640 (owner read/write, group read, others none)
		cmd = exec.CommandContext(rc.Ctx, "chmod", "640", path)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to chmod %s: %w", path, err)
		}
	}

	logger.Debug("✓ Permissions fixed")
	return nil
}

// waitForTokenRenewal waits for Vault Agent to renew the token
// Returns nil when token is valid AND has good TTL
func waitForTokenRenewal(rc *eos_io.RuntimeContext, maxWaitSeconds int) error {
	logger := otelzap.Ctx(rc.Ctx)
	ctx, cancel := context.WithTimeout(rc.Ctx, time.Duration(maxWaitSeconds)*time.Second)
	defer cancel()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	// Record initial token state for comparison
	initialTTL := int64(0)
	initialToken := ""

	// Try to read initial state (may fail if token doesn't exist yet)
	if tokenData, err := os.ReadFile(shared.AgentToken); err == nil {
		initialToken = strings.TrimSpace(string(tokenData))
		if client, err := GetVaultClient(rc); err == nil && initialToken != "" {
			client.SetToken(initialToken)
			if tokenInfo, err := client.Auth().Token().LookupSelf(); err == nil {
				if ttlRaw, ok := tokenInfo.Data["ttl"]; ok {
					initialTTL = extractTTLInt64(ttlRaw)
				}
			}
		}
	}

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for token renewal after %d seconds", maxWaitSeconds)
		case <-ticker.C:
			// Check if token file has been updated
			stat, err := os.Stat(shared.AgentToken)
			if err != nil {
				logger.Debug("Token file not found yet, waiting...")
				continue // File doesn't exist yet
			}

			if stat.Size() == 0 {
				logger.Debug("Token file still empty, waiting...")
				continue
			}

			// Try to validate token
			tokenData, err := os.ReadFile(shared.AgentToken)
			if err != nil {
				logger.Debug("Cannot read token file, waiting...", zap.Error(err))
				continue
			}

			token := strings.TrimSpace(string(tokenData))
			if token == "" {
				logger.Debug("Token file empty, waiting...")
				continue
			}

			client, err := GetVaultClient(rc)
			if err != nil {
				logger.Debug("Cannot create Vault client, waiting...", zap.Error(err))
				continue
			}

			client.SetToken(token)
			tokenInfo, err := client.Auth().Token().LookupSelf()
			if err != nil {
				logger.Debug("Token not yet valid, waiting...", zap.Error(err))
				continue
			}

			// Extract current TTL
			currentTTL := int64(0)
			if ttlRaw, ok := tokenInfo.Data["ttl"]; ok {
				currentTTL = extractTTLInt64(ttlRaw)
			}

			// Token is valid - check if TTL is sufficient
			const minAcceptableTTL = 300 // 5 minutes minimum

			if currentTTL < minAcceptableTTL {
				logger.Debug("Token valid but TTL too low, waiting for renewal...",
					zap.Int64("current_ttl", currentTTL),
					zap.Int64("min_required", minAcceptableTTL))
				continue
			}

			// Success! Token is valid and has good TTL
			if initialTTL > 0 && currentTTL > initialTTL {
				logger.Debug("✓ Token renewed (TTL increased)",
					zap.Int64("old_ttl", initialTTL),
					zap.Int64("new_ttl", currentTTL))
			} else {
				logger.Debug("✓ Token valid with sufficient TTL",
					zap.Int64("ttl", currentTTL))
			}

			return nil
		}
	}
}

// extractTTLInt64 extracts TTL from various formats Vault returns
func extractTTLInt64(ttlRaw interface{}) int64 {
	switch v := ttlRaw.(type) {
	case json.Number:
		ttl, _ := v.Int64()
		return ttl
	case float64:
		return int64(v)
	case int:
		return int64(v)
	case int64:
		return v
	default:
		return 0
	}
}

// boolToStatus converts bool to ✓/✗ string
func boolToStatus(b bool) string {
	if b {
		return "✓"
	}
	return "✗"
}

// formatSeconds formats seconds into human-readable duration
func formatSeconds(seconds int64) string {
	if seconds < 60 {
		return fmt.Sprintf("%ds", seconds)
	} else if seconds < 3600 {
		minutes := seconds / 60
		return fmt.Sprintf("%dm %ds", minutes, seconds%60)
	} else {
		hours := seconds / 3600
		minutes := (seconds % 3600) / 60
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
}
