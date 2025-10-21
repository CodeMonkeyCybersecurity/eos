// pkg/debug/vault/diagnostics.go
// Vault-specific diagnostic checks

package vault

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/debug"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// NOTE: These constants duplicate values from pkg/vault/constants.go
// This is intentional to avoid circular import (pkg/debug/vault cannot import pkg/vault)
// If you change these values, also update pkg/vault/constants.go
//
// For runtime paths that don't cause circular imports, use pkg/shared constants:
// - shared.AgentToken (vault.VaultAgentTokenPath)
// - shared.AppRolePaths.RoleID (vault.VaultRoleIDFilePath)
// - shared.AppRolePaths.SecretID (vault.VaultSecretIDFilePath)
// - shared.EosRunDir (vault.EosRunDir)
// - shared.VaultAgentConfigPath (vault.VaultAgentConfigPath)
const (
	DefaultBinaryPath      = "/usr/local/bin/vault"          // Matches vault.VaultBinaryPath
	DefaultConfigPath      = "/etc/vault.d/vault.hcl"        // Matches vault.VaultConfigPath
	DefaultAgentConfigPath = "/etc/vault.d/agent-config.hcl" // Matches vault.VaultAgentConfigPath & shared.VaultAgentConfigPath
	DefaultDataPath        = "/opt/vault/data"               // Matches vault.VaultDataDir
	DefaultLogPath         = "/var/log/vault"                // Matches vault.VaultLogsDir
	DeletionTransactionDir = "/var/log/eos"
)

// AllDiagnostics returns all vault diagnostic checks
func AllDiagnostics() []*debug.Diagnostic {
	return []*debug.Diagnostic{
		BinaryDiagnostic(),
		ConfigFileDiagnostic(),
		ConfigValidationDiagnostic(),
		DataDirectoryDiagnostic(),
		LogDirectoryDiagnostic(),
		UserDiagnostic(),
		PermissionsDiagnostic(), // NEW: Comprehensive permissions check
		ServiceDiagnostic(),
		ServiceConfigDiagnostic(), // NEW: Show User=/Group= from systemd
		ServiceLogsDiagnostic(),
		ProcessDiagnostic(),
		PortDiagnostic(),
		HealthCheckDiagnostic(),
		EnvironmentDiagnostic(),
		CapabilitiesDiagnostic(),
		DeletionTransactionLogsDiagnostic(),
		IdempotencyStatusDiagnostic(), // NEW: Shows current installation state for idempotent operations
		OrphanedStateDiagnostic(),     // NEW: Detects orphaned Vault state (initialized but credentials lost)
		// Vault Agent diagnostics
		VaultAgentServiceDiagnostic(),
		VaultAgentConfigDiagnostic(),
		VaultAgentCredentialsDiagnostic(),
		VaultAgentTokenDiagnostic(),
		VaultAgentTokenPermissionsDiagnostic(), // Comprehensive token permissions analysis
		VaultAgentLogsDiagnostic(),
	}
}

// BinaryDiagnostic checks the vault binary
func BinaryDiagnostic() *debug.Diagnostic {
	return debug.BinaryCheck("Vault", DefaultBinaryPath)
}

// ConfigFileDiagnostic checks the vault configuration file
func ConfigFileDiagnostic() *debug.Diagnostic {
	return debug.FileCheck("Configuration File", DefaultConfigPath, true)
}

// ConfigValidationDiagnostic validates the configuration file
func ConfigValidationDiagnostic() *debug.Diagnostic {
	return &debug.Diagnostic{
		Name:        "Configuration Validation",
		Category:    "Configuration",
		Description: "Validate vault.hcl configuration",
		Condition: func(ctx context.Context) bool {
			logger := otelzap.Ctx(ctx)
			// Only run if binary and config exist
			_, binErr := os.Stat(DefaultBinaryPath)
			_, cfgErr := os.Stat(DefaultConfigPath)
			canRun := binErr == nil && cfgErr == nil
			logger.Debug("Checking config validation prerequisites",
				zap.Bool("binary_exists", binErr == nil),
				zap.Bool("config_exists", cfgErr == nil),
				zap.Bool("will_run", canRun))
			return canRun
		},
		Collect: func(ctx context.Context) (*debug.Result, error) {
			logger := otelzap.Ctx(ctx)
			logger.Info("Starting Vault configuration validation",
				zap.String("config_path", DefaultConfigPath))

			result := &debug.Result{
				Metadata: make(map[string]interface{}),
			}

			cmd := exec.CommandContext(ctx, DefaultBinaryPath, "validate", DefaultConfigPath)
			output, err := cmd.CombinedOutput()

			result.Output = string(output)
			result.Metadata["config_path"] = DefaultConfigPath

			if err != nil {
				logger.Error("Configuration validation failed",
					zap.String("config_path", DefaultConfigPath),
					zap.String("output", string(output)),
					zap.Error(err))
				result.Status = debug.StatusError
				result.Message = "Configuration validation failed"
				result.Remediation = fmt.Sprintf("Fix configuration errors in %s", DefaultConfigPath)
			} else {
				logger.Info("Configuration validation successful",
					zap.String("config_path", DefaultConfigPath))
				result.Status = debug.StatusOK
				result.Message = "Configuration is valid"
			}

			return result, nil
		},
	}
}

// DataDirectoryDiagnostic checks the vault data directory
func DataDirectoryDiagnostic() *debug.Diagnostic {
	return debug.DirectoryCheck("Data Directory", DefaultDataPath, "vault")
}

// LogDirectoryDiagnostic checks the vault log directory
func LogDirectoryDiagnostic() *debug.Diagnostic {
	return debug.DirectoryCheck("Log Directory", DefaultLogPath, "vault")
}

// UserDiagnostic checks the vault user exists
func UserDiagnostic() *debug.Diagnostic {
	return &debug.Diagnostic{
		Name:        "Vault User",
		Category:    "System",
		Description: "Check vault user and group exist",
		Collect: func(ctx context.Context) (*debug.Result, error) {
			result := &debug.Result{
				Metadata: make(map[string]interface{}),
			}

			// Check user exists
			cmd := exec.CommandContext(ctx, "id", "vault")
			output, err := cmd.CombinedOutput()
			result.Output = string(output)

			if err != nil {
				result.Status = debug.StatusError
				result.Message = "Vault user does not exist"
				result.Remediation = "Create vault user: useradd -r -s /bin/false vault"
			} else {
				result.Status = debug.StatusOK
				result.Message = "Vault user exists"

				// Extract uid/gid
				outputStr := string(output)
				result.Metadata["id_output"] = outputStr
			}

			return result, nil
		},
	}
}

// PermissionsDiagnostic performs comprehensive permission checks
// This combines checks from the bash diagnostic script
func PermissionsDiagnostic() *debug.Diagnostic {
	return &debug.Diagnostic{
		Name:        "Permissions & Ownership",
		Category:    "System",
		Description: "Check vault user, data directory ownership, and permissions",
		Collect: func(ctx context.Context) (*debug.Result, error) {
			logger := otelzap.Ctx(ctx)
			logger.Info("Starting comprehensive Vault permissions diagnostic")

			result := &debug.Result{
				Metadata: make(map[string]interface{}),
			}

			var output strings.Builder
			output.WriteString("=== Vault Permission Diagnostics ===\n\n")

			// 1. Check vault user exists with detailed ID output
			logger.Debug("Checking vault user existence")
			output.WriteString("=== Vault User ===\n")
			idCmd := exec.CommandContext(ctx, "id", "vault")
			idOutput, idErr := idCmd.CombinedOutput()
			if idErr != nil {
				logger.Error("Vault user does not exist",
					zap.Error(idErr),
					zap.String("output", string(idOutput)))
				output.WriteString("ERROR: vault user doesn't exist!\n")
				output.WriteString(fmt.Sprintf("Command output: %s\n", string(idOutput)))
				result.Status = debug.StatusError
				result.Message = "Vault user does not exist"
				result.Remediation = "Create vault user: sudo useradd -r -s /bin/false vault"
			} else {
				logger.Info("Vault user exists",
					zap.String("id_output", string(idOutput)))
				output.WriteString(string(idOutput))
				output.WriteString("\n")
				result.Metadata["vault_user_exists"] = true
				result.Metadata["vault_user_id"] = string(idOutput)
			}

			// 2. Check /opt/vault directory ownership
			output.WriteString("=== /opt/vault Directory ===\n")
			vaultOptCmd := exec.CommandContext(ctx, "ls", "-la", "/opt/vault/")
			vaultOptOutput, vaultOptErr := vaultOptCmd.CombinedOutput()
			if vaultOptErr != nil {
				output.WriteString("ERROR: /opt/vault doesn't exist!\n")
				output.WriteString(fmt.Sprintf("Command output: %s\n", string(vaultOptOutput)))
				result.Metadata["vault_opt_exists"] = false
			} else {
				output.WriteString(string(vaultOptOutput))
				output.WriteString("\n")
				result.Metadata["vault_opt_exists"] = true
			}

			// 3. Check /opt/vault/data directory ownership
			output.WriteString("=== /opt/vault/data Directory ===\n")
			dataCmd := exec.CommandContext(ctx, "ls", "-la", "/opt/vault/data/")
			dataOutput, dataErr := dataCmd.CombinedOutput()
			if dataErr != nil {
				output.WriteString("ERROR: /opt/vault/data doesn't exist!\n")
				output.WriteString(fmt.Sprintf("Command output: %s\n", string(dataOutput)))
				result.Metadata["vault_data_exists"] = false
			} else {
				output.WriteString(string(dataOutput))
				output.WriteString("\n")
				result.Metadata["vault_data_exists"] = true
			}

			// 4. Check config directory ownership
			output.WriteString("=== /etc/vault.d Directory ===\n")
			configCmd := exec.CommandContext(ctx, "ls", "-la", "/etc/vault.d/")
			configOutput, configErr := configCmd.CombinedOutput()
			if configErr != nil {
				output.WriteString("ERROR: /etc/vault.d doesn't exist!\n")
				output.WriteString(fmt.Sprintf("Command output: %s\n", string(configOutput)))
				result.Metadata["vault_config_exists"] = false
			} else {
				output.WriteString(string(configOutput))
				output.WriteString("\n")
				result.Metadata["vault_config_exists"] = true
			}

			// 5. Check TLS directory permissions if it exists
			output.WriteString("=== /etc/vault.d/tls Directory (if exists) ===\n")
			tlsCmd := exec.CommandContext(ctx, "ls", "-la", "/etc/vault.d/tls/")
			tlsOutput, tlsErr := tlsCmd.CombinedOutput()
			if tlsErr != nil {
				output.WriteString("TLS directory not present (may be using tls_disable=true)\n\n")
				result.Metadata["vault_tls_exists"] = false
			} else {
				output.WriteString(string(tlsOutput))
				output.WriteString("\n")
				result.Metadata["vault_tls_exists"] = true

				// Check for proper key file permissions (should be 0600)
				if strings.Contains(string(tlsOutput), "vault.key") || strings.Contains(string(tlsOutput), "tls.key") {
					if strings.Contains(string(tlsOutput), "rw-------") {
						output.WriteString("✓ TLS key file has correct permissions (0600)\n\n")
					} else {
						output.WriteString("⚠ WARNING: TLS key file may have insecure permissions!\n")
						output.WriteString("  Expected: rw------- (0600)\n\n")
						if result.Status == "" {
							result.Status = debug.StatusWarning
							result.Message = "TLS key file has insecure permissions"
							result.Remediation = "Fix permissions: sudo chmod 600 /etc/vault.d/tls/*.key"
						}
					}
				}
			}

			// 5a. Check /opt/vault/logs directory (for audit logs)
			output.WriteString("=== /opt/vault/logs Directory (for audit logs) ===\n")
			logsCmd := exec.CommandContext(ctx, "ls", "-laZ", "/opt/vault/logs/")
			logsOutput, logsErr := logsCmd.CombinedOutput()
			var logsErrNoZ error
			if logsErr != nil {
				// Try without -Z flag (SELinux not available)
				logsCmdNoZ := exec.CommandContext(ctx, "ls", "-la", "/opt/vault/logs/")
				var logsOutputNoZ []byte
				logsOutputNoZ, logsErrNoZ = logsCmdNoZ.CombinedOutput()
				if logsErrNoZ != nil {
					output.WriteString("ERROR: /opt/vault/logs doesn't exist!\n")
					output.WriteString(fmt.Sprintf("Command output: %s\n", string(logsOutputNoZ)))
					output.WriteString("This directory is required for Vault audit logging.\n\n")
					result.Metadata["vault_logs_exists"] = false
					if result.Status == "" {
						result.Status = debug.StatusError
						result.Message = "Vault logs directory missing"
						result.Remediation = "Create logs directory:\n" +
							"  sudo mkdir -p /opt/vault/logs\n" +
							"  sudo chown vault:vault /opt/vault/logs\n" +
							"  sudo chmod 750 /opt/vault/logs"
					}
				} else {
					output.WriteString(string(logsOutputNoZ))
					output.WriteString("\n")
					result.Metadata["vault_logs_exists"] = true
				}
			} else {
				output.WriteString(string(logsOutput))
				output.WriteString("\n")
				result.Metadata["vault_logs_exists"] = true
				result.Metadata["selinux_labels_shown"] = true
			}

			// 5b. Check SELinux status
			output.WriteString("=== SELinux Status ===\n")
			selinuxCmd := exec.CommandContext(ctx, "getenforce")
			selinuxOutput, selinuxErr := selinuxCmd.CombinedOutput()
			if selinuxErr != nil {
				output.WriteString("SELinux not available or not installed\n\n")
				result.Metadata["selinux_available"] = false
			} else {
				selinuxStatus := strings.TrimSpace(string(selinuxOutput))
				output.WriteString(fmt.Sprintf("SELinux status: %s\n", selinuxStatus))
				result.Metadata["selinux_available"] = true
				result.Metadata["selinux_status"] = selinuxStatus

				if selinuxStatus == "Enforcing" {
					output.WriteString("⚠ SELinux is enforcing - may block Vault file operations\n")
					output.WriteString("If Vault has permission errors, check SELinux audit log:\n")
					output.WriteString("  sudo ausearch -m avc -ts recent | grep vault\n\n")
					if result.Status == "" {
						result.Status = debug.StatusWarning
						result.Message = "SELinux is enforcing - may affect Vault"
						result.Remediation = "If permission errors occur, check SELinux contexts or set to permissive:\n" +
							"  sudo setenforce 0  # Temporary\n" +
							"  Or configure SELinux policy for Vault"
					}
				} else {
					output.WriteString("SELinux is not blocking Vault operations\n\n")
				}
			}

			// 5c. Test vault user can write to logs directory
			output.WriteString("=== Vault User Write Test (logs directory) ===\n")
			if idErr == nil && logsErrNoZ == nil {
				testWriteLogsCmd := exec.CommandContext(ctx, "sudo", "-u", "vault", "touch", "/opt/vault/logs/test_write.log")
				writeLogsErr := testWriteLogsCmd.Run()

				if writeLogsErr == nil {
					output.WriteString("✓ vault user CAN write to /opt/vault/logs\n\n")
					// Clean up test file
					_ = exec.CommandContext(ctx, "sudo", "rm", "-f", "/opt/vault/logs/test_write.log").Run()
					result.Metadata["vault_user_can_write_logs"] = true
				} else {
					output.WriteString("✗ vault user CANNOT write to /opt/vault/logs\n")
					output.WriteString(fmt.Sprintf("Error: %v\n", writeLogsErr))
					output.WriteString("This will cause audit log failures!\n\n")
					result.Metadata["vault_user_can_write_logs"] = false
					if result.Status == "" || result.Status == debug.StatusWarning {
						result.Status = debug.StatusError
						result.Message = "vault user cannot write to logs directory"
						result.Remediation = "Fix logs directory permissions:\n" +
							"  sudo chown -R vault:vault /opt/vault/logs\n" +
							"  sudo chmod 750 /opt/vault/logs\n" +
							"  sudo systemctl restart vault"
					}
				}
			} else {
				output.WriteString("Skipping write test (vault user or logs directory doesn't exist)\n\n")
			}

			// 6. CRITICAL: Test vault user access to data directory
			// This is the smoking gun for the "permission denied" bug
			logger.Debug("Testing vault user access to data directory")
			output.WriteString("=== Vault User Access Test ===\n")
			if idErr == nil && dataErr == nil {
				// Test if vault user can read the data directory
				testReadCmd := exec.CommandContext(ctx, "sudo", "-u", "vault", "test", "-r", "/opt/vault/data")
				canRead := testReadCmd.Run() == nil

				testWriteCmd := exec.CommandContext(ctx, "sudo", "-u", "vault", "test", "-w", "/opt/vault/data")
				canWrite := testWriteCmd.Run() == nil

				testTraverseCmd := exec.CommandContext(ctx, "sudo", "-u", "vault", "test", "-x", "/opt/vault/data")
				canTraverse := testTraverseCmd.Run() == nil

				logger.Info("Data directory access test results",
					zap.Bool("can_read", canRead),
					zap.Bool("can_write", canWrite),
					zap.Bool("can_traverse", canTraverse))

				if canRead && canWrite && canTraverse {
					logger.Info("Vault user has full access to data directory")
					output.WriteString("✓ vault user CAN read /opt/vault/data\n")
					output.WriteString("✓ vault user CAN write to /opt/vault/data\n")
					output.WriteString("✓ vault user CAN traverse /opt/vault/data\n\n")
					result.Metadata["vault_user_can_access_data"] = true
				} else {
					logger.Error("CRITICAL: Vault user cannot properly access data directory",
						zap.Bool("can_read", canRead),
						zap.Bool("can_write", canWrite),
						zap.Bool("can_traverse", canTraverse))
					output.WriteString("✗ CRITICAL: vault user CANNOT properly access /opt/vault/data!\n")
					if !canRead {
						output.WriteString("  ✗ Cannot READ\n")
					}
					if !canWrite {
						output.WriteString("  ✗ Cannot WRITE\n")
					}
					if !canTraverse {
						output.WriteString("  ✗ Cannot TRAVERSE\n")
					}
					output.WriteString("\n")
					result.Metadata["vault_user_can_access_data"] = false
					result.Status = debug.StatusError
					result.Message = "vault user cannot access data directory"
					result.Remediation = "Fix parent directory permissions:\n" +
						"  sudo chown vault:vault /opt/vault\n" +
						"  sudo chmod 755 /opt/vault\n" +
						"  sudo chown -R vault:vault /opt/vault/data\n" +
						"  sudo chmod 700 /opt/vault/data\n" +
						"  sudo systemctl restart vault"
				}

				// Also test parent directory (/opt/vault)
				logger.Debug("Testing vault user access to parent directory")
				output.WriteString("=== Parent Directory Access Test ===\n")
				testParentCmd := exec.CommandContext(ctx, "sudo", "-u", "vault", "test", "-x", "/opt/vault")
				canAccessParent := testParentCmd.Run() == nil

				// Get detailed info about /opt/vault
				statCmd := exec.CommandContext(ctx, "stat", "-c", "Owner: %U:%G, Perms: %a", "/opt/vault")
				statOutput, statErr := statCmd.CombinedOutput()

				logger.Info("Parent directory access test result",
					zap.Bool("can_access", canAccessParent),
					zap.String("stat_info", strings.TrimSpace(string(statOutput))))

				if canAccessParent {
					logger.Info("Vault user can traverse parent directory")
					output.WriteString("✓ vault user CAN traverse /opt/vault (parent directory)\n")
					if statErr == nil {
						output.WriteString(fmt.Sprintf("  Directory info: %s\n", strings.TrimSpace(string(statOutput))))
					}
					output.WriteString("\n")
					result.Metadata["vault_user_can_access_parent"] = true
				} else {
					logger.Error("CRITICAL: Vault user cannot traverse parent directory - this is the root cause of permission errors",
						zap.String("current_permissions", strings.TrimSpace(string(statOutput))))
					output.WriteString("✗ CRITICAL: vault user CANNOT traverse /opt/vault (parent directory)!\n")
					output.WriteString("  This is the ROOT CAUSE of 'permission denied' errors!\n")
					if statErr == nil {
						output.WriteString(fmt.Sprintf("  Current: %s\n", strings.TrimSpace(string(statOutput))))
						output.WriteString("  Expected: Owner: vault:vault, Perms: 755\n")
					}
					output.WriteString("\n")
					result.Metadata["vault_user_can_access_parent"] = false
					result.Status = debug.StatusError
					result.Message = "vault user cannot traverse parent directory /opt/vault"
					result.Remediation = "FIX PARENT DIRECTORY FIRST (this is the bug):\n" +
						"  sudo chown vault:vault /opt/vault\n" +
						"  sudo chmod 755 /opt/vault\n" +
						"Then restart: sudo systemctl restart vault"
				}
			} else {
				output.WriteString("Skipping access tests (vault user or data directory doesn't exist)\n\n")
			}

			// Set final status if not already set by access tests
			if result.Status == "" {
				if idErr == nil && vaultOptErr == nil && dataErr == nil {
					result.Status = debug.StatusOK
					result.Message = "Vault user and directories have correct ownership and access"
				} else {
					result.Status = debug.StatusError
					result.Message = "Permission or ownership issues detected"
					result.Remediation = "Ensure vault user exists and owns directories:\n" +
						"  sudo useradd -r -s /bin/false vault\n" +
						"  sudo chown vault:vault /opt/vault\n" +
						"  sudo chmod 755 /opt/vault\n" +
						"  sudo chown -R vault:vault /opt/vault/data /etc/vault.d\n" +
						"  sudo chmod 700 /opt/vault/data"
				}
			}

			result.Output = output.String()
			return result, nil
		},
	}
}

// ServiceDiagnostic checks the systemd service status
func ServiceDiagnostic() *debug.Diagnostic {
	return debug.SystemdServiceCheck("vault")
}

// ServiceConfigDiagnostic shows the systemd service User and Group configuration
func ServiceConfigDiagnostic() *debug.Diagnostic {
	return &debug.Diagnostic{
		Name:        "Systemd Service Configuration",
		Category:    "Systemd",
		Description: "Show User= and Group= configuration from vault.service",
		Collect: func(ctx context.Context) (*debug.Result, error) {
			result := &debug.Result{
				Metadata: make(map[string]interface{}),
			}

			var output strings.Builder
			output.WriteString("=== Systemd Service Configuration ===\n\n")

			// Run systemctl cat to show full service file
			catCmd := exec.CommandContext(ctx, "systemctl", "cat", "vault.service")
			catOutput, catErr := catCmd.CombinedOutput()

			if catErr != nil {
				output.WriteString("ERROR: Could not read vault.service configuration\n")
				output.WriteString(fmt.Sprintf("Command output: %s\n", string(catOutput)))
				result.Status = debug.StatusError
				result.Message = "Vault service file not found"
				result.Remediation = "Install vault service: sudo eos create vault"
				result.Output = output.String()
				return result, nil
			}

			// Show full service file
			output.WriteString("Full Service File:\n")
			output.WriteString("─────────────────────────────────────────────────────────────\n")
			output.WriteString(string(catOutput))
			output.WriteString("\n")

			// Extract and highlight User= and Group= lines
			output.WriteString("Key Configuration:\n")
			output.WriteString("─────────────────────────────────────────────────────────────\n")

			lines := strings.Split(string(catOutput), "\n")
			foundUser := false
			foundGroup := false
			var user, group string

			for _, line := range lines {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "User=") {
					output.WriteString(fmt.Sprintf("  %s\n", trimmed))
					user = strings.TrimPrefix(trimmed, "User=")
					result.Metadata["user"] = user
					foundUser = true
				} else if strings.HasPrefix(trimmed, "Group=") {
					output.WriteString(fmt.Sprintf("  %s\n", trimmed))
					group = strings.TrimPrefix(trimmed, "Group=")
					result.Metadata["group"] = group
					foundGroup = true
				}
			}

			if !foundUser {
				output.WriteString("  ⚠ WARNING: No User= directive found (will run as root!)\n")
				result.Status = debug.StatusWarning
				result.Message = "Service not configured to run as vault user"
				result.Remediation = "Add 'User=vault' to [Service] section of vault.service"
			}

			if !foundGroup {
				output.WriteString("  ⚠ WARNING: No Group= directive found\n")
			}

			// Verify the user exists
			if foundUser && user != "" {
				idCmd := exec.CommandContext(ctx, "id", user)
				idOutput, idErr := idCmd.CombinedOutput()
				output.WriteString("\nUser Verification:\n")
				if idErr != nil {
					output.WriteString(fmt.Sprintf("  ✗ User '%s' does not exist!\n", user))
					result.Status = debug.StatusError
					result.Message = fmt.Sprintf("Configured user '%s' does not exist", user)
					result.Remediation = fmt.Sprintf("Create user: sudo useradd -r -s /bin/false %s", user)
				} else {
					output.WriteString(fmt.Sprintf("  ✓ User '%s' exists: %s\n", user, strings.TrimSpace(string(idOutput))))
				}
			}

			if result.Status == "" {
				result.Status = debug.StatusOK
				result.Message = "Service configured correctly"
			}

			result.Output = output.String()
			return result, nil
		},
	}
}

// ServiceLogsDiagnostic retrieves recent service logs
func ServiceLogsDiagnostic() *debug.Diagnostic {
	return &debug.Diagnostic{
		Name:        "Service Logs",
		Category:    "Systemd",
		Description: "Recent vault service logs with permission error detection",
		Collect: func(ctx context.Context) (*debug.Result, error) {
			logger := otelzap.Ctx(ctx)
			logger.Info("Retrieving and analyzing Vault service logs")

			result := &debug.Result{
				Metadata: make(map[string]interface{}),
			}

			cmd := exec.CommandContext(ctx, "journalctl", "-u", "vault.service", "-n", "100", "--no-pager")
			output, err := cmd.CombinedOutput()

			outputStr := string(output)

			// Count permission denied errors (the bug we're looking for!)
			permDeniedCount := strings.Count(strings.ToLower(outputStr), "permission denied")
			logger.Info("Analyzed service logs for permission errors",
				zap.Int("permission_denied_count", permDeniedCount),
				zap.Int("log_lines", strings.Count(outputStr, "\n")))

			var enhancedOutput strings.Builder
			enhancedOutput.WriteString("=== Vault Service Logs (last 100 lines) ===\n\n")

			// If permission errors found, highlight them at the top
			if permDeniedCount > 0 {
				logger.Error("CRITICAL: Permission denied errors found in service logs",
					zap.Int("error_count", permDeniedCount))
				enhancedOutput.WriteString(fmt.Sprintf("  CRITICAL: Found %d 'permission denied' errors!\n", permDeniedCount))
				enhancedOutput.WriteString("This indicates the vault user cannot access required directories.\n")
				enhancedOutput.WriteString("This is typically caused by /opt/vault having wrong permissions/ownership.\n\n")

				// Extract just the permission denied lines
				enhancedOutput.WriteString("Permission Denied Errors:\n")
				enhancedOutput.WriteString("─────────────────────────────────────────────────────────────\n")
				lines := strings.Split(outputStr, "\n")
				count := 0
				for _, line := range lines {
					if strings.Contains(strings.ToLower(line), "permission denied") {
						enhancedOutput.WriteString(line)
						enhancedOutput.WriteString("\n")
						count++
						if count >= 5 { // Show first 5, then summarize
							if permDeniedCount > 5 {
								enhancedOutput.WriteString(fmt.Sprintf("... and %d more similar errors\n", permDeniedCount-5))
							}
							break
						}
					}
				}
				enhancedOutput.WriteString("\n")
			}

			// Add full log output
			enhancedOutput.WriteString("Full Log Output:\n")
			enhancedOutput.WriteString("─────────────────────────────────────────────────────────────\n")
			enhancedOutput.WriteString(outputStr)

			result.Output = enhancedOutput.String()
			result.Metadata["permission_denied_count"] = permDeniedCount

			if err != nil {
				result.Status = debug.StatusWarning
				result.Message = "Could not retrieve logs"
			} else if permDeniedCount > 0 {
				// CRITICAL: Permission errors found
				result.Status = debug.StatusError
				result.Message = fmt.Sprintf("CRITICAL: %d permission denied errors (see Permissions diagnostic)", permDeniedCount)
				result.Remediation = "Fix parent directory permissions:\n" +
					"  sudo chown vault:vault /opt/vault\n" +
					"  sudo chmod 755 /opt/vault\n" +
					"  sudo systemctl restart vault\n" +
					"Run 'sudo eos debug vault' for detailed permission analysis"
			} else {
				// Check for other errors in logs
				if strings.Contains(outputStr, "error") || strings.Contains(outputStr, "Error") {
					result.Status = debug.StatusWarning
					result.Message = "Logs contain errors (see output)"
				} else {
					result.Status = debug.StatusInfo
					result.Message = "Logs retrieved successfully, no critical errors"
				}
			}

			return result, nil
		},
	}
}

// ProcessDiagnostic checks for running vault processes
func ProcessDiagnostic() *debug.Diagnostic {
	return debug.CommandCheck("Running Processes", "System", "pgrep", "-a", "vault")
}

// PortDiagnostic checks if vault is listening on configured ports using multiple methods
func PortDiagnostic() *debug.Diagnostic {
	return &debug.Diagnostic{
		Name:        fmt.Sprintf("Vault Ports (%d API, %d Cluster)", shared.PortVault, shared.PortVault+1),
		Category:    "Network",
		Description: fmt.Sprintf("Check if Vault is listening on ports %d (API) and %d (Cluster) using lsof, netstat, and ss", shared.PortVault, shared.PortVault+1),
		Collect: func(ctx context.Context) (*debug.Result, error) {
			logger := otelzap.Ctx(ctx)
			logger.Info("Checking Vault network ports",
				zap.Int("api_port", shared.PortVault),
				zap.Int("cluster_port", shared.PortVault+1))

			result := &debug.Result{
				Metadata: make(map[string]interface{}),
			}

			var outputBuilder strings.Builder
			outputBuilder.WriteString("=== Network Port Diagnostics ===\n\n")

			// Method 1: lsof (shows which process owns the port)
			outputBuilder.WriteString(fmt.Sprintf("Method 1: lsof -i :%d\n", shared.PortVault))
			lsofCmd := exec.CommandContext(ctx, "lsof", "-i", fmt.Sprintf(":%d", shared.PortVault))
			lsofOutput, lsofErr := lsofCmd.CombinedOutput()
			if lsofErr == nil && len(lsofOutput) > 0 {
				outputBuilder.WriteString(string(lsofOutput))
				outputBuilder.WriteString("\n")
			} else if lsofErr != nil && strings.Contains(lsofErr.Error(), "executable file not found") {
				outputBuilder.WriteString("  (lsof not installed)\n\n")
			} else {
				outputBuilder.WriteString(fmt.Sprintf("  No process listening on port %d\n\n", shared.PortVault))
			}

			// Method 2: netstat (traditional, widely available)
			outputBuilder.WriteString(fmt.Sprintf("Method 2: netstat -tulpn | grep %d\n", shared.PortVault))
			netstatCmd := exec.CommandContext(ctx, "sh", "-c", fmt.Sprintf("netstat -tulpn 2>/dev/null | grep ':%d'", shared.PortVault))
			netstatOutput, netstatErr := netstatCmd.CombinedOutput()
			if netstatErr == nil && len(netstatOutput) > 0 {
				outputBuilder.WriteString(string(netstatOutput))
				outputBuilder.WriteString("\n")
			} else if strings.Contains(string(netstatOutput), "command not found") {
				outputBuilder.WriteString("  (netstat not installed)\n\n")
			} else {
				outputBuilder.WriteString(fmt.Sprintf("  No process listening on port %d\n\n", shared.PortVault))
			}

			// Method 3: ss (modern replacement for netstat)
			outputBuilder.WriteString(fmt.Sprintf("Method 3: ss -tulpn | grep %d\n", shared.PortVault))
			ssCmd := exec.CommandContext(ctx, "sh", "-c", fmt.Sprintf("ss -tulpn | grep ':%d'", shared.PortVault))
			ssOutput, ssErr := ssCmd.CombinedOutput()
			if ssErr == nil && len(ssOutput) > 0 {
				outputBuilder.WriteString(string(ssOutput))
				outputBuilder.WriteString("\n")
			} else {
				outputBuilder.WriteString(fmt.Sprintf("  No process listening on port %d\n\n", shared.PortVault))
			}

			// Check cluster port (8180) with ss/netstat only
			outputBuilder.WriteString(fmt.Sprintf("Cluster Port Check: %d\n", shared.PortVault+1))
			clusterCmd := exec.CommandContext(ctx, "sh", "-c", fmt.Sprintf("ss -tlnp | grep ':%d' || netstat -tlnp 2>/dev/null | grep ':%d'", shared.PortVault+1, shared.PortVault+1))
			clusterOutput, _ := clusterCmd.CombinedOutput()

			// Determine if API port is listening based on any method
			apiListening := (lsofErr == nil && len(lsofOutput) > 0) ||
				(netstatErr == nil && len(netstatOutput) > 0) ||
				(ssErr == nil && len(ssOutput) > 0)

			clusterListening := len(clusterOutput) > 0

			result.Metadata["api_port"] = shared.PortVault
			result.Metadata["cluster_port"] = shared.PortVault + 1
			result.Metadata["api_listening"] = apiListening
			result.Metadata["cluster_listening"] = clusterListening
			result.Metadata["lsof_available"] = lsofErr == nil || !strings.Contains(string(lsofOutput), "not found")
			result.Metadata["netstat_available"] = netstatErr == nil || !strings.Contains(string(netstatOutput), "not found")
			result.Metadata["ss_available"] = ssErr == nil

			// Summary
			outputBuilder.WriteString("\n=== Summary ===\n")
			if apiListening {
				outputBuilder.WriteString(fmt.Sprintf("✓ API Port %d: LISTENING\n", shared.PortVault))
			} else {
				outputBuilder.WriteString(fmt.Sprintf("✗ API Port %d: NOT IN USE\n", shared.PortVault))
			}

			if clusterListening {
				outputBuilder.WriteString(fmt.Sprintf("✓ Cluster Port %d: LISTENING\n", shared.PortVault+1))
				outputBuilder.WriteString(string(clusterOutput))
			} else {
				outputBuilder.WriteString(fmt.Sprintf("✗ Cluster Port %d: NOT IN USE (normal for single-node)\n", shared.PortVault+1))
			}

			// Diagnostic commands for manual verification
			outputBuilder.WriteString("\n=== Manual Verification Commands ===\n")
			outputBuilder.WriteString(fmt.Sprintf("sudo lsof -i :%d\n", shared.PortVault))
			outputBuilder.WriteString(fmt.Sprintf("sudo netstat -tulpn | grep %d\n", shared.PortVault))
			outputBuilder.WriteString(fmt.Sprintf("sudo ss -tulpn | grep %d\n", shared.PortVault))
			outputBuilder.WriteString("curl -k https://localhost:8179/v1/sys/health\n")

			result.Output = outputBuilder.String()

			// Set status based on results
			if apiListening && clusterListening {
				logger.Info("Both Vault ports are listening",
					zap.Int("api_port", shared.PortVault),
					zap.Int("cluster_port", shared.PortVault+1))
				result.Status = debug.StatusOK
				result.Message = "Both API and cluster ports are listening"
			} else if apiListening {
				logger.Info("Vault API port is listening (cluster port not active)",
					zap.Int("api_port", shared.PortVault),
					zap.Bool("cluster_listening", false))
				result.Status = debug.StatusOK
				result.Message = "API port listening (cluster port not needed for single-node)"
			} else {
				logger.Error("Vault is not listening on configured port",
					zap.Int("expected_port", shared.PortVault))
				result.Status = debug.StatusError
				result.Message = fmt.Sprintf("Port %d not in use - Vault is not listening", shared.PortVault)
				result.Remediation = "Ensure vault service is running: sudo systemctl status vault\n" +
					"Check service logs: sudo journalctl -u vault -n 50\n" +
					"Verify configuration: vault validate /etc/vault.d/vault.hcl"
			}

			return result, nil
		},
	}
}

// HealthCheckDiagnostic performs HTTP health check
func HealthCheckDiagnostic() *debug.Diagnostic {
	healthURL := fmt.Sprintf("http://127.0.0.1:%d/v1/sys/health", shared.PortVault)
	return debug.NetworkCheck("HTTP Health Check", healthURL, 5*time.Second)
}

// EnvironmentDiagnostic checks vault environment variables
func EnvironmentDiagnostic() *debug.Diagnostic {
	return &debug.Diagnostic{
		Name:        "Environment Variables",
		Category:    "Configuration",
		Description: "Check Vault environment variables",
		Collect: func(ctx context.Context) (*debug.Result, error) {
			result := &debug.Result{
				Metadata: make(map[string]interface{}),
			}

			envVars := map[string]string{
				"VAULT_ADDR":        os.Getenv("VAULT_ADDR"),
				"VAULT_TOKEN":       maskToken(os.Getenv("VAULT_TOKEN")),
				"VAULT_CACERT":      os.Getenv("VAULT_CACERT"),
				"VAULT_SKIP_VERIFY": os.Getenv("VAULT_SKIP_VERIFY"),
				"VAULT_NAMESPACE":   os.Getenv("VAULT_NAMESPACE"),
			}

			var output strings.Builder
			hasVars := false
			for k, v := range envVars {
				if v != "" {
					output.WriteString(fmt.Sprintf("%s=%s\n", k, v))
					result.Metadata[k] = v
					hasVars = true
				}
			}

			result.Output = output.String()

			if hasVars {
				result.Status = debug.StatusInfo
				result.Message = "Environment variables configured"
			} else {
				result.Status = debug.StatusInfo
				result.Message = "No Vault environment variables set"
			}

			return result, nil
		},
	}
}

// CapabilitiesDiagnostic checks binary capabilities
func CapabilitiesDiagnostic() *debug.Diagnostic {
	return debug.CommandCheck("Binary Capabilities", "System", "getcap", DefaultBinaryPath)
}

// Helper function to mask tokens
func maskToken(token string) string {
	if token == "" {
		return ""
	}
	if len(token) <= 8 {
		return "***"
	}
	return token[:4] + "..." + token[len(token)-4:]
}

// DeletionTransactionLogsDiagnostic checks for vault deletion transaction logs
func DeletionTransactionLogsDiagnostic() *debug.Diagnostic {
	return &debug.Diagnostic{
		Name:        "Deletion Transaction Logs",
		Category:    "Deletion History",
		Description: "Check for vault deletion transaction logs and analyze deletion attempts",
		Collect: func(ctx context.Context) (*debug.Result, error) {
			result := &debug.Result{
				Metadata: make(map[string]interface{}),
			}

			// Check if transaction directory exists
			if _, err := os.Stat(DeletionTransactionDir); os.IsNotExist(err) {
				result.Status = debug.StatusOK
				result.Message = "No deletion transaction logs found (vault has not been deleted)"
				result.Output = fmt.Sprintf("Directory %s does not exist\n", DeletionTransactionDir)
				return result, nil
			}

			// Find all vault-deletion-*.log files
			entries, err := os.ReadDir(DeletionTransactionDir)
			if err != nil {
				result.Status = debug.StatusWarning
				result.Message = "Could not read transaction log directory"
				result.Output = fmt.Sprintf("Error reading %s: %v\n", DeletionTransactionDir, err)
				return result, nil
			}

			var logFiles []string
			var latestLog string
			var latestTime time.Time

			for _, entry := range entries {
				if !entry.IsDir() && strings.HasPrefix(entry.Name(), "vault-deletion-") && strings.HasSuffix(entry.Name(), ".log") {
					logPath := fmt.Sprintf("%s/%s", DeletionTransactionDir, entry.Name())
					logFiles = append(logFiles, logPath)

					// Track the latest log file
					info, err := entry.Info()
					if err == nil && info.ModTime().After(latestTime) {
						latestTime = info.ModTime()
						latestLog = logPath
					}
				}
			}

			result.Metadata["log_count"] = len(logFiles)
			result.Metadata["log_files"] = logFiles

			if len(logFiles) == 0 {
				result.Status = debug.StatusOK
				result.Message = "No vault deletion logs found"
				result.Output = "No vault-deletion-*.log files in " + DeletionTransactionDir + "\n"
				return result, nil
			}

			// Build output showing all logs
			var output strings.Builder
			output.WriteString(fmt.Sprintf("Found %d deletion transaction log(s):\n\n", len(logFiles)))

			for _, logFile := range logFiles {
				info, err := os.Stat(logFile)
				if err != nil {
					continue
				}
				marker := ""
				if logFile == latestLog {
					marker = " (LATEST)"
				}
				output.WriteString(fmt.Sprintf("  - %s%s\n", logFile, marker))
				output.WriteString(fmt.Sprintf("    Modified: %s\n", info.ModTime().Format(time.RFC3339)))
				output.WriteString(fmt.Sprintf("    Size: %d bytes\n", info.Size()))
			}

			// Read and display the latest log
			if latestLog != "" {
				output.WriteString("\n═══════════════════════════════════════════════════════════════\n")
				output.WriteString(fmt.Sprintf("Latest Deletion Log: %s\n", latestLog))
				output.WriteString("═══════════════════════════════════════════════════════════════\n\n")

				content, err := os.ReadFile(latestLog)
				if err != nil {
					output.WriteString(fmt.Sprintf("Error reading log: %v\n", err))
				} else {
					output.WriteString(string(content))

					// Analyze the log content for issues
					contentStr := string(content)
					result.Metadata["latest_log"] = latestLog
					result.Metadata["log_content"] = contentStr

					if strings.Contains(contentStr, "INTERRUPTED") {
						result.Status = debug.StatusError
						result.Message = "Deletion was interrupted - system may be in inconsistent state"
						result.Remediation = "Run 'sudo eos delete vault' to retry deletion"
					} else if strings.Contains(contentStr, "FAILED") {
						result.Status = debug.StatusError
						result.Message = "Deletion encountered failures"
						result.Remediation = "Review log for errors, then retry deletion"
					} else if strings.Contains(contentStr, "FINISHED") && strings.Contains(contentStr, "SUCCESS") {
						result.Status = debug.StatusOK
						result.Message = "Last deletion completed successfully"
					} else {
						result.Status = debug.StatusWarning
						result.Message = "Deletion log exists but status unclear"
						result.Remediation = "Review log contents to determine current state"
					}
				}

				// Add analysis of what might still be present
				output.WriteString("\n")
				output.WriteString("Current System State Check:\n")
				output.WriteString("─────────────────────────────────────────────────────────────\n")

				// Check if components still exist
				checks := map[string]string{
					"VaultBinaryPath":                   "Binary",
					"/etc/vault.d":                      "Config directory",
					"/opt/vault":                        "Data directory",
					"/var/log/vault":                    "Log directory",
					"/etc/systemd/system/vault.service": "Service file",
				}

				stillPresent := []string{}
				for path, desc := range checks {
					if _, err := os.Stat(path); err == nil {
						stillPresent = append(stillPresent, fmt.Sprintf("%s (%s)", desc, path))
						output.WriteString(fmt.Sprintf("  ✗ %s still exists: %s\n", desc, path))
					} else {
						output.WriteString(fmt.Sprintf("  ✓ %s removed: %s\n", desc, path))
					}
				}

				result.Metadata["remaining_components"] = stillPresent

				if len(stillPresent) > 0 {
					output.WriteString("\n⚠ WARNING: Partial deletion detected - some components remain\n")
					if result.Status == debug.StatusOK {
						result.Status = debug.StatusWarning
						result.Message = "Deletion completed but some components still present"
						result.Remediation = "Run 'sudo eos delete vault' to complete removal"
					}
				}
			}

			result.Output = output.String()

			if result.Status == "" {
				result.Status = debug.StatusWarning
			}

			return result, nil
		},
	}
}

//--------------------------------------------------------------------
// Vault Agent Diagnostics
//--------------------------------------------------------------------

// VaultAgentServiceDiagnostic checks the vault-agent-eos service status
func VaultAgentServiceDiagnostic() *debug.Diagnostic {
	return &debug.Diagnostic{
		Name:        "Vault Agent Service",
		Category:    "Vault Agent",
		Description: "Check vault-agent-eos systemd service status",
		Condition: func(ctx context.Context) bool {
			// Check if systemd service file exists
			_, err := os.Stat("/etc/systemd/system/vault-agent-eos.service")
			return err == nil
		},
		Collect: func(ctx context.Context) (*debug.Result, error) {
			logger := otelzap.Ctx(ctx)
			logger.Info("Checking Vault Agent service status")

			result := &debug.Result{
				Metadata: make(map[string]interface{}),
			}

			cmd := exec.CommandContext(ctx, "systemctl", "status", "vault-agent-eos")
			output, err := cmd.CombinedOutput()
			result.Output = string(output)

			// Check if service is active
			isActiveCmd := exec.CommandContext(ctx, "systemctl", "is-active", "vault-agent-eos")
			activeOutput, _ := isActiveCmd.CombinedOutput()
			isActive := strings.TrimSpace(string(activeOutput)) == "active"

			result.Metadata["is_active"] = isActive
			result.Metadata["service_name"] = "vault-agent-eos.service"

			if isActive {
				result.Status = debug.StatusOK
				result.Message = "Service is running"
			} else if err == nil {
				result.Status = debug.StatusWarning
				result.Message = fmt.Sprintf("Service is not active: %s", strings.TrimSpace(string(activeOutput)))
				result.Remediation = "Start service: sudo systemctl start vault-agent-eos"
			} else {
				result.Status = debug.StatusError
				result.Message = "Service not found or failed to query"
				result.Remediation = "Install Vault Agent: eos enable vault agent"
			}

			return result, nil
		},
	}
}

// VaultAgentConfigDiagnostic checks the Vault Agent configuration file
func VaultAgentConfigDiagnostic() *debug.Diagnostic {
	return &debug.Diagnostic{
		Name:        "Vault Agent Configuration",
		Category:    "Vault Agent",
		Description: "Check Vault Agent config file existence and validity",
		Condition: func(ctx context.Context) bool {
			return true // Always run
		},
		Collect: func(ctx context.Context) (*debug.Result, error) {
			logger := otelzap.Ctx(ctx)
			configPath := DefaultAgentConfigPath

			result := &debug.Result{
				Metadata: make(map[string]interface{}),
			}
			result.Metadata["config_path"] = configPath

			logger.Info("Checking Vault Agent configuration", zap.String("path", configPath))

			// Check if config exists
			stat, err := os.Stat(configPath)
			if os.IsNotExist(err) {
				result.Status = debug.StatusError
				result.Message = "Configuration file not found"
				result.Output = fmt.Sprintf("File does not exist: %s", configPath)
				result.Remediation = "Configure Vault Agent: eos enable vault agent"
				return result, nil
			} else if err != nil {
				result.Status = debug.StatusError
				result.Message = "Failed to stat configuration file"
				result.Output = err.Error()
				return result, nil
			}

			// Read and display config
			content, err := os.ReadFile(configPath)
			if err != nil {
				result.Status = debug.StatusWarning
				result.Message = fmt.Sprintf("File exists (%d bytes) but cannot read", stat.Size())
				result.Output = err.Error()
				return result, nil
			}

			result.Status = debug.StatusOK
			result.Message = fmt.Sprintf("Configuration file exists (%d bytes)", len(content))
			result.Output = string(content)
			result.Metadata["size_bytes"] = len(content)
			result.Metadata["mode"] = stat.Mode().String()

			return result, nil
		},
	}
}

// VaultAgentCredentialsDiagnostic checks AppRole credentials for Vault Agent
func VaultAgentCredentialsDiagnostic() *debug.Diagnostic {
	return &debug.Diagnostic{
		Name:        "Vault Agent Credentials",
		Category:    "Vault Agent",
		Description: "Check AppRole role_id and secret_id files",
		Condition: func(ctx context.Context) bool {
			return true // Always run
		},
		Collect: func(ctx context.Context) (*debug.Result, error) {
			logger := otelzap.Ctx(ctx)
			// Use shared constants instead of hardcoded paths
			roleIDPath := shared.AppRolePaths.RoleID
			secretIDPath := shared.AppRolePaths.SecretID

			result := &debug.Result{
				Metadata: make(map[string]interface{}),
			}

			var output strings.Builder
			output.WriteString("=== AppRole Credentials Check ===\n\n")

			// Check role_id
			roleIDStat, roleIDErr := os.Stat(roleIDPath)
			result.Metadata["role_id_path"] = roleIDPath
			result.Metadata["role_id_exists"] = roleIDErr == nil

			if roleIDErr == nil {
				output.WriteString(fmt.Sprintf("✓ role_id file exists: %s\n", roleIDPath))
				output.WriteString(fmt.Sprintf("  Size: %d bytes\n", roleIDStat.Size()))
				output.WriteString(fmt.Sprintf("  Mode: %s\n", roleIDStat.Mode().String()))
				result.Metadata["role_id_size"] = roleIDStat.Size()
				result.Metadata["role_id_mode"] = roleIDStat.Mode().String()

				// Try to read (as root)
				roleIDContent, err := os.ReadFile(roleIDPath)
				if err == nil && len(roleIDContent) > 0 {
					output.WriteString(fmt.Sprintf("  Content: %d characters (redacted)\n", len(strings.TrimSpace(string(roleIDContent)))))
					result.Metadata["role_id_populated"] = true
				} else {
					output.WriteString("  ✗ File is empty or unreadable\n")
					result.Metadata["role_id_populated"] = false
				}
			} else {
				output.WriteString(fmt.Sprintf("✗ role_id file NOT found: %s\n", roleIDPath))
				output.WriteString(fmt.Sprintf("  Error: %v\n", roleIDErr))
			}

			output.WriteString("\n")

			// Check secret_id
			secretIDStat, secretIDErr := os.Stat(secretIDPath)
			result.Metadata["secret_id_path"] = secretIDPath
			result.Metadata["secret_id_exists"] = secretIDErr == nil

			if secretIDErr == nil {
				output.WriteString(fmt.Sprintf("✓ secret_id file exists: %s\n", secretIDPath))
				output.WriteString(fmt.Sprintf("  Size: %d bytes\n", secretIDStat.Size()))
				output.WriteString(fmt.Sprintf("  Mode: %s\n", secretIDStat.Mode().String()))
				result.Metadata["secret_id_size"] = secretIDStat.Size()
				result.Metadata["secret_id_mode"] = secretIDStat.Mode().String()

				// Try to read (as root)
				secretIDContent, err := os.ReadFile(secretIDPath)
				if err == nil && len(secretIDContent) > 0 {
					output.WriteString(fmt.Sprintf("  Content: %d characters (redacted)\n", len(strings.TrimSpace(string(secretIDContent)))))
					result.Metadata["secret_id_populated"] = true
				} else {
					output.WriteString("  ✗ File is empty or unreadable\n")
					result.Metadata["secret_id_populated"] = false
				}
			} else {
				output.WriteString(fmt.Sprintf("✗ secret_id file NOT found: %s\n", secretIDPath))
				output.WriteString(fmt.Sprintf("  Error: %v\n", secretIDErr))
			}

			output.WriteString("\n")

			// Test if vault user can read credentials
			output.WriteString("=== Vault User Access Test ===\n")
			testCmd := exec.CommandContext(ctx, "sudo", "-u", "vault", "test", "-r", roleIDPath)
			canReadRoleID := testCmd.Run() == nil
			if canReadRoleID {
				output.WriteString(fmt.Sprintf("✓ vault user CAN read: %s\n", roleIDPath))
			} else {
				output.WriteString(fmt.Sprintf("✗ vault user CANNOT read: %s\n", roleIDPath))
			}

			testCmd = exec.CommandContext(ctx, "sudo", "-u", "vault", "test", "-r", secretIDPath)
			canReadSecretID := testCmd.Run() == nil
			if canReadSecretID {
				output.WriteString(fmt.Sprintf("✓ vault user CAN read: %s\n", secretIDPath))
			} else {
				output.WriteString(fmt.Sprintf("✗ vault user CANNOT read: %s\n", secretIDPath))
			}

			// If vault user cannot read credentials, show directory permissions for debugging
			if !canReadRoleID || !canReadSecretID {
				output.WriteString("\n=== Directory Permissions Diagnostic ===\n")
				output.WriteString("Checking parent directory permissions...\n\n")

				// Check /var/lib/eos/
				output.WriteString("Parent directory: /var/lib/eos/\n")
				lsCmd := exec.CommandContext(ctx, "ls", "-ld", "/var/lib/eos/")
				if lsOutput, err := lsCmd.CombinedOutput(); err == nil {
					output.WriteString(string(lsOutput))
				}

				// Check /var/lib/eos/secret/
				output.WriteString("\nSecrets directory: /var/lib/eos/secret/\n")
				lsCmd = exec.CommandContext(ctx, "ls", "-ld", "/var/lib/eos/secret/")
				if lsOutput, err := lsCmd.CombinedOutput(); err == nil {
					output.WriteString(string(lsOutput))
				}

				// List contents of /var/lib/eos/secret/ as root
				output.WriteString("\nSecrets directory contents (as root):\n")
				lsCmd = exec.CommandContext(ctx, "ls", "-la", "/var/lib/eos/secret/")
				if lsOutput, err := lsCmd.CombinedOutput(); err == nil {
					output.WriteString(string(lsOutput))
				}

				// Try to list as vault user (will fail if permissions wrong)
				output.WriteString("\nSecrets directory contents (as vault user):\n")
				lsCmd = exec.CommandContext(ctx, "sudo", "-u", "vault", "ls", "-la", "/var/lib/eos/secret/")
				if lsOutput, err := lsCmd.CombinedOutput(); err == nil {
					output.WriteString(string(lsOutput))
				} else {
					output.WriteString(fmt.Sprintf("Error: %v\n", err))
					output.WriteString(string(lsOutput))
					output.WriteString("\n⚠ This indicates a directory traversal permission issue!\n")
					output.WriteString("The vault user cannot traverse /var/lib/eos/ to reach /var/lib/eos/secret/\n")
				}
			}

			result.Output = output.String()

			// Determine status
			bothExist := roleIDErr == nil && secretIDErr == nil
			if bothExist {
				result.Status = debug.StatusOK
				result.Message = "AppRole credentials found"
			} else {
				result.Status = debug.StatusError
				result.Message = "AppRole credentials missing"
				result.Remediation = "Enable AppRole auth: eos enable vault approle"
			}

			logger.Info("Vault Agent credentials check complete",
				zap.Bool("role_id_exists", roleIDErr == nil),
				zap.Bool("secret_id_exists", secretIDErr == nil))

			return result, nil
		},
	}
}

// VaultAgentTokenDiagnostic checks the Vault Agent token file
func VaultAgentTokenDiagnostic() *debug.Diagnostic {
	return &debug.Diagnostic{
		Name:        "Vault Agent Token",
		Category:    "Vault Agent",
		Description: "Check Vault Agent token sink file",
		Condition: func(ctx context.Context) bool {
			return true // Always run
		},
		Collect: func(ctx context.Context) (*debug.Result, error) {
			logger := otelzap.Ctx(ctx)
			// Use shared constants instead of hardcoded paths
			tokenPath := shared.AgentToken
			runtimeDir := shared.EosRunDir

			result := &debug.Result{
				Metadata: make(map[string]interface{}),
			}
			result.Metadata["token_path"] = tokenPath
			result.Metadata["runtime_dir"] = runtimeDir

			var output strings.Builder
			output.WriteString("=== Vault Agent Token Sink Check ===\n\n")

			// Check runtime directory
			runtimeStat, runtimeErr := os.Stat(runtimeDir)
			if runtimeErr == nil {
				output.WriteString(fmt.Sprintf("✓ Runtime directory exists: %s\n", runtimeDir))
				output.WriteString(fmt.Sprintf("  Mode: %s\n", runtimeStat.Mode().String()))

				result.Metadata["runtime_dir_exists"] = true
				result.Metadata["runtime_dir_mode"] = runtimeStat.Mode().String()

				// List contents
				entries, err := os.ReadDir(runtimeDir)
				if err == nil {
					output.WriteString(fmt.Sprintf("  Contents: %d files\n", len(entries)))
					for _, entry := range entries {
						info, _ := entry.Info()
						if info != nil {
							output.WriteString(fmt.Sprintf("    - %s (%s, %d bytes)\n",
								entry.Name(), info.Mode().String(), info.Size()))
						}
					}
				}
			} else {
				output.WriteString(fmt.Sprintf("✗ Runtime directory NOT found: %s\n", runtimeDir))
				output.WriteString(fmt.Sprintf("  Error: %v\n", runtimeErr))
				result.Metadata["runtime_dir_exists"] = false
			}

			output.WriteString("\n")

			// Check token file
			tokenStat, tokenErr := os.Stat(tokenPath)
			result.Metadata["token_file_exists"] = tokenErr == nil

			if tokenErr == nil {
				output.WriteString(fmt.Sprintf("✓ Token file exists: %s\n", tokenPath))
				output.WriteString(fmt.Sprintf("  Size: %d bytes\n", tokenStat.Size()))
				output.WriteString(fmt.Sprintf("  Mode: %s\n", tokenStat.Mode().String()))
				output.WriteString(fmt.Sprintf("  Modified: %s\n", tokenStat.ModTime().Format(time.RFC3339)))

				result.Metadata["token_file_size"] = tokenStat.Size()
				result.Metadata["token_file_mode"] = tokenStat.Mode().String()
				result.Metadata["token_file_mtime"] = tokenStat.ModTime().Format(time.RFC3339)

				if tokenStat.Size() == 0 {
					output.WriteString("\n⚠ WARNING: Token file is EMPTY (0 bytes)\n")
					output.WriteString("  This means Vault Agent has NOT successfully authenticated yet.\n")
					output.WriteString("  Check Vault Agent logs for authentication errors.\n")
					result.Status = debug.StatusWarning
					result.Message = "Token file exists but is empty - Agent not authenticated"
					result.Remediation = "Check Vault Agent logs: sudo journalctl -u vault-agent-eos -n 50"
				} else {
					// Try to read token (redacted)
					tokenContent, err := os.ReadFile(tokenPath)
					if err == nil {
						token := strings.TrimSpace(string(tokenContent))
						output.WriteString(fmt.Sprintf("\n✓ Token file has content: %d characters\n", len(token)))
						if len(token) >= 16 {
							output.WriteString(fmt.Sprintf("  Token preview: %s...%s (redacted)\n",
								token[:8], token[len(token)-8:]))
						}
						result.Status = debug.StatusOK
						result.Message = "Token file populated - Agent authenticated successfully"
						result.Metadata["token_populated"] = true
					} else {
						output.WriteString(fmt.Sprintf("\n✗ Cannot read token file: %v\n", err))
						result.Status = debug.StatusWarning
						result.Message = "Token file exists but cannot be read"
					}
				}
			} else {
				output.WriteString(fmt.Sprintf("✗ Token file NOT found: %s\n", tokenPath))
				output.WriteString(fmt.Sprintf("  Error: %v\n", tokenErr))
				result.Status = debug.StatusError
				result.Message = "Token file does not exist"
				result.Remediation = "Start Vault Agent: sudo systemctl start vault-agent-eos"
				result.Metadata["token_file_exists"] = false
			}

			result.Output = output.String()

			logger.Info("Vault Agent token check complete",
				zap.Bool("token_exists", tokenErr == nil),
				zap.Int64("token_size", func() int64 {
					if tokenStat != nil {
						return tokenStat.Size()
					}
					return 0
				}()))

			return result, nil
		},
	}
}

// VaultAgentLogsDiagnostic retrieves recent Vault Agent service logs
func VaultAgentLogsDiagnostic() *debug.Diagnostic {
	return &debug.Diagnostic{
		Name:        "Vault Agent Logs",
		Category:    "Vault Agent",
		Description: "Retrieve recent Vault Agent service logs",
		Condition: func(ctx context.Context) bool {
			// Only run if service file exists
			_, err := os.Stat("/etc/systemd/system/vault-agent-eos.service")
			return err == nil
		},
		Collect: func(ctx context.Context) (*debug.Result, error) {
			logger := otelzap.Ctx(ctx)
			logger.Info("Retrieving Vault Agent service logs")

			result := &debug.Result{
				Metadata: make(map[string]interface{}),
			}

			var output strings.Builder
			output.WriteString("=== Vault Agent Service Logs (last 100 lines) ===\n\n")

			// Get logs
			cmd := exec.CommandContext(ctx, "journalctl", "-u", "vault-agent-eos", "-n", "100", "--no-pager")
			logOutput, err := cmd.CombinedOutput()

			if err != nil {
				output.WriteString(fmt.Sprintf("Failed to retrieve logs: %v\n", err))
				result.Status = debug.StatusWarning
				result.Message = "Could not retrieve service logs"
			} else {
				logs := string(logOutput)
				output.WriteString(logs)

				// Analyze logs for common errors
				errorCount := strings.Count(logs, "level=error")
				warnCount := strings.Count(logs, "level=warn")
				authFailCount := strings.Count(logs, "auth") + strings.Count(logs, "authentication")

				result.Metadata["error_count"] = errorCount
				result.Metadata["warning_count"] = warnCount
				result.Metadata["auth_mentions"] = authFailCount
				result.Metadata["log_lines"] = strings.Count(logs, "\n")

				output.WriteString("\n=== Log Analysis ===\n")
				output.WriteString(fmt.Sprintf("Errors: %d\n", errorCount))
				output.WriteString(fmt.Sprintf("Warnings: %d\n", warnCount))
				output.WriteString(fmt.Sprintf("Auth mentions: %d\n", authFailCount))

				if errorCount > 0 {
					result.Status = debug.StatusError
					result.Message = fmt.Sprintf("Logs contain %d error(s)", errorCount)
					result.Remediation = "Review error messages in logs above"
				} else if warnCount > 0 {
					result.Status = debug.StatusWarning
					result.Message = fmt.Sprintf("Logs contain %d warning(s)", warnCount)
				} else {
					result.Status = debug.StatusOK
					result.Message = "No errors in recent logs"
				}
			}

			result.Output = output.String()
			return result, nil
		},
	}
}

// IdempotencyStatusDiagnostic checks the current installation state for idempotent operations
// This helps users understand what already exists before running "eos create vault"
func IdempotencyStatusDiagnostic() *debug.Diagnostic {
	return &debug.Diagnostic{
		Name:        "Idempotency Status",
		Category:    "Installation State",
		Description: "Check current installation state for idempotent operations",
		Collect: func(ctx context.Context) (*debug.Result, error) {
			logger := otelzap.Ctx(ctx)
			logger.Info("Checking idempotency status - what components already exist")

			result := &debug.Result{
				Metadata: make(map[string]interface{}),
			}

			var output strings.Builder
			output.WriteString("=== Idempotency Status - Current Installation State ===\n\n")
			output.WriteString("This shows what components already exist. Eos 'create vault' commands\n")
			output.WriteString("are idempotent and will verify/update existing components rather than fail.\n\n")

			componentCount := 0
			existingCount := 0

			// Check Vault binary
			componentCount++
			if binaryPath, err := exec.LookPath("vault"); err == nil {
				existingCount++
				output.WriteString("✓ Vault Binary: EXISTS\n")
				result.Metadata["binary_exists"] = true
				result.Metadata["binary_path"] = binaryPath

				// Get version
				if versionCmd := exec.CommandContext(ctx, "vault", "version"); versionCmd != nil {
					if versionOut, err := versionCmd.Output(); err == nil {
						version := strings.TrimSpace(string(versionOut))
						output.WriteString(fmt.Sprintf("  └─ Version: %s\n", version))
						result.Metadata["binary_version"] = version
					}
				}
			} else {
				output.WriteString("✗ Vault Binary: NOT FOUND\n")
				result.Metadata["binary_exists"] = false
			}

			// Check Vault user
			componentCount++
			if userCmd := exec.CommandContext(ctx, "id", "vault"); userCmd.Run() == nil {
				existingCount++
				output.WriteString("✓ Vault User: EXISTS\n")
				result.Metadata["user_exists"] = true

				// Get user details
				if idCmd := exec.CommandContext(ctx, "id", "vault"); idCmd != nil {
					if idOut, err := idCmd.Output(); err == nil {
						output.WriteString(fmt.Sprintf("  └─ %s\n", strings.TrimSpace(string(idOut))))
					}
				}
			} else {
				output.WriteString("✗ Vault User: NOT FOUND\n")
				result.Metadata["user_exists"] = false
			}

			// Check Vault service
			componentCount++
			if statusCmd := exec.CommandContext(ctx, "systemctl", "is-active", "vault"); statusCmd != nil {
				if statusOut, err := statusCmd.Output(); err == nil {
					status := strings.TrimSpace(string(statusOut))
					existingCount++
					output.WriteString(fmt.Sprintf("✓ Vault Service: %s\n", strings.ToUpper(status)))
					result.Metadata["service_exists"] = true
					result.Metadata["service_status"] = status

					// Get service uptime
					if uptimeCmd := exec.CommandContext(ctx, "systemctl", "show", "vault", "--property=ActiveEnterTimestamp"); uptimeCmd != nil {
						if uptimeOut, err := uptimeCmd.Output(); err == nil {
							uptime := strings.TrimSpace(strings.TrimPrefix(string(uptimeOut), "ActiveEnterTimestamp="))
							output.WriteString(fmt.Sprintf("  └─ Started: %s\n", uptime))
						}
					}
				} else {
					output.WriteString("✗ Vault Service: NOT ACTIVE\n")
					result.Metadata["service_exists"] = false
				}
			}

			// Check Vault Agent service
			componentCount++
			if agentStatusCmd := exec.CommandContext(ctx, "systemctl", "is-active", "vault-agent-eos"); agentStatusCmd != nil {
				if agentOut, err := agentStatusCmd.Output(); err == nil {
					status := strings.TrimSpace(string(agentOut))
					existingCount++
					output.WriteString(fmt.Sprintf("✓ Vault Agent Service: %s\n", strings.ToUpper(status)))
					result.Metadata["agent_service_exists"] = true
					result.Metadata["agent_service_status"] = status
				} else {
					output.WriteString("✗ Vault Agent Service: NOT ACTIVE\n")
					result.Metadata["agent_service_exists"] = false
				}
			}

			// Check ports in use
			componentCount++
			vaultPort := shared.PortVault // 8179
			if conn, err := exec.CommandContext(ctx, "lsof", "-i", fmt.Sprintf(":%d", vaultPort), "-sTCP:LISTEN").Output(); err == nil && len(conn) > 0 {
				existingCount++
				output.WriteString(fmt.Sprintf("✓ Port %d: IN USE\n", vaultPort))
				result.Metadata["port_in_use"] = true

				// Check if it's vault using the port
				if strings.Contains(strings.ToLower(string(conn)), "vault") {
					output.WriteString("  └─ Used by: Vault process (expected)\n")
					result.Metadata["port_used_by_vault"] = true
				} else {
					output.WriteString("  └─ Used by: OTHER process (conflict!)\n")
					result.Metadata["port_used_by_vault"] = false
				}
			} else {
				output.WriteString(fmt.Sprintf("✗ Port %d: NOT IN USE\n", vaultPort))
				result.Metadata["port_in_use"] = false
			}

			// Check key directories
			componentCount++
			keyDirs := []string{
				"/opt/vault/data",
				"/opt/vault/logs",
				"/etc/vault.d",
				"/var/lib/eos/secret",
			}
			dirsExist := 0
			for _, dir := range keyDirs {
				if _, err := os.Stat(dir); err == nil {
					dirsExist++
				}
			}
			if dirsExist > 0 {
				existingCount++
				output.WriteString(fmt.Sprintf("✓ Key Directories: %d/%d exist\n", dirsExist, len(keyDirs)))
				result.Metadata["directories_exist_count"] = dirsExist
			} else {
				output.WriteString("✗ Key Directories: NONE EXIST\n")
				result.Metadata["directories_exist_count"] = 0
			}

			// Summary
			output.WriteString("\n=== Summary ===\n")
			output.WriteString(fmt.Sprintf("Existing Components: %d/%d\n", existingCount, componentCount))
			result.Metadata["total_components"] = componentCount
			result.Metadata["existing_components"] = existingCount

			percentage := int(float64(existingCount) / float64(componentCount) * 100)
			result.Metadata["installation_percentage"] = percentage

			output.WriteString("\n=== Idempotency Behavior ===\n")
			if existingCount == 0 {
				output.WriteString("✓ Clean system - 'eos create vault' will perform full installation\n")
				result.Status = debug.StatusOK
				result.Message = "Clean system ready for installation"
			} else if existingCount == componentCount {
				output.WriteString("✓ Fully installed - 'eos create vault' will verify and update configuration\n")
				output.WriteString("  Eos will check existing components and update if needed (idempotent)\n")
				result.Status = debug.StatusOK
				result.Message = "Vault fully installed - operations are idempotent"
			} else {
				output.WriteString(fmt.Sprintf("⚠ Partial installation (%d%%) - 'eos create vault' will complete missing components\n", percentage))
				output.WriteString("  Existing components will be verified, missing ones will be created\n")
				result.Status = debug.StatusWarning
				result.Message = fmt.Sprintf("Partial installation detected (%d%%)", percentage)
				result.Remediation = "Run 'eos create vault' to complete installation, or 'eos delete vault' for clean slate"
			}

			result.Output = output.String()
			logger.Info("Idempotency status check complete",
				zap.Int("total_components", componentCount),
				zap.Int("existing_components", existingCount),
				zap.Int("percentage", percentage))

			return result, nil
		},
	}
}

// OrphanedStateDiagnostic detects orphaned Vault state
// (Vault initialized in Consul but credentials file missing)
func OrphanedStateDiagnostic() *debug.Diagnostic {
	return &debug.Diagnostic{
		Name:        "Orphaned State Detection",
		Category:    "Critical Issues",
		Description: "Detect if Vault is initialized but credentials are lost",
		Collect: func(ctx context.Context) (*debug.Result, error) {
			logger := otelzap.Ctx(ctx)
			logger.Info("Checking for orphaned Vault state")

			result := &debug.Result{
				Metadata: make(map[string]interface{}),
			}

			var output strings.Builder

			// Check 1: Does Consul storage have Vault data?
			_, err := exec.LookPath("consul")
			consulStorageExists := false
			consulKeyCount := 0

			if err == nil {
				checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
				defer cancel()

				cmd := exec.CommandContext(checkCtx, "consul", "kv", "get", "-keys", "-recurse", "vault/")
				consulOutput, err := cmd.CombinedOutput()

				if err == nil {
					lines := strings.Split(strings.TrimSpace(string(consulOutput)), "\n")
					for _, line := range lines {
						if strings.TrimSpace(line) != "" {
							consulKeyCount++
						}
					}
					if consulKeyCount > 0 {
						consulStorageExists = true
					}
				}
			}

			// Check 2: Does credentials file exist?
			credentialsPath := "/var/lib/eos/secret/vault_init.json"
			_, credErr := os.Stat(credentialsPath)
			credentialsExist := credErr == nil

			// Check 3: Is Vault initialized? (requires Vault to be running)
			vaultInitialized := false
			vaultAddr := os.Getenv("VAULT_ADDR")
			if vaultAddr == "" {
				vaultAddr = "https://127.0.0.1:8200"
			}

			// Try to check init status (this requires VAULT_SKIP_VERIFY=1 for self-signed certs)
			initCheckCtx, initCancel := context.WithTimeout(ctx, 3*time.Second)
			defer initCancel()
			os.Setenv("VAULT_SKIP_VERIFY", "1")
			initCmd := exec.CommandContext(initCheckCtx, "vault", "status", "-format=json")
			initOutput, err := initCmd.CombinedOutput()
			if err == nil {
				// Parse for initialized field (simple string search)
				if strings.Contains(string(initOutput), `"initialized":true`) {
					vaultInitialized = true
				}
			}

			// Store findings
			result.Metadata["consul_storage_exists"] = consulStorageExists
			result.Metadata["consul_key_count"] = consulKeyCount
			result.Metadata["credentials_exist"] = credentialsExist
			result.Metadata["vault_initialized"] = vaultInitialized

			output.WriteString("=== Orphaned State Detection ===\n\n")
			output.WriteString(fmt.Sprintf("Consul Storage Exists: %v (%d keys)\n", consulStorageExists, consulKeyCount))
			output.WriteString(fmt.Sprintf("Credentials File: %v (%s)\n", credentialsExist, credentialsPath))
			output.WriteString(fmt.Sprintf("Vault Initialized: %v\n\n", vaultInitialized))

			// Detect orphaned state
			isOrphaned := (consulStorageExists || vaultInitialized) && !credentialsExist

			if isOrphaned {
				output.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
				output.WriteString("⚠  CRITICAL: ORPHANED VAULT STATE DETECTED!\n")
				output.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")
				output.WriteString("What this means:\n")
				output.WriteString("  • Vault is initialized in Consul storage backend\n")
				output.WriteString("  • Credentials file (vault_init.json) is missing\n")
				output.WriteString("  • You CANNOT unseal Vault (unseal keys lost)\n")
				output.WriteString("  • You CANNOT access any secrets\n")
				output.WriteString("  • Reinstalling Vault will FAIL (data already exists)\n\n")
				output.WriteString("How this happened:\n")
				output.WriteString("  1. Vault was initialized and vault_init.json was created\n")
				output.WriteString("  2. The credentials file was deleted (following security checklist)\n")
				output.WriteString("  3. 'eos delete vault' was run WITHOUT --purge flag\n")
				output.WriteString("  4. Consul storage data was NOT deleted\n\n")
				output.WriteString("How to fix:\n")
				output.WriteString("  Option 1: Complete teardown and fresh install\n")
				output.WriteString("    $ sudo eos delete vault --purge --yes\n")
				output.WriteString("    $ sudo eos create vault\n\n")
				output.WriteString("  Option 2: If you have the unseal keys and root token saved elsewhere\n")
				output.WriteString("    $ sudo eos enable vault\n")
				output.WriteString("    (You will be prompted to enter credentials manually)\n\n")
				output.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

				result.Status = debug.StatusError
				result.Message = "Orphaned Vault state detected - initialized but credentials lost"
				result.Remediation = "Run: sudo eos delete vault --purge --yes && sudo eos create vault"
			} else if consulStorageExists && credentialsExist {
				output.WriteString("✓ Vault state is healthy\n")
				output.WriteString("  • Storage backend has data\n")
				output.WriteString("  • Credentials file exists\n")
				result.Status = debug.StatusOK
				result.Message = "Vault state is healthy"
			} else if !consulStorageExists && !vaultInitialized {
				output.WriteString("✓ No Vault data detected (clean state)\n")
				result.Status = debug.StatusOK
				result.Message = "No Vault installation detected"
			} else {
				output.WriteString("ℹ Vault state is ambiguous\n")
				result.Status = debug.StatusWarning
				result.Message = "Vault state could not be fully determined"
			}

			result.Output = output.String()
			logger.Info("Orphaned state check complete",
				zap.Bool("is_orphaned", isOrphaned),
				zap.Bool("consul_storage_exists", consulStorageExists),
				zap.Bool("credentials_exist", credentialsExist))

			return result, nil
		},
	}
}

// VaultAgentTokenPermissionsDiagnostic provides comprehensive token permissions analysis
// This diagnostic helps troubleshoot "permission denied" errors by showing:
// - Token policies
// - Token TTL and renewal status
// - Token capabilities on specific paths
// - Policy content verification
// - AppRole configuration
func VaultAgentTokenPermissionsDiagnostic() *debug.Diagnostic {
	return &debug.Diagnostic{
		Name:        "Vault Agent Token Permissions",
		Category:    "Vault Agent",
		Description: "Comprehensive token permissions and policy analysis",
		Condition: func(ctx context.Context) bool {
			// Only run if token file exists
			_, err := os.Stat(shared.AgentToken)
			return err == nil
		},
		Collect: func(ctx context.Context) (*debug.Result, error) {
			logger := otelzap.Ctx(ctx)
			logger.Info("Analyzing Vault Agent token permissions")

			result := &debug.Result{
				Metadata: make(map[string]interface{}),
			}

			var output strings.Builder
			output.WriteString("═══════════════════════════════════════════════════════════════\n")
			output.WriteString(" Vault Token Permissions Analysis\n")
			output.WriteString("═══════════════════════════════════════════════════════════════\n\n")

			// Get hostname for Vault address
			hostname, _ := os.Hostname()
			vaultAddr := fmt.Sprintf("https://%s:8200", hostname)

			// Read token
			tokenContent, err := os.ReadFile(shared.AgentToken)
			if err != nil {
				result.Status = debug.StatusError
				result.Message = "Cannot read token file"
				result.Remediation = fmt.Sprintf("Check file permissions: ls -la %s", shared.AgentToken)
				output.WriteString(fmt.Sprintf("❌ ERROR: Cannot read token file: %v\n", err))
				result.Output = output.String()
				return result, nil
			}

			token := strings.TrimSpace(string(tokenContent))
			if len(token) == 0 {
				result.Status = debug.StatusError
				result.Message = "Token file is empty"
				result.Remediation = "Restart Vault Agent: sudo systemctl restart vault-agent-eos"
				output.WriteString("❌ ERROR: Token file is empty\n")
				result.Output = output.String()
				return result, nil
			}

			output.WriteString("1. Vault Agent Token File\n")
			output.WriteString("───────────────────────────────────────────────────────────────\n")
			output.WriteString(fmt.Sprintf("   Path: %s\n", shared.AgentToken))
			output.WriteString(fmt.Sprintf("   Token (first 8 chars): %s...\n", token[:min(8, len(token))]))
			output.WriteString("\n")

			// Set environment variables for vault CLI
			os.Setenv("VAULT_ADDR", vaultAddr)
			os.Setenv("VAULT_SKIP_VERIFY", "1")
			os.Setenv("VAULT_TOKEN", token)

			// 2. Token Lookup
			output.WriteString("2. Token Lookup (full details)\n")
			output.WriteString("───────────────────────────────────────────────────────────────\n")

			cmd := exec.Command("vault", "token", "lookup", "-format=json")
			lookupOutput, err := cmd.CombinedOutput()
			if err != nil {
				output.WriteString(fmt.Sprintf("❌ Failed to lookup token: %v\n", err))
				output.WriteString(fmt.Sprintf("   Output: %s\n", string(lookupOutput)))
				result.Status = debug.StatusError
				result.Message = "Token lookup failed"
				result.Remediation = "Token may be expired or invalid. Restart Vault Agent."
			} else {
				output.WriteString(fmt.Sprintf("   %s\n", string(lookupOutput)))
				result.Metadata["token_lookup"] = string(lookupOutput)
			}
			output.WriteString("\n")

			// 3. Token Capabilities on services/* path
			output.WriteString("3. Token Capabilities on services/* Path\n")
			output.WriteString("───────────────────────────────────────────────────────────────\n")

			testPaths := []string{
				"secret/data/services/production/bionicgpt/azure_openai_api_key",
				"secret/data/services/*",
				"secret/metadata/services/*",
			}

			hasCreateOrUpdate := false
			for _, testPath := range testPaths {
				output.WriteString(fmt.Sprintf("   Testing path: %s\n", testPath))

				cmd = exec.Command("vault", "token", "capabilities", testPath)
				capsOutput, err := cmd.CombinedOutput()
				if err != nil {
					output.WriteString(fmt.Sprintf("   ❌ Failed to check capabilities: %v\n", err))
				} else {
					caps := strings.TrimSpace(string(capsOutput))
					output.WriteString(fmt.Sprintf("   Capabilities: %s\n", caps))

					if strings.Contains(caps, "create") || strings.Contains(caps, "update") {
						output.WriteString("   ✓ Token has write permissions\n")
						hasCreateOrUpdate = true
					} else if strings.Contains(caps, "deny") {
						output.WriteString("   ❌ Token is DENIED access\n")
					}
				}
				output.WriteString("\n")
			}

			if !hasCreateOrUpdate {
				result.Status = debug.StatusError
				result.Message = "Token does NOT have create/update on services/* path"
				result.Remediation = "Update policy: sudo eos update vault --update-policies && sudo systemctl restart vault-agent-eos"
			}

			// 4. Check eos-default-policy content
			output.WriteString("4. eos-default-policy Content\n")
			output.WriteString("───────────────────────────────────────────────────────────────\n")

			cmd = exec.Command("vault", "policy", "read", "eos-default-policy")
			policyOutput, err := cmd.CombinedOutput()
			if err != nil {
				output.WriteString(fmt.Sprintf("❌ Failed to read policy: %v\n", err))
			} else {
				policyContent := string(policyOutput)

				// Check if services/* path is in policy
				if strings.Contains(policyContent, "secret/data/services") {
					output.WriteString("✓ Policy includes services/* path\n\n")

					// Extract and show the services section
					lines := strings.Split(policyContent, "\n")
					inServicesSection := false
					for _, line := range lines {
						if strings.Contains(line, "secret/data/services") || strings.Contains(line, "secret/metadata/services") {
							inServicesSection = true
						}
						if inServicesSection {
							output.WriteString(fmt.Sprintf("   %s\n", line))
							if strings.Contains(line, "}") && !strings.Contains(line, "capabilities") {
								inServicesSection = false
								output.WriteString("\n")
							}
						}
					}
				} else {
					output.WriteString("❌ ERROR: services/* path NOT FOUND in eos-default-policy\n\n")
					output.WriteString("   Expected to find something like:\n")
					output.WriteString("   path \"secret/data/services/*\" {\n")
					output.WriteString("     capabilities = [\"create\", \"read\", \"update\", \"delete\", \"list\"]\n")
					output.WriteString("   }\n\n")

					result.Status = debug.StatusError
					result.Message = "Policy missing services/* path"
					result.Remediation = "Update policy: sudo eos update vault --update-policies"
				}
			}

			// 5. AppRole Configuration
			output.WriteString("5. AppRole Configuration\n")
			output.WriteString("───────────────────────────────────────────────────────────────\n")

			cmd = exec.Command("vault", "read", "auth/approle/role/eos-approle", "-format=json")
			appRoleOutput, err := cmd.CombinedOutput()
			if err != nil {
				output.WriteString(fmt.Sprintf("❌ Failed to read AppRole: %v\n", err))
			} else {
				output.WriteString(fmt.Sprintf("   %s\n", string(appRoleOutput)))
				result.Metadata["approle_config"] = string(appRoleOutput)
			}
			output.WriteString("\n")

			// 6. Vault Agent Service Status
			output.WriteString("6. Vault Agent Service Status\n")
			output.WriteString("───────────────────────────────────────────────────────────────\n")

			cmd = exec.Command("systemctl", "status", "vault-agent-eos", "--no-pager")
			statusOutput, err := cmd.CombinedOutput()
			if err == nil {
				// Just show first 20 lines
				lines := strings.Split(string(statusOutput), "\n")
				for i := 0; i < min(20, len(lines)); i++ {
					output.WriteString(fmt.Sprintf("   %s\n", lines[i]))
				}
			} else {
				output.WriteString(fmt.Sprintf("   %s\n", string(statusOutput)))
			}
			output.WriteString("\n")

			// Final summary
			output.WriteString("═══════════════════════════════════════════════════════════════\n")
			output.WriteString(" Diagnosis Complete\n")
			output.WriteString("═══════════════════════════════════════════════════════════════\n\n")

			if result.Status == "" {
				result.Status = debug.StatusOK
				result.Message = "Token has valid permissions"
			}

			if result.Status == debug.StatusError {
				output.WriteString("Next steps:\n")
				output.WriteString("  1. Check section 4 - does eos-default-policy have services/* path?\n")
				output.WriteString("  2. Check section 5 - does AppRole have eos-default-policy attached?\n")
				output.WriteString("  3. If policy is correct, restart Vault Agent to get new token:\n")
				output.WriteString("     sudo systemctl restart vault-agent-eos\n")
				output.WriteString("  4. Run this command again to verify: sudo eos debug vault\n\n")
			}

			result.Output = output.String()
			logger.Info("Token permissions analysis complete", zap.String("status", string(result.Status)))

			return result, nil
		},
	}
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
