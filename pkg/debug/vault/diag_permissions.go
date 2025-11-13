// pkg/debug/vault/diag_permissions.go
// Permissions and ownership diagnostic checks

package vault

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/debug"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

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
