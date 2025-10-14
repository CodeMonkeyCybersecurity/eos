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
)

const (
	DefaultBinaryPath      = "/usr/local/bin/vault"
	DefaultConfigPath      = "/etc/vault.d/vault.hcl"
	DefaultDataPath        = "/opt/vault/data"
	DefaultLogPath         = "/var/log/vault"
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
		PermissionsDiagnostic(),      // NEW: Comprehensive permissions check
		ServiceDiagnostic(),
		ServiceConfigDiagnostic(),    // NEW: Show User=/Group= from systemd
		ServiceLogsDiagnostic(),
		ProcessDiagnostic(),
		PortDiagnostic(),
		HealthCheckDiagnostic(),
		EnvironmentDiagnostic(),
		CapabilitiesDiagnostic(),
		DeletionTransactionLogsDiagnostic(),
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
			// Only run if binary and config exist
			_, binErr := os.Stat(DefaultBinaryPath)
			_, cfgErr := os.Stat(DefaultConfigPath)
			return binErr == nil && cfgErr == nil
		},
		Collect: func(ctx context.Context) (*debug.Result, error) {
			result := &debug.Result{
				Metadata: make(map[string]interface{}),
			}

			cmd := exec.CommandContext(ctx, DefaultBinaryPath, "validate", DefaultConfigPath)
			output, err := cmd.CombinedOutput()

			result.Output = string(output)
			result.Metadata["config_path"] = DefaultConfigPath

			if err != nil {
				result.Status = debug.StatusError
				result.Message = "Configuration validation failed"
				result.Remediation = fmt.Sprintf("Fix configuration errors in %s", DefaultConfigPath)
			} else {
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
			result := &debug.Result{
				Metadata: make(map[string]interface{}),
			}

			var output strings.Builder
			output.WriteString("=== Vault Permission Diagnostics ===\n\n")

			// 1. Check vault user exists with detailed ID output
			output.WriteString("=== Vault User ===\n")
			idCmd := exec.CommandContext(ctx, "id", "vault")
			idOutput, idErr := idCmd.CombinedOutput()
			if idErr != nil {
				output.WriteString("ERROR: vault user doesn't exist!\n")
				output.WriteString(fmt.Sprintf("Command output: %s\n", string(idOutput)))
				result.Status = debug.StatusError
				result.Message = "Vault user does not exist"
				result.Remediation = "Create vault user: sudo useradd -r -s /bin/false vault"
			} else {
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

			// 6. CRITICAL: Test vault user access to data directory
			// This is the smoking gun for the "permission denied" bug
			output.WriteString("=== Vault User Access Test ===\n")
			if idErr == nil && dataErr == nil {
				// Test if vault user can read the data directory
				testReadCmd := exec.CommandContext(ctx, "sudo", "-u", "vault", "test", "-r", "/opt/vault/data")
				canRead := testReadCmd.Run() == nil

				testWriteCmd := exec.CommandContext(ctx, "sudo", "-u", "vault", "test", "-w", "/opt/vault/data")
				canWrite := testWriteCmd.Run() == nil

				testTraverseCmd := exec.CommandContext(ctx, "sudo", "-u", "vault", "test", "-x", "/opt/vault/data")
				canTraverse := testTraverseCmd.Run() == nil

				if canRead && canWrite && canTraverse {
					output.WriteString("✓ vault user CAN read /opt/vault/data\n")
					output.WriteString("✓ vault user CAN write to /opt/vault/data\n")
					output.WriteString("✓ vault user CAN traverse /opt/vault/data\n\n")
					result.Metadata["vault_user_can_access_data"] = true
				} else {
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
				output.WriteString("=== Parent Directory Access Test ===\n")
				testParentCmd := exec.CommandContext(ctx, "sudo", "-u", "vault", "test", "-x", "/opt/vault")
				canAccessParent := testParentCmd.Run() == nil

				// Get detailed info about /opt/vault
				statCmd := exec.CommandContext(ctx, "stat", "-c", "Owner: %U:%G, Perms: %a", "/opt/vault")
				statOutput, statErr := statCmd.CombinedOutput()

				if canAccessParent {
					output.WriteString("✓ vault user CAN traverse /opt/vault (parent directory)\n")
					if statErr == nil {
						output.WriteString(fmt.Sprintf("  Directory info: %s\n", strings.TrimSpace(string(statOutput))))
					}
					output.WriteString("\n")
					result.Metadata["vault_user_can_access_parent"] = true
				} else {
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
			result := &debug.Result{
				Metadata: make(map[string]interface{}),
			}

			cmd := exec.CommandContext(ctx, "journalctl", "-u", "vault.service", "-n", "100", "--no-pager")
			output, err := cmd.CombinedOutput()

			outputStr := string(output)

			// Count permission denied errors (the bug we're looking for!)
			permDeniedCount := strings.Count(strings.ToLower(outputStr), "permission denied")

			var enhancedOutput strings.Builder
			enhancedOutput.WriteString("=== Vault Service Logs (last 100 lines) ===\n\n")

			// If permission errors found, highlight them at the top
			if permDeniedCount > 0 {
				enhancedOutput.WriteString(fmt.Sprintf("⚠️  CRITICAL: Found %d 'permission denied' errors!\n", permDeniedCount))
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
				result.Status = debug.StatusOK
				result.Message = "Both API and cluster ports are listening"
			} else if apiListening {
				result.Status = debug.StatusOK
				result.Message = "API port listening (cluster port not needed for single-node)"
			} else {
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
	return debug.NetworkCheck("HTTP Health Check", "http://127.0.0.1:8200/v1/sys/health", 5*time.Second)
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
						result.Remediation = "Run 'sudo eos delete vault --force' to retry deletion"
					} else if strings.Contains(contentStr, "FAILED") {
						result.Status = debug.StatusError
						result.Message = "Deletion encountered failures"
						result.Remediation = "Review log for errors, then retry with --force"
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
					"/usr/local/bin/vault":           "Binary",
					"/etc/vault.d":                   "Config directory",
					"/opt/vault":                     "Data directory",
					"/var/log/vault":                 "Log directory",
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
						result.Remediation = "Run 'sudo eos delete vault --force' to complete removal"
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
