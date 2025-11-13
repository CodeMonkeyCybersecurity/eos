// pkg/debug/vault/diag_agent.go
// Vault Agent diagnostic checks
//
// This module contains diagnostics for the Vault Agent service (vault-agent-eos):
// - VaultAgentServiceDiagnostic: Service status check
// - VaultAgentConfigDiagnostic: Configuration file validation
// - VaultAgentCredentialsDiagnostic: AppRole credentials check
// - VaultAgentTokenDiagnostic: Token file validation
// - VaultAgentLogsDiagnostic: Recent service logs
// - VaultAgentTokenPermissionsDiagnostic: Comprehensive token permissions analysis

package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/debug"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

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
				result.Remediation = "Install Vault Agent during Vault setup: sudo eos create vault (or sudo eos update vault --enable-agent if Vault is already installed)"
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
				result.Remediation = "Configure Vault Agent during Vault setup: sudo eos create vault (or sudo eos update vault --enable-agent if Vault is already installed)"
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
				result.Remediation = "Enable AppRole auth during Vault setup: sudo eos create vault (or sudo eos update vault --enable-approle if Vault is already installed)"
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

			// Create Vault API client (replaces vault CLI)
			vaultClient, err := createVaultClientFromToken(ctx, vaultAddr, token)
			if err != nil {
				result.Status = debug.StatusError
				result.Message = "Failed to create Vault client"
				result.Remediation = "Check Vault connectivity and token validity"
				output.WriteString(fmt.Sprintf("❌ ERROR: Cannot create Vault client: %v\n", err))
				result.Output = output.String()
				return result, nil
			}

			// 2. Token Lookup (using SDK)
			output.WriteString("2. Token Lookup (full details)\n")
			output.WriteString("───────────────────────────────────────────────────────────────\n")

			tokenLookup, err := vaultClient.Auth().Token().LookupSelf()
			if err != nil {
				output.WriteString(fmt.Sprintf("❌ Failed to lookup token: %v\n", err))
				result.Status = debug.StatusError
				result.Message = "Token lookup failed"
				result.Remediation = "Token may be expired or invalid. Restart Vault Agent."
			} else {
				// Pretty-print the JSON response
				lookupJSON, _ := json.MarshalIndent(tokenLookup, "   ", "  ")
				output.WriteString(fmt.Sprintf("   %s\n", string(lookupJSON)))
				result.Metadata["token_lookup"] = string(lookupJSON)
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

				// Use SDK to check capabilities
				caps, err := vaultClient.Sys().CapabilitiesSelf(testPath)
				if err != nil {
					output.WriteString(fmt.Sprintf("   ❌ Failed to check capabilities: %v\n", err))
				} else {
					capsStr := strings.Join(caps, ", ")
					output.WriteString(fmt.Sprintf("   Capabilities: %s\n", capsStr))

					for _, cap := range caps {
						if cap == "create" || cap == "update" {
							output.WriteString("   ✓ Token has write permissions\n")
							hasCreateOrUpdate = true
							break
						} else if cap == "deny" {
							output.WriteString("   ❌ Token is DENIED access\n")
							break
						}
					}
				}
				output.WriteString("\n")
			}

			if !hasCreateOrUpdate {
				result.Status = debug.StatusError
				result.Message = "Token does NOT have create/update on services/* path"
				result.Remediation = "Update policy: sudo eos update vault --policies && sudo systemctl restart vault-agent-eos"
			}

			// 4. Check eos-default-policy content (using SDK)
			output.WriteString("4. eos-default-policy Content\n")
			output.WriteString("───────────────────────────────────────────────────────────────\n")

			policyContent, err := vaultClient.Sys().GetPolicy("eos-default-policy")
			if err != nil {
				output.WriteString(fmt.Sprintf("❌ Failed to read policy: %v\n", err))
			} else {
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
					result.Remediation = "Update policy: sudo eos update vault --policies"
				}
			}

			// 5. AppRole Configuration
			output.WriteString("5. AppRole Configuration\n")
			output.WriteString("───────────────────────────────────────────────────────────────\n")

			// Use SDK to read AppRole configuration
			appRoleResp, err := vaultClient.Logical().Read("auth/approle/role/eos-approle")
			if err != nil {
				output.WriteString(fmt.Sprintf("❌ Failed to read AppRole: %v\n", err))
			} else if appRoleResp != nil {
				appRoleJSON, _ := json.MarshalIndent(appRoleResp.Data, "   ", "  ")
				output.WriteString(fmt.Sprintf("   %s\n", string(appRoleJSON)))
				result.Metadata["approle_config"] = string(appRoleJSON)
			} else {
				output.WriteString("❌ AppRole not found\n")
			}
			output.WriteString("\n")

			// 6. Vault Agent Service Status
			output.WriteString("6. Vault Agent Service Status\n")
			output.WriteString("───────────────────────────────────────────────────────────────\n")

			statusCmd := exec.Command("systemctl", "status", "vault-agent-eos", "--no-pager")
			statusOutput, err := statusCmd.CombinedOutput()
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

// createVaultClientFromToken creates a Vault API client with the given token
// This replaces shell-out to vault CLI commands
func createVaultClientFromToken(ctx context.Context, vaultAddr, token string) (*vaultapi.Client, error) {
	logger := otelzap.Ctx(ctx)

	// Create Vault API client config
	config := vaultapi.DefaultConfig()
	config.Address = vaultAddr

	// Handle self-signed certificates
	tlsConfig := &vaultapi.TLSConfig{
		Insecure: true,
	}
	if err := config.ConfigureTLS(tlsConfig); err != nil {
		logger.Debug("Failed to configure TLS", zap.Error(err))
		return nil, fmt.Errorf("failed to configure TLS: %w", err)
	}

	// Create client
	client, err := vaultapi.NewClient(config)
	if err != nil {
		logger.Debug("Failed to create Vault client", zap.Error(err))
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	// Set token
	client.SetToken(token)

	return client, nil
}
