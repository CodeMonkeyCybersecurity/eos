// pkg/debug/vault/diag_state.go
// Vault installation state diagnostic checks
//
// This module contains diagnostics for Vault installation and deletion state:
// - DeletionTransactionLogsDiagnostic: Check vault deletion transaction logs
// - IdempotencyStatusDiagnostic: Check current installation state for idempotent operations
// - OrphanedStateDiagnostic: Detect orphaned Vault state (initialized but credentials lost)

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

				// Get version using Vault API client (reads version from binary metadata)
				// This is better than shelling out to 'vault version'
				if versionInfo, err := getVaultBinaryVersion(ctx, binaryPath); err == nil {
					output.WriteString(fmt.Sprintf("  └─ Version: %s\n", versionInfo))
					result.Metadata["binary_version"] = versionInfo
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
			switch existingCount {
			case 0:
				output.WriteString("✓ Clean system - 'eos create vault' will perform full installation\n")
				result.Status = debug.StatusOK
				result.Message = "Clean system ready for installation"
			case componentCount:
				output.WriteString("✓ Fully installed - 'eos create vault' will verify and update configuration\n")
				output.WriteString("  Eos will check existing components and update if needed (idempotent)\n")
				result.Status = debug.StatusOK
				result.Message = "Vault fully installed - operations are idempotent"
			default:
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

			// Use Vault API client to check initialization status
			initCheckCtx, initCancel := context.WithTimeout(ctx, 3*time.Second)
			defer initCancel()

			if initialized, err := checkVaultInitialized(initCheckCtx); err == nil {
				vaultInitialized = initialized
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
				output.WriteString("    $ sudo eos update vault --unseal\n")
				output.WriteString("    (Unseals Vault using stored unseal keys)\n\n")
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
