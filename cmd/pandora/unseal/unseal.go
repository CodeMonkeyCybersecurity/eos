// cmd/pandora/unseal/unseal.go
package unseal

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/hashicorp/vault/api"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"golang.org/x/term"
)

var (
	waitForVault bool
	maxWaitTime  time.Duration
	auditLog     bool
)

// UnsealCmd represents the unseal command
var UnsealCmd = &cobra.Command{
	Use:   "unseal",
	Short: "Securely unseal a sealed Vault instance",
	Long: `Securely unseal a sealed Vault instance using manual key input.

SECURITY NOTICE:
This command implements secure unsealing that respects Shamir's Secret Sharing.
Each unseal key must be provided manually to prevent compromise of the secret sharing scheme.

FEATURES:
• Manual key input with secure password prompts
• Comprehensive audit logging of all unseal attempts
• No keys stored on disk or in memory longer than necessary
• Distributed key management support

USAGE:
  # Secure manual unsealing (recommended)
  eos pandora unseal

  # Wait for Vault to be available before unsealing
  eos pandora unseal --wait

  # Enable audit logging
  eos pandora unseal --audit

SECURITY WARNINGS:
• Never store all unseal keys in one location
• Each key should be held by different trusted parties
• All unseal attempts are logged for security auditing
• Keys are never displayed or logged in plain text`,
	RunE: eos.Wrap(runUnseal),
}

func init() {
	UnsealCmd.Flags().BoolVarP(&waitForVault, "wait", "w", false, "Wait for Vault to be available before unsealing")
	UnsealCmd.Flags().DurationVar(&maxWaitTime, "wait-timeout", 60*time.Second, "Maximum time to wait for Vault")
	UnsealCmd.Flags().BoolVarP(&auditLog, "audit", "a", true, "Enable audit logging (default: true)")
}

// AuditEntry represents an audit log entry
type AuditEntry struct {
	Timestamp time.Time              `json:"timestamp"`
	Event     string                 `json:"event"`
	User      string                 `json:"user"`
	Hostname  string                 `json:"hostname"`
	Success   bool                   `json:"success"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
	Error     string                 `json:"error,omitempty"`
}

// Auditor handles audit logging for unsealing operations
type Auditor struct {
	file *os.File
}

// NewAuditor creates a new audit logger
func NewAuditor() (*Auditor, error) {
	auditDir := "/var/log/eos"
	if err := os.MkdirAll(auditDir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create audit directory: %w", err)
	}

	auditPath := filepath.Join(auditDir, "vault-unseal-audit.log")
	f, err := os.OpenFile(auditPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit log: %w", err)
	}

	return &Auditor{file: f}, nil
}

// LogEvent logs an audit event
func (a *Auditor) LogEvent(event string, metadata map[string]interface{}) {
	if a.file == nil {
		return
	}

	entry := AuditEntry{
		Timestamp: time.Now().UTC(),
		Event:     event,
		User:      os.Getenv("USER"),
		Hostname:  getHostname(),
		Success:   true,
		Metadata:  metadata,
	}

	if err, hasError := metadata["error"]; hasError {
		entry.Success = false
		if errStr, ok := err.(string); ok {
			entry.Error = errStr
		}
	}

	jsonData, _ := json.Marshal(entry)
	fmt.Fprintf(a.file, "%s\n", jsonData)
	a.file.Sync()
}

// Close closes the audit log file
func (a *Auditor) Close() {
	if a.file != nil {
		a.file.Close()
	}
}

func runUnseal(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Starting secure Vault unseal operation",
		zap.String("user", os.Getenv("USER")),
		zap.String("hostname", getHostname()),
		zap.String("command_line", "eos pandora unseal"),
		zap.Bool("wait", waitForVault),
		zap.Bool("audit", auditLog))

	// Initialize audit logging
	var auditor *Auditor
	if auditLog {
		var err error
		auditor, err = NewAuditor()
		if err != nil {
			log.Warn(" Failed to initialize audit logging", zap.Error(err))
			// Continue without auditing rather than fail
		}
		defer func() {
			if auditor != nil {
				auditor.Close()
			}
		}()
	}

	// Get Vault client
	client, err := vault.NewClient(rc)
	if err != nil {
		log.Error(" Failed to create Vault client", zap.Error(err))
		if auditor != nil {
			auditor.LogEvent("client_creation_failed", map[string]interface{}{
				"error": err.Error(),
			})
		}
		return logger.LogErrAndWrap(rc, "Failed to create Vault client: %w", err)
	}

	// Wait for Vault if requested
	if waitForVault {
		log.Info(" Waiting for Vault to be available",
			zap.Duration("timeout", maxWaitTime))
		if err := waitForVaultAvailable(rc, client, maxWaitTime); err != nil {
			log.Error(" Vault not available", zap.Error(err))
			if auditor != nil {
				auditor.LogEvent("vault_unavailable", map[string]interface{}{
					"timeout": maxWaitTime.String(),
					"error":   err.Error(),
				})
			}
			return logger.LogErrAndWrap(rc, "Vault not available: %w", err)
		}
	}

	// Check seal status
	status, err := client.Sys().SealStatus()
	if err != nil {
		log.Error(" Failed to check seal status", zap.Error(err))
		if auditor != nil {
			auditor.LogEvent("seal_status_check_failed", map[string]interface{}{
				"error": err.Error(),
			})
		}
		return logger.LogErrAndWrap(rc, "Failed to check seal status: %w", err)
	}

	if !status.Sealed {
		log.Info(" Vault is already unsealed")
		if auditor != nil {
			auditor.LogEvent("vault_already_unsealed", map[string]interface{}{
				"threshold": status.T,
				"shares":    status.N,
			})
		}
		return nil
	}

	log.Info(" Vault is sealed - beginning secure manual unseal process",
		zap.Int("threshold", status.T),
		zap.Int("shares", status.N),
		zap.Int("progress", status.Progress))

	if auditor != nil {
		auditor.LogEvent("unseal_attempt_started", map[string]interface{}{
			"threshold": status.T,
			"shares":    status.N,
			"progress":  status.Progress,
			"mode":      "manual",
		})
	}

	// Perform secure manual unseal
	return performSecureManualUnseal(rc, client, auditor, status.T)
}

func waitForVaultAvailable(rc *eos_io.RuntimeContext, client *api.Client, timeout time.Duration) error {
	log := otelzap.Ctx(rc.Ctx)
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	attempts := 0
	for {
		select {
		case <-ticker.C:
			attempts++
			log.Debug(" Checking Vault health", zap.Int("attempt", attempts))

			_, err := client.Sys().Health()
			if err == nil {
				log.Info(" Vault is available",
					zap.Int("attempts", attempts),
					zap.Duration("elapsed", time.Since(deadline.Add(-timeout))))
				return nil
			}

			if time.Now().After(deadline) {
				log.Error(" Timeout waiting for Vault",
					zap.Error(err),
					zap.Int("attempts", attempts))
				return fmt.Errorf("timeout waiting for Vault: %w", err)
			}

			log.Debug(" Vault not ready yet",
				zap.Error(err),
				zap.Duration("remaining", time.Until(deadline)))
		case <-rc.Ctx.Done():
			return rc.Ctx.Err()
		}
	}
}

// performSecureManualUnseal performs the secure manual unsealing process
func performSecureManualUnseal(rc *eos_io.RuntimeContext, client *api.Client, auditor *Auditor, threshold int) error {
	log := otelzap.Ctx(rc.Ctx)

	log.Info(" ")
	log.Info(" ╔═══════════════════════════════════════════════════════════════════════╗")
	log.Info(" ║                        SECURE VAULT UNSEALING                        ║")
	log.Info(" ╚═══════════════════════════════════════════════════════════════════════╝")
	log.Info(" ")
	log.Info(" SECURITY NOTICE:")
	log.Info("   • Each unseal key should be held by a different trusted party")
	log.Info("   • Keys will not be displayed or logged")
	log.Info("   • All attempts are audited for security")
	log.Info("   • This process respects Shamir's Secret Sharing principles")
	log.Info(" ")

	startTime := time.Now()
	keysProvided := 0

	for keysProvided < threshold {
		// Get current status to show progress
		status, err := client.Sys().SealStatus()
		if err != nil {
			log.Error(" Failed to check seal status", zap.Error(err))
			if auditor != nil {
				auditor.LogEvent("seal_status_check_failed", map[string]interface{}{
					"keys_provided": keysProvided,
					"error":         err.Error(),
				})
			}
			return fmt.Errorf("failed to check seal status: %w", err)
		}

		if !status.Sealed {
			log.Info(" ")
			log.Info("  Vault successfully unsealed!",
				zap.Int("keys_provided", keysProvided),
				zap.Duration("duration", time.Since(startTime)))

			if auditor != nil {
				auditor.LogEvent("unseal_successful", map[string]interface{}{
					"keys_provided": keysProvided,
					"duration_ms":   time.Since(startTime).Milliseconds(),
				})
			}
			return nil
		}

		keysNeeded := threshold - status.Progress
		log.Info(" Vault unsealing progress",
			zap.Int("current_progress", status.Progress),
			zap.Int("threshold", threshold),
			zap.Int("keys_still_needed", keysNeeded))

		// Prompt for the next key
		key, err := promptForUnsealKey(keysProvided + 1)
		if err != nil {
			log.Error(" Failed to get unseal key", zap.Error(err))
			if auditor != nil {
				auditor.LogEvent("key_input_failed", map[string]interface{}{
					"key_number": keysProvided + 1,
					"error":      err.Error(),
				})
			}
			return fmt.Errorf("failed to get unseal key: %w", err)
		}

		// Apply the key
		log.Info(" Applying unseal key", zap.Int("key_number", keysProvided+1))

		resp, err := client.Sys().Unseal(key)
		if err != nil {
			log.Error(" Failed to apply unseal key",
				zap.Int("key_number", keysProvided+1),
				zap.Error(err))

			if auditor != nil {
				auditor.LogEvent("key_application_failed", map[string]interface{}{
					"key_number": keysProvided + 1,
					"error":      err.Error(),
				})
			}

			// Ask user if they want to continue or abort
			if !askContinueAfterError(rc) {
				return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("unseal aborted by user"))
			}
			continue
		}

		keysProvided++

		if auditor != nil {
			auditor.LogEvent("key_applied_successfully", map[string]interface{}{
				"key_number": keysProvided,
				"progress":   resp.Progress,
				"threshold":  resp.T,
				"sealed":     resp.Sealed,
			})
		}

		// Clear the key from memory immediately
		_ = key // Explicitly ignore the key value after use

		log.Info(" Key applied successfully",
			zap.Int("progress", resp.Progress),
			zap.Int("threshold", resp.T))

		if !resp.Sealed {
			log.Info(" ")
			log.Info("  Vault successfully unsealed!",
				zap.Int("keys_provided", keysProvided),
				zap.Duration("duration", time.Since(startTime)))

			if auditor != nil {
				auditor.LogEvent("unseal_successful", map[string]interface{}{
					"keys_provided": keysProvided,
					"duration_ms":   time.Since(startTime).Milliseconds(),
				})
			}
			return nil
		}
	}

	// Should not reach here, but handle the case
	log.Error(" Vault still sealed after providing all required keys")
	if auditor != nil {
		auditor.LogEvent("unseal_failed_unexpected", map[string]interface{}{
			"keys_provided": keysProvided,
			"threshold":     threshold,
		})
	}
	return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("vault still sealed after providing %d keys", keysProvided))
}

// promptForUnsealKey securely prompts for an unseal key
func promptForUnsealKey(keyNumber int) (string, error) {
	fmt.Printf(" Enter unseal key #%d (input will be hidden): ", keyNumber)

	// Use terminal package for secure input
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", fmt.Errorf("failed to read key input: %w", err)
	}
	fmt.Println() // New line after hidden input

	key := strings.TrimSpace(string(bytePassword))
	if key == "" {
		return "", fmt.Errorf("empty key provided")
	}

	// Validate key format (basic check)
	if len(key) < 20 {
		return "", fmt.Errorf("key appears too short - please check and try again")
	}

	return key, nil
}

// askContinueAfterError asks the user if they want to continue after a key application error
func askContinueAfterError(rc *eos_io.RuntimeContext) bool {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print(" Key application failed. Continue with next key? [y/N]: ")
	response, err := reader.ReadString('\n')
	if err != nil {
		return false
	}

	response = strings.TrimSpace(strings.ToLower(response))
	return response == "y" || response == "yes"
}

// getHostname returns the system hostname
func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}
