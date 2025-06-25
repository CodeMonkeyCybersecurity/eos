// cmd/pandora/unseal/unseal.go
package unseal

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/hashicorp/vault/api"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	unsealKeyFile  string
	unsealKeyIndex int
	autoUnseal     bool
	waitForVault   bool
	maxWaitTime    time.Duration
)

// UnsealCmd represents the unseal command
var UnsealCmd = &cobra.Command{
	Use:   "unseal",
	Short: "Unseal a sealed Vault instance",
	Long: `Unseal a sealed Vault instance using stored unseal keys.

This command will attempt to unseal Vault using keys from the vault_init.json file
or a specified key file. It can handle both single-key and multi-key unseal scenarios.

Examples:
  # Auto-unseal using stored keys
  eos pandora unseal --auto

  # Use specific key file
  eos pandora unseal --key-file /path/to/keys.json

  # Wait for Vault to be available before unsealing
  eos pandora unseal --wait --auto

  # Use specific key index
  eos pandora unseal --key-index 0`,
	RunE: eos.Wrap(runUnseal),
}

func init() {
	UnsealCmd.Flags().StringVarP(&unsealKeyFile, "key-file", "k", "", "Path to file containing unseal key(s)")
	UnsealCmd.Flags().IntVarP(&unsealKeyIndex, "key-index", "i", -1, "Index of specific unseal key to use (default: use all)")
	UnsealCmd.Flags().BoolVarP(&autoUnseal, "auto", "a", false, "Automatically unseal using all available keys")
	UnsealCmd.Flags().BoolVarP(&waitForVault, "wait", "w", false, "Wait for Vault to be available before unsealing")
	UnsealCmd.Flags().DurationVar(&maxWaitTime, "wait-timeout", 60*time.Second, "Maximum time to wait for Vault")
}

func runUnseal(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Starting Vault unseal operation",
		zap.String("user", os.Getenv("USER")),
		zap.String("command_line", "eos pandora unseal"),
		zap.Bool("auto", autoUnseal),
		zap.Bool("wait", waitForVault))

	// Get Vault client
	client, err := vault.NewClient(rc)
	if err != nil {
		log.Error(" Failed to create Vault client", zap.Error(err))
		return logger.LogErrAndWrap(rc, "Failed to create Vault client: %w", err)
	}

	// Wait for Vault if requested
	if waitForVault {
		log.Info(" Waiting for Vault to be available",
			zap.Duration("timeout", maxWaitTime))
		if err := waitForVaultAvailable(rc, client, maxWaitTime); err != nil {
			log.Error(" Vault not available", zap.Error(err))
			return logger.LogErrAndWrap(rc, "Vault not available: %w", err)
		}
	}

	// Check seal status
	status, err := client.Sys().SealStatus()
	if err != nil {
		log.Error(" Failed to check seal status", zap.Error(err))
		return logger.LogErrAndWrap(rc, "Failed to check seal status: %w", err)
	}

	if !status.Sealed {
		log.Info(" Vault is already unsealed")
		return nil
	}

	log.Info(" Vault is sealed",
		zap.Int("threshold", status.T),
		zap.Int("shares", status.N),
		zap.Int("progress", status.Progress))

	// Get unseal keys
	keys, err := getUnsealKeys(rc)
	if err != nil {
		log.Error(" Failed to get unseal keys", zap.Error(err))
		return logger.LogErrAndWrap(rc, "Failed to get unseal keys: %w", err)
	}

	log.Info(" Loaded unseal keys",
		zap.Int("keys_available", len(keys)))

	// Perform unseal
	if autoUnseal {
		return autoUnsealVault(rc, client, keys, status.T)
	} else if unsealKeyIndex >= 0 {
		return unsealWithSpecificKey(rc, client, keys, unsealKeyIndex)
	} else {
		return interactiveUnseal(rc, client, keys, status.T)
	}
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

func getUnsealKeys(rc *eos_io.RuntimeContext) ([]string, error) {
	log := otelzap.Ctx(rc.Ctx)

	// If specific key file is provided
	if unsealKeyFile != "" {
		log.Info(" Reading keys from specified file",
			zap.String("file_path", unsealKeyFile))
		return readKeysFromFile(rc, unsealKeyFile)
	}

	// Try to load from vault_init.json
	initFile := "/var/lib/eos/secrets/vault_init.json"

	// Check if file exists
	if _, err := os.Stat(initFile); err != nil {
		log.Warn(" vault_init.json not found, trying fallback location",
			zap.String("primary_path", initFile),
			zap.Error(err))

		// Try fallback location
		initFile = "/var/lib/eos/secret/vault_init.json"
		if _, err := os.Stat(initFile); err != nil {
			log.Error(" No vault_init.json found in any location",
				zap.String("fallback_path", initFile),
				zap.Error(err))
			return nil, fmt.Errorf("vault_init.json not found: %w", err)
		}
	}

	log.Info(" Reading vault initialization data",
		zap.String("file_path", initFile))

	// Load using existing vault function
	initRes, err := vault.ReadVaultInitResult()
	if err != nil {
		log.Error(" Failed to load vault_init.json",
			zap.String("file_path", initFile),
			zap.Error(err))
		return nil, fmt.Errorf("failed to load vault_init.json: %w", err)
	}

	log.Info(" Loaded unseal keys from vault_init.json",
		zap.Int("keys_available", len(initRes.KeysB64)),
		zap.Int("threshold", 3))

	return initRes.KeysB64, nil
}

func readKeysFromFile(rc *eos_io.RuntimeContext, filename string) ([]string, error) {
	log := otelzap.Ctx(rc.Ctx)

	log.Info(" Reading key file",
		zap.String("file_path", filename))

	data, err := os.ReadFile(filename)
	if err != nil {
		log.Error(" Failed to read key file",
			zap.String("file_path", filename),
			zap.Error(err))
		return nil, err
	}

	// Try to parse as JSON array first
	var keys []string
	if err := json.Unmarshal(data, &keys); err == nil {
		log.Info(" Parsed keys as JSON array",
			zap.Int("key_count", len(keys)))
		return keys, nil
	}

	// Otherwise treat as single key
	key := string(data)
	log.Info(" Treating file content as single key",
		zap.Int("key_length", len(key)))
	return []string{key}, nil
}

func autoUnsealVault(rc *eos_io.RuntimeContext, client *api.Client, keys []string, threshold int) error {
	log := otelzap.Ctx(rc.Ctx)

	log.Info(" Starting automatic unseal process",
		zap.Int("keys_available", len(keys)),
		zap.Int("threshold", threshold))

	startTime := time.Now()
	keysUsed := 0

	for i, key := range keys {
		if keysUsed >= threshold {
			break
		}

		log.Info(" Applying unseal key",
			zap.Int("key_index", i+1),
			zap.Int("progress", keysUsed+1),
			zap.Int("threshold", threshold))

		resp, err := client.Sys().Unseal(key)
		if err != nil {
			log.Error(" Failed to apply unseal key",
				zap.Int("key_index", i+1),
				zap.Error(err),
				zap.String("troubleshooting", "Check if key is valid and Vault is accessible"))
			continue
		}

		keysUsed++

		if !resp.Sealed {
			log.Info(" Vault successfully unsealed",
				zap.Int("keys_used", keysUsed),
				zap.Duration("duration", time.Since(startTime)))
			return nil
		}

		log.Info(" Unseal progress",
			zap.Int("progress", resp.Progress),
			zap.Int("threshold", resp.T),
			zap.Bool("sealed", resp.Sealed))
	}

	log.Error(" Failed to unseal Vault",
		zap.Int("keys_used", keysUsed),
		zap.Int("threshold", threshold),
		zap.String("troubleshooting", "Ensure you have enough valid unseal keys"))

	return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("failed to unseal: used %d keys but threshold is %d", keysUsed, threshold))
}

func unsealWithSpecificKey(rc *eos_io.RuntimeContext, client *api.Client, keys []string, index int) error {
	log := otelzap.Ctx(rc.Ctx)

	if index >= len(keys) {
		log.Error(" Key index out of range",
			zap.Int("requested_index", index),
			zap.Int("available_keys", len(keys)))
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("key index %d out of range (available: %d)", index, len(keys)))
	}

	log.Info(" Using specific unseal key",
		zap.Int("key_index", index))

	startTime := time.Now()
	resp, err := client.Sys().Unseal(keys[index])
	if err != nil {
		log.Error(" Unseal failed",
			zap.Int("key_index", index),
			zap.Error(err))
		return logger.LogErrAndWrap(rc, "unseal failed", err)
	}

	if resp.Sealed {
		log.Info(" Unseal in progress",
			zap.Int("progress", resp.Progress),
			zap.Int("threshold", resp.T),
			zap.Duration("duration", time.Since(startTime)))
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("vault still sealed (progress: %d/%d)", resp.Progress, resp.T))
	}

	log.Info(" Vault successfully unsealed",
		zap.Duration("duration", time.Since(startTime)))
	return nil
}

func interactiveUnseal(rc *eos_io.RuntimeContext, client *api.Client, keys []string, threshold int) error {
	log := otelzap.Ctx(rc.Ctx)

	log.Info(" Interactive unseal mode",
		zap.Int("keys_available", len(keys)),
		zap.Int("threshold", threshold))

	// Show available keys
	log.Info(" Available unseal keys:")
	for i := range keys {
		log.Info(" Key available", zap.Int("index", i))
	}

	log.Info(" Vault requires keys to unseal",
		zap.Int("threshold", threshold))

	// Get current seal status
	status, err := client.Sys().SealStatus()
	if err != nil {
		return logger.LogErrAndWrap(rc, "failed to get seal status", err)
	}

	keysNeeded := threshold - status.Progress
	log.Info(" Keys needed to complete unseal",
		zap.Int("keys_needed", keysNeeded),
		zap.Int("current_progress", status.Progress))

	// Prompt for key indices
	prompt := fmt.Sprintf("Enter %d key indices (0-%d) separated by spaces", keysNeeded, len(keys)-1)
	input := interaction.PromptInput(rc.Ctx, prompt, "")

	// Parse indices
	var indices []int
	if _, err := fmt.Sscanf(input, "%d %d %d", &indices); err != nil {
		// Try auto mode if parsing fails
		if input == "all" || input == "auto" {
			return autoUnsealVault(rc, client, keys, threshold)
		}
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("invalid input format"))
	}

	// Apply selected keys
	startTime := time.Now()
	for _, idx := range indices {
		if idx < 0 || idx >= len(keys) {
			log.Warn(" Skipping invalid key index", zap.Int("index", idx))
			continue
		}

		resp, err := client.Sys().Unseal(keys[idx])
		if err != nil {
			log.Error(" Failed to apply key",
				zap.Int("index", idx),
				zap.Error(err))
			continue
		}

		if !resp.Sealed {
			log.Info(" Vault successfully unsealed",
				zap.Duration("duration", time.Since(startTime)))
			return nil
		}

		log.Info(" Unseal progress",
			zap.Int("progress", resp.Progress),
			zap.Int("threshold", resp.T))
	}

	return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("vault remains sealed after applying selected keys"))
}

