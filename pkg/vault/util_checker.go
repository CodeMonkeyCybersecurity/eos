/* pkg/vault/check.go */

package vault

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
)

/**/
// a logic wrapper for:
// CheckVaultHealth
// isInstalled
// NewClient
// isVaultInitialized
// isVaultSealed
// testKVSecret
// CheckVaultSecrets
func Check(client *api.Client, log *zap.Logger, storedHashes []string, hashedRoot string) (*CheckReport, *api.Client) {
	report := &CheckReport{}

	// 0. Direct HTTP liveness check
	addr, err := CheckVaultHealth(log)
	if err != nil {
		log.Warn("🔌 Vault health check failed (raw HTTP)",
			zap.String("VAULT_ADDR", addr),
			zap.String("hint", "Is Vault listening at this address? Does it use http vs https? Is port correct?"),
			zap.Error(err),
		)
		report.Notes = append(report.Notes, fmt.Sprintf("Vault health check failed: %v", err))
		return report, nil // no point continuing if Vault is unreachable
	}
	log.Info("✅ Raw Vault health check passed")

	// ... the rest of your Check function

	// 1. Binary check
	report.Installed = isInstalled(log)
	if !report.Installed {
		report.Notes = append(report.Notes, "Vault binary not found in PATH")
		return report, nil
	}

	// 2. Attempt to recover nil client
	if client == nil {
		var err error
		client, err = NewClient(log)
		if err != nil {
			log.Warn("Vault client creation failed", zap.Error(err))
			report.Notes = append(report.Notes, "Could not initialize Vault client")
			return report, nil
		}
	}

	// 3. Init check
	report.Initialized, err = IsVaultInitialized(client, log)
	if err != nil {
		report.Notes = append(report.Notes, fmt.Sprintf("Vault health query failed: %v", err))
		return report, client
	}

	// 4. Seal check
	report.Sealed = IsVaultSealed(client, log)
	if report.Sealed {
		report.Notes = append(report.Notes, "Vault is sealed")
	} else {
		log.Info("✅ Vault is unsealed and accessible")
	}

	// 5. KV test
	if err := testKVSecret(client, log); err == nil {
		report.KVWorking = true
		log.Info("✅ KV secret test passed")
	} else {
		log.Warn("❌ KV test failed", zap.Error(err))
		report.Notes = append(report.Notes, fmt.Sprintf("KV test failed: %v", err))
	}
	if !report.KVWorking || report.Sealed {
		return report, nil
	}

	// 6. Secret verification (optional)
	if len(storedHashes) > 0 && hashedRoot != "" {
		log.Info("🔐 Performing unseal key + root token check")
		CheckVaultSecrets(log)
	}

	// ✅ Done
	return report, client
}

/**/
func isInstalled(log *zap.Logger) bool {
	_, err := exec.LookPath("vault")
	if err != nil {
		log.Warn("Vault binary not found in PATH", zap.Error(err))
		return false
	}
	log.Info("✅ Vault binary found in PATH")
	return true
}

/**/

/**/
// TODO: ensure functionality
// -> InitializeVault(client *api.Client) (VaultInitResponse, error)
func IsVaultInitialized(client *api.Client, log *zap.Logger) (bool, error) {
	if client == nil {
		return false, fmt.Errorf("vault client is nil")
	}
	status, err := client.Sys().Health()
	if err != nil {
		log.Warn("Failed to query Vault health", zap.Error(err))
		return false, err
	}
	log.Info("Vault health check complete", zap.Bool("initialized", status.Initialized), zap.Bool("sealed", status.Sealed))
	return status.Initialized, nil
}

/**/

// isVaultSealed checks if Vault is sealed and logs the result.
func IsVaultSealed(client *api.Client, log *zap.Logger) bool {
	health, err := client.Sys().Health()
	if err != nil {
		log.Warn("Unable to determine Vault sealed state", zap.Error(err))
		return false // fail-open assumption
	}
	log.Debug("Vault sealed check complete", zap.Bool("sealed", health.Sealed))
	return health.Sealed
}

// TestKVSecret writes and reads a test secret from the KV engine.
func testKVSecret(client *api.Client, log *zap.Logger) error {
	log.Info("📝 Writing test secret to Vault...")

	kv := client.KVv2("secret")
	testPath := "hello"
	testKey := "value"
	testValue := "world"

	if _, err := kv.Put(context.Background(), testPath, map[string]interface{}{testKey: testValue}); err != nil {
		log.Error("Failed to write test secret", zap.String("path", testPath), zap.Error(err))
		return fmt.Errorf("failed to write test secret: %w", err)
	}

	secret, err := kv.Get(context.Background(), testPath)
	if err != nil {
		log.Error("Failed to read test secret", zap.String("path", testPath), zap.Error(err))
		return fmt.Errorf("failed to read test secret: %w", err)
	}

	value := secret.Data[testKey]
	log.Info("✅ Test secret read successful", zap.String("path", testPath), zap.Any("value", value))
	return nil
}

// CheckVaultSecrets prompts the user for unseal keys + root token, validates them.
func CheckVaultSecrets(log *zap.Logger) {
	log.Info("🔐 Prompting user to verify unseal keys and root token...")

	// Ask the user to re-enter 3 unseal keys and the root token
	keys, root, err := PromptOrRecallUnsealKeys(log)
	if err != nil {
		log.Warn("Failed to recall or prompt for secrets", zap.Error(err))
		fmt.Println("❌ Vault secret check aborted.")
		return
	}

	// Prevent duplicated keys
	if !crypto.AllUnique(keys) {
		log.Warn("Duplicate unseal keys detected")
		fmt.Println("❌ Please ensure you enter 3 unique keys.")
		return
	}

	// Load previously stored reference values
	storedHashes, hashedRoot, err := rememberBootstrapHashes(log)
	if err != nil {
		log.Warn("Failed to load stored Vault bootstrap hashes", zap.Error(err))
		fmt.Println("❌ Unable to verify unseal keys — no trusted reference available.")
		return
	}

	// Hash and compare
	hashedInputs := crypto.HashStrings(keys)
	if !crypto.AllHashesPresent(hashedInputs, storedHashes) || crypto.HashString(root) != hashedRoot {
		log.Warn("Entered secrets did not match stored hashes")
		fmt.Println("❌ Secrets do not match known trusted values.")
		return
	}

	log.Info("✅ Vault secrets verified successfully")
	fmt.Println("✅ Unseal keys and root token verified.")
}

/**/
func CheckVaultHealth(log *zap.Logger) (string, error) {
	addr := os.Getenv("VAULT_ADDR")
	if addr == "" {
		return "", fmt.Errorf("VAULT_ADDR not set")
	}

	healthURL := strings.TrimRight(addr, "/") + "/v1/sys/health"
	client := http.Client{
		Timeout: 5 * time.Second,
	}
	resp, err := client.Get(healthURL)
	if err != nil {
		return addr, fmt.Errorf("vault not responding at %s: %w", addr, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 500 {
		body, _ := io.ReadAll(resp.Body)
		return addr, fmt.Errorf("vault unhealthy: %s", string(body))
	}
	log.Info("✅ Vault responded to health check", zap.String("VAULT_ADDR", addr))
	return addr, nil
}

/**/

/**/
func IsAlreadyInitialized(err error, log *zap.Logger) bool {
	return strings.Contains(err.Error(), "Vault is already initialized")
}

/**/
/**/
// VaultList returns keys under a path
func ListVault(path string, log *zap.Logger) ([]string, error) {
	client, err := GetPrivilegedVaultClient(log)
	if err != nil {
		return nil, err
	}
	list, err := client.Logical().List("secret/metadata/" + path)
	if err != nil || list == nil {
		return nil, err
	}
	raw := list.Data["keys"].([]interface{})
	keys := make([]string, len(raw))
	for i, k := range raw {
		keys[i] = fmt.Sprintf("%v", k)
	}
	return keys, nil
}

/**/
