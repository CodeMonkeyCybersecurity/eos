// pkg/vault/util_checker.go

package vault

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
)

// Check performs a full sanity check on Vault health, binary installation,
// initialization status, seal status, and KV functionality.
// It returns a CheckReport summarizing the findings.
func Check(client *api.Client, storedHashes []string, hashedRoot string) (*shared.CheckReport, *api.Client) {
	report := &shared.CheckReport{}

	// 1️⃣ Environment sanity
	addr := os.Getenv(shared.VaultAddrEnv)
	if addr == "" {
		zap.L().Error("❌ VAULT_ADDR not set")
		report.Notes = append(report.Notes, "VAULT_ADDR environment variable not set")
		return report, nil
	}

	// 2️⃣ HTTP liveness probe
	healthy, err := CheckVaultHealth()
	if err != nil || !healthy {
		zap.L().Warn("🔌 Vault health check failed",
			zap.String(shared.VaultAddrEnv, addr),
			zap.Error(err))
		report.Notes = append(report.Notes, fmt.Sprintf("Vault health check failed: %v", err))
		return report, nil
	}
	zap.L().Info("✅ Vault HTTP health probe passed")

	// 3️⃣ Vault binary check
	if !isInstalled() {
		zap.L().Warn("Vault binary not found in PATH")
		report.Notes = append(report.Notes, "Vault binary not installed or not found in $PATH")
		return report, nil
	}
	report.Installed = true

	// 4️⃣ Recover Vault client if nil
	if client == nil {
		zap.L().Info("ℹ️ Vault client was nil, creating new client")
		newClient, err := NewClient()
		if err != nil {
			zap.L().Warn("Failed to create Vault client", zap.Error(err))
			report.Notes = append(report.Notes, "Could not initialize Vault client")
			return report, nil
		}
		client = newClient
	}

	// 5️⃣ Initialization check
	report.Initialized, err = IsVaultInitialized(client)
	if err != nil {
		zap.L().Warn("Vault initialization status check failed", zap.Error(err))
		report.Notes = append(report.Notes, fmt.Sprintf("Vault init check failed: %v", err))
		return report, client
	}

	// 6️⃣ Seal check
	report.Sealed = IsVaultSealed(client)
	if report.Sealed {
		zap.L().Warn("🔒 Vault is currently sealed")
		report.Notes = append(report.Notes, "Vault is sealed")
	} else {
		zap.L().Info("✅ Vault is unsealed and accessible")
	}

	// 7️⃣ KV test
	if err := testKVSecret(client); err != nil {
		zap.L().Warn("❌ KV secret test failed", zap.Error(err))
		report.Notes = append(report.Notes, fmt.Sprintf("KV test failed: %v", err))
	} else {
		report.KVWorking = true
		zap.L().Info("✅ KV secret test passed")
	}

	// 8️⃣ (Optional) Vault secrets verification
	if len(storedHashes) > 0 && hashedRoot != "" {
		zap.L().Info("🔐 Checking unseal keys and root token against stored hashes")
		if verifyVaultSecrets(storedHashes, hashedRoot) {
			zap.L().Info("✅ Vault secret verification succeeded")
		} else {
			zap.L().Warn("❌ Vault secret verification failed")
			report.Notes = append(report.Notes, "Vault secret mismatch or verification failed")
		}
	}

	// ✅ Final report
	return report, client
}

func verifyVaultSecrets(storedHashes []string, hashedRoot string) bool {
	keys, root, err := PromptOrRecallUnsealKeys()
	if err != nil {
		zap.L().Warn("Failed to prompt for unseal keys and root", zap.Error(err))
		return false
	}
	if !crypto.AllUnique(keys) {
		zap.L().Warn("Duplicate unseal keys detected")
		return false
	}
	hashedInputs := crypto.HashStrings(keys)
	if !crypto.AllHashesPresent(hashedInputs, storedHashes) {
		zap.L().Warn("Unseal keys mismatch")
		return false
	}
	if crypto.HashString(root) != hashedRoot {
		zap.L().Warn("Root token mismatch")
		return false
	}
	return true
}

func isInstalled() bool {
	_, err := exec.LookPath("vault")
	if err != nil {
		zap.L().Warn("Vault binary not found in PATH", zap.Error(err))
		return false
	}
	zap.L().Info("✅ Vault binary found in PATH")
	return true
}

// InitializeVault(client *api.Client) (VaultInitResponse, error)
func IsVaultInitialized(client *api.Client) (bool, error) {
	if client == nil {
		return false, fmt.Errorf("vault client is nil")
	}
	status, err := client.Sys().Health()
	if err != nil {
		zap.L().Warn("Failed to query Vault health", zap.Error(err))
		return false, err
	}
	zap.L().Info("Vault health check complete", zap.Bool("initialized", status.Initialized), zap.Bool("sealed", status.Sealed))
	return status.Initialized, nil
}

// isVaultSealed checks if Vault is sealed and logs the result.
func IsVaultSealed(client *api.Client) bool {
	health, err := client.Sys().Health()
	if err != nil {
		zap.L().Warn("Unable to determine Vault sealed state", zap.Error(err))
		return false // fail-open assumption
	}
	zap.L().Debug("Vault sealed check complete", zap.Bool("sealed", health.Sealed))
	return health.Sealed
}

// TestKVSecret writes and reads a test secret from the KV engine.
func testKVSecret(client *api.Client) error {
	zap.L().Info("📝 Writing test secret to Vault...")

	kv := client.KVv2("secret")

	if _, err := kv.Put(context.Background(), shared.TestKVPath, map[string]interface{}{shared.TestKVKey: shared.TestKVValue}); err != nil {
		zap.L().Error("Failed to write test secret", zap.String("path", shared.TestKVPath), zap.Error(err))
		return fmt.Errorf("failed to write test secret: %w", err)
	}

	secret, err := kv.Get(context.Background(), shared.TestKVPath)
	if err != nil {
		zap.L().Error("Failed to read test secret", zap.String("path", shared.TestKVPath), zap.Error(err))
		return fmt.Errorf("failed to read test secret: %w", err)
	}

	value := secret.Data[shared.TestKVKey]
	zap.L().Info("✅ Test secret read successful", zap.String("path", shared.TestKVPath), zap.Any("value", value))
	return nil
}

// CheckVaultSecrets prompts the user for unseal keys + root token, validates them.
func CheckVaultSecrets() {
	zap.L().Info("🔐 Prompting user to verify unseal keys and root token...")

	// Ask the user to re-enter 3 unseal keys and the root token
	keys, root, err := PromptOrRecallUnsealKeys()
	if err != nil {
		zap.L().Warn("Failed to recall or prompt for secrets", zap.Error(err))
		fmt.Println("❌ Vault secret check aborted.")
		return
	}

	// Prevent duplicated keys
	if !crypto.AllUnique(keys) {
		zap.L().Warn("Duplicate unseal keys detected")
		fmt.Println("❌ Please ensure you enter 3 unique keys.")
		return
	}

	// Load previously stored reference values
	storedHashes, hashedRoot, err := rememberBootstrapHashes()
	if err != nil {
		zap.L().Warn("Failed to load stored Vault bootstrap hashes", zap.Error(err))
		fmt.Println("❌ Unable to verify unseal keys — no trusted reference available.")
		return
	}

	// Hash and compare
	hashedInputs := crypto.HashStrings(keys)
	if !crypto.AllHashesPresent(hashedInputs, storedHashes) || crypto.HashString(root) != hashedRoot {
		zap.L().Warn("Entered secrets did not match stored hashes")
		fmt.Println("❌ Secrets do not match known trusted values.")
		return
	}

	zap.L().Info("✅ Vault secrets verified successfully")
	fmt.Println("✅ Unseal keys and root token verified.")
}

// IsAlreadyInitialized returns true if the error indicates Vault is already initialized.
func IsAlreadyInitialized(err error) bool {
	return strings.Contains(err.Error(), "Vault is already initialized")
}

// ListVault returns keys under a path in Vault's secret KV engine.
func ListVault(path string) ([]string, error) {
	client, err := GetPrivilegedVaultClient()
	if err != nil {
		return nil, err
	}
	list, err := client.Logical().List("secret/metadata/" + path)
	if err != nil || list == nil {
		return nil, err
	}
	rawKeys, ok := list.Data["keys"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected format for Vault list keys")
	}
	keys := make([]string, len(rawKeys))
	for i, k := range rawKeys {
		keys[i] = fmt.Sprintf("%v", k)
	}
	return keys, nil
}

func CheckVaultAgentService() error {
	zap.L().Info("Checking Vault Agent systemd service", zap.String("service", shared.VaultAgentService))

	cmd := exec.Command("sudo", "systemctl", "is-active", "--quiet", shared.VaultAgentService)
	if err := cmd.Run(); err != nil {
		zap.L().Error("Vault Agent service inactive", zap.Error(err))
		return fmt.Errorf("vault agent service is not running")
	}

	zap.L().Info("Vault Agent service is active")
	return nil
}

func CheckVaultTokenFile() error {
	zap.L().Info("Checking Vault Agent token file", zap.String("path", shared.VaultAgentTokenPath))

	if _, err := os.Stat(shared.VaultAgentTokenPath); os.IsNotExist(err) {
		zap.L().Error("Vault token file missing", zap.String("path", shared.VaultAgentTokenPath))
		return fmt.Errorf("vault token file not found at %s", shared.VaultAgentTokenPath)
	}

	zap.L().Info("Vault token file exists", zap.String("path", shared.VaultAgentTokenPath))
	return nil
}

func RunVaultTestQuery() error {
	zap.L().Info("Running test query using Vault Agent token", zap.String("path", shared.TestKVPath))

	cmd := exec.Command("sudo", "vault", "kv", "get", "-format=json", shared.TestKVPath)
	cmd.Env = append(os.Environ(), "VAULT_TOKEN_PATH="+shared.VaultAgentTokenPath)

	output, err := cmd.CombinedOutput()
	if err != nil {
		zap.L().Error("Vault test query failed", zap.ByteString("output", output), zap.Error(err))
		return fmt.Errorf("vault test query failed: %w", err)
	}

	zap.L().Info("Vault test query succeeded", zap.ByteString("response", output))
	return nil
}

func EnsureVaultReady() (*api.Client, error) {
	client, err := NewClient()
	if err != nil {
		return nil, fmt.Errorf("vault client error: %w", err)
	}

	// Call SetupVault to initialize/unseal Vault.
	client, _, err = SetupVault(client)
	if err != nil {
		return nil, fmt.Errorf("vault not ready: %w", err)
	}
	return client, nil
}
