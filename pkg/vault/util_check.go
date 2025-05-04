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

func Check(client *api.Client, storedHashes []string, hashedRoot string) (*shared.CheckReport, *api.Client) {
	report := &shared.CheckReport{}

	// 1️⃣ Check VAULT_ADDR
	if os.Getenv(shared.VaultAddrEnv) == "" {
		return failReport(report, "VAULT_ADDR environment variable not set")
	}

	// 2️⃣ Check Vault health
	if healthy, err := CheckVaultHealth(); err != nil || !healthy {
		return failReport(report, fmt.Sprintf("Vault health check failed: %v", err))
	}

	// 3️⃣ Check vault binary
	if !isInstalled() {
		return failReport(report, "Vault binary not installed or not found in $PATH")
	}
	report.Installed = true

	// 4️⃣ Ensure client
	if client == nil {
		c, err := NewClient()
		if err != nil {
			return failReport(report, "Could not initialize Vault client")
		}
		client = c
	}

	// 5️⃣ Check initialized & sealed
	if ok, err := IsVaultInitialized(client); err == nil {
		report.Initialized = ok
	} else {
		return failReport(report, fmt.Sprintf("Vault init check failed: %v", err))
	}
	report.Sealed = IsVaultSealed(client)
	if report.Sealed {
		report.Notes = append(report.Notes, "Vault is sealed")
	}

	// 6️⃣ Test KV
	if err := testKVSecret(client); err != nil {
		report.Notes = append(report.Notes, fmt.Sprintf("KV test failed: %v", err))
	} else {
		report.KVWorking = true
	}

	// 7️⃣ Verify secrets
	if len(storedHashes) > 0 && hashedRoot != "" && !verifyVaultSecrets(storedHashes, hashedRoot) {
		report.Notes = append(report.Notes, "Vault secret mismatch or verification failed")
	}

	return report, client
}

func failReport(r *shared.CheckReport, msg string) (*shared.CheckReport, *api.Client) {
	zap.L().Warn(msg)
	r.Notes = append(r.Notes, msg)
	return r, nil
}

func verifyVaultSecrets(storedHashes []string, hashedRoot string) bool {
	keys, root, err := PromptOrRecallUnsealKeys()
	if err != nil || !crypto.AllUnique(keys) {
		return false
	}
	return crypto.AllHashesPresent(crypto.HashStrings(keys), storedHashes) &&
		crypto.HashString(root) == hashedRoot
}

func isInstalled() bool {
	_, err := exec.LookPath("vault")
	return err == nil
}

func IsVaultInitialized(client *api.Client) (bool, error) {
	status, err := client.Sys().Health()
	return err == nil && status.Initialized, err
}

func IsVaultSealed(client *api.Client) bool {
	status, err := client.Sys().Health()
	return err == nil && status.Sealed
}

func testKVSecret(client *api.Client) error {
	kv := client.KVv2("secret")
	if _, err := kv.Put(context.Background(), shared.TestKVPath, map[string]interface{}{shared.TestKVKey: shared.TestKVValue}); err != nil {
		return err
	}
	_, err := kv.Get(context.Background(), shared.TestKVPath)
	return err
}

func CheckVaultSecrets() {
	keys, root, err := PromptOrRecallUnsealKeys()
	if err != nil || !crypto.AllUnique(keys) {
		fmt.Println("❌ Secret check aborted or invalid keys")
		return
	}
	storedHashes, hashedRoot, err := rememberBootstrapHashes()
	if err != nil {
		fmt.Println("❌ Unable to verify unseal keys — no trusted reference available.")
		return
	}
	if crypto.AllHashesPresent(crypto.HashStrings(keys), storedHashes) && crypto.HashString(root) == hashedRoot {
		fmt.Println("✅ Unseal keys and root token verified.")
	} else {
		fmt.Println("❌ Secrets do not match known trusted values.")
	}
}

func IsAlreadyInitialized(err error) bool {
	return strings.Contains(err.Error(), "Vault is already initialized")
}

func ListVault(path string) ([]string, error) {
	client, err := GetRootClient()
	if err != nil {
		return nil, err
	}
	list, err := client.Logical().List("secret/metadata/" + path)
	if err != nil || list == nil {
		return nil, err
	}
	rawKeys, _ := list.Data["keys"].([]interface{})
	keys := make([]string, len(rawKeys))
	for i, k := range rawKeys {
		keys[i] = fmt.Sprintf("%v", k)
	}
	return keys, nil
}

func CheckVaultAgentService() error {
	return exec.Command("systemctl", "is-active", "--quiet", shared.VaultAgentService).Run()
}

func CheckVaultTokenFile() error {
	if _, err := os.Stat(shared.VaultAgentTokenPath); os.IsNotExist(err) {
		return fmt.Errorf("vault token file not found at %s", shared.VaultAgentTokenPath)
	}
	return nil
}

func RunVaultTestQuery() error {
	cmd := exec.Command("vault", "kv", "get", "-format=json", shared.TestKVPath)
	cmd.Env = append(os.Environ(), "VAULT_TOKEN_PATH="+shared.VaultAgentTokenPath)
	return cmd.Run()
}

func EnsureVaultReady() (*api.Client, error) {
	client, err := NewClient()
	if err != nil {
		return nil, err
	}
	if err := probeVaultHealthUntilReady(client); err == nil {
		return client, nil
	}
	if err := recoverVaultHealth(client); err != nil {
		return nil, fmt.Errorf("vault recovery failed: %w", err)
	}
	return client, nil
}
