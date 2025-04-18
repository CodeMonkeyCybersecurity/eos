// pkg/vault/lifecycle_kv.go

package vault

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

//
// ========================== ENSURE ==========================
//

//
// ========================== LIST ==========================
//

//
// ========================== READ ==========================
//

//
// ========================== UPDATE ==========================
//

//
// ========================== DELETE ==========================
//

// DeployAndStoreSecrets automates Vault setup and stores secrets after confirmation.
func DeployAndStoreSecrets(client *api.Client, path string, secrets map[string]string, log *zap.Logger) error {
	log.Info("🚀 Starting Vault deployment")

	if err := execute.ExecuteAndLog("eos", "deploy", "vault"); err != nil && !strings.Contains(err.Error(), "already installed") {
		log.Error("Vault deploy failed", zap.Error(err))
		return fmt.Errorf("vault deploy failed: %w", err)
	}

	if err := execute.ExecuteAndLog("eos", "enable", "vault"); err != nil {
		log.Warn("Vault enable failed — manual unseal may be required", zap.Error(err))
		return fmt.Errorf("vault enable failed: %w", err)
	}

	if err := execute.ExecuteAndLog("eos", "secure", "vault"); err != nil {
		log.Error("Vault secure failed", zap.Error(err))
		return fmt.Errorf("vault secure failed: %w", err)
	}

	report, client := Check(client, log, nil, "")
	if !report.Initialized || report.Sealed || !report.KVWorking {
		log.Error("Vault is not fully operational after setup", zap.Any("report", report))
		return fmt.Errorf("vault does not appear to be running after setup. Try 'eos logs vault'")
	}

	log.Info("✅ Vault is ready. Proceeding to store secrets...", zap.String("path", path))

	// Convert string map to interface{}
	data := make(map[string]interface{}, len(secrets))
	for k, v := range secrets {
		data[k] = v
	}

	if err := WriteSecret(client, path, data); err != nil {
		log.Error("Failed to write secrets to Vault", zap.String("path", path), zap.Error(err))
		return err
	}

	log.Info("✅ Secrets written to Vault successfully", zap.String("path", path))
	return nil
}

func RevokeRootToken(client *api.Client, token string, log *zap.Logger) error {
	client.SetToken(token)

	err := client.Auth().Token().RevokeSelf("")
	if err != nil {
		return fmt.Errorf("failed to revoke root token: %w", err)
	}

	fmt.Println("✅ Root token revoked.")
	return nil
}

/* Initialize Vault (if not already initialized) */
func SetupVault(client *api.Client, log *zap.Logger) (*api.Client, *api.InitResponse, error) {
	fmt.Println("\nInitializing Vault...")

	if err := EnsureRuntimeDir(log); err != nil {
		log.Error("Runtime dir missing or invalid", zap.Error(err))
		return nil, nil, err
	}

	initRes, err := client.Sys().Init(&api.InitRequest{
		SecretShares:    5,
		SecretThreshold: 3,
	})
	if err != nil {
		if IsAlreadyInitialized(err, log) {
			fmt.Println("✅ Vault already initialized.")

			// ✨ Reuse fallback or prompt logic
			initRes, err := LoadInitResultOrPrompt(client, log)
			if err != nil {
				return nil, nil, fmt.Errorf("vault already initialized and fallback failed: %w\n💡 Run `eos enable vault` on a fresh Vault to reinitialize and regenerate fallback data", err)
			}

			// 🔓 Unseal and auth
			if err := UnsealVault(client, initRes, log); err != nil {
				return nil, nil, fmt.Errorf("failed to unseal already-initialized Vault: %w", err)
			}
			client.SetToken(initRes.RootToken)

			// ✅ Re-store init result
			if err := Write(client, "vault_init", initRes, log); err != nil {
				log.Warn("Failed to persist Vault init result", zap.Error(err))
			} else {
				fmt.Println("✅ Vault init result persisted successfully")
			}
			return client, initRes, nil
		}
		return nil, nil, fmt.Errorf("init failed: %w", err)
	}

	// 🆕 Vault just initialized: unseal and persist
	DumpInitResult(initRes, log)
	if err := UnsealVault(client, initRes, log); err != nil {
		return nil, nil, err
	}
	client.SetToken(initRes.RootToken)

	if err := Write(client, "vault_init", initRes, log); err != nil {
		return nil, nil, fmt.Errorf("failed to persist Vault init result: %w", err)
	}
	fmt.Println("✅ Vault init result persisted successfully")

	return client, initRes, nil
}

func IsAlreadyInitialized(err error, log *zap.Logger) bool {
	return strings.Contains(err.Error(), "Vault is already initialized")
}

func DumpInitResult(initRes *api.InitResponse, log *zap.Logger) {
	b, _ := json.MarshalIndent(initRes, "", "  ")
	_ = os.WriteFile("/tmp/vault_init.json", b, 0600)
	_ = os.WriteFile(DiskPath("vault_init", log), b, 0600)
	fmt.Printf("✅ Vault initialized with %d unseal keys.\n", len(initRes.KeysB64))
}

func UnsealVault(client *api.Client, initRes *api.InitResponse, log *zap.Logger) error {
	if len(initRes.KeysB64) < 3 {
		return fmt.Errorf("not enough unseal keys")
	}

	fmt.Println("\nUnsealing Vault...")
	for i, key := range initRes.KeysB64[:3] {
		resp, err := client.Sys().Unseal(key)
		if err != nil {
			return fmt.Errorf("unseal failed: %w", err)
		}
		if !resp.Sealed {
			fmt.Printf("✅ Vault unsealed after key %d\n", i+1)
			break
		}
	}
	fmt.Println("🔓 Unseal completed.")
	return nil
}

/* Enable file audit at "/var/snap/vault/common/vault_audit.log" */
func EnableFileAudit(client *api.Client, log *zap.Logger) error {

	// Check if the audit device is already enabled
	audits, err := client.Sys().ListAudit()
	if err != nil {
		return fmt.Errorf("failed to list audit devices: %w", err)
	}

	if _, exists := audits[auditPath]; exists {
		log.Info("Audit device already enabled at sys/audit/file. Skipping.")
		return nil
	}

	// Enable the audit device
	return enableFeature(client, mountPath,
		map[string]interface{}{
			"type": "file",
			"options": map[string]string{
				"file_path": "/var/snap/vault/common/vault_audit.log",
			},
		},
		"✅ File audit enabled.",
	)
}

func IsMountEnabled(client *api.Client, mount string) (bool, error) {
	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return false, err
	}
	_, exists := mounts[mount]
	return exists, nil
}

/* Enable KV v2 */
func EnableKV2(client *api.Client, log *zap.Logger) error {
	ok, err := IsMountEnabled(client, "secret/")
	if err != nil {
		return fmt.Errorf("failed to check if KV is mounted: %w", err)
	}
	if ok {
		log.Info("KV v2 already mounted at path=secret/. Skipping.")
		return nil
	}
	return enableMount(client, "secret", "kv", map[string]string{"version": "2"}, "✅ KV v2 enabled at path=secret.")
}

/* Enable UserPass */
func EnableUserPass(client *api.Client) error {
	return enableAuth(client, "userpass")
}

func EnsureVaultAuthMethods(client *api.Client, log *zap.Logger) error {
	if err := EnsureAuthMethod(client, "userpass", "userpass/", log); err != nil {
		return err
	}
	if err := EnsureAuthMethod(client, "approle", "approle/", log); err != nil {
		return err
	}
	return nil
}

func EnsureAuthMethod(client *api.Client, methodType, mountPath string, log *zap.Logger) error {
	existing, err := client.Sys().ListAuth()
	if err != nil {
		return fmt.Errorf("failed to list Vault auth methods: %w", err)
	}

	if _, ok := existing[mountPath]; ok {
		return nil // Already enabled
	}

	return client.Sys().EnableAuthWithOptions(
		strings.TrimSuffix(mountPath, "/"),
		&api.EnableAuthOptions{Type: methodType},
	)
}
