// pkg/vault/lifecycle_kv.go

package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

// EnsureKVv2Enabled makes sure the KV‑v2 secrets engine is mounted at mountPath.
func EnsureKVv2Enabled(client *api.Client, mountPath string, log *zap.Logger) error {
	log.Info("➕ Ensuring KV‑v2 secrets engine", zap.String("path", mountPath))

	// Vault mounts always include a trailing slash in the map key
	normalized := strings.TrimSuffix(mountPath, "/") + "/"

	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return fmt.Errorf("could not list mounts: %w", err)
	}
	if m, ok := mounts[normalized]; ok {
		if m.Type == "kv" && m.Options["version"] == "2" {
			log.Info("✅ KV‑v2 already enabled", zap.String("path", mountPath))
			return nil
		}
		// if it’s kv v1, we’ll unmount then re‑enable v2
		if m.Type == "kv" {
			log.Warn("🔄 KV engine mounted as v1, unmounting to reconfigure v2", zap.String("path", mountPath))
			if err := client.Sys().Unmount(mountPath); err != nil {
				return fmt.Errorf("failed to unmount existing KV v1 at %s: %w", mountPath, err)
			}
		}
	}

	// enable KV v2
	if err := client.Sys().Mount(mountPath, &api.MountInput{
		Type:    "kv",
		Options: map[string]string{"version": "2"},
	}); err != nil {
		return fmt.Errorf("failed to enable KV‑v2 at %s: %w", mountPath, err)
	}
	log.Info("✅ KV‑v2 enabled", zap.String("path", mountPath))
	return nil
}

// BootstrapKV puts a little “ok” into secret/bootstrap/test.
func BootstrapKV(client *api.Client, kvPath string, log *zap.Logger) error {
	log.Info("🧪 Writing bootstrap secret", zap.String("path", kvPath))

	// get a KV v2 client for the "secret/" mount
	kvClient := client.KVv2(strings.TrimSuffix(KVNamespaceSecrets, "/"))

	// debug: show exactly what we're about to write
	payload := map[string]interface{}{"value": "ok"}
	log.Debug("🔃 KV v2 put",
		zap.String("mount", strings.TrimSuffix(KVNamespaceSecrets, "/")),
		zap.String("path", kvPath),
		zap.Any("data", payload),
	)

	// ignore the returned *KVSecret, just catch the error
	if _, err := kvClient.Put(context.Background(), kvPath, payload); err != nil {
		log.Error("❌ Failed to write bootstrap secret",
			zap.String("path", kvPath),
			zap.Error(err),
		)
		return fmt.Errorf("failed to write bootstrap secret at %s: %w", kvPath, err)
	}

	log.Info("✅ Bootstrap secret written", zap.String("path", kvPath))
	return nil
}

// EnsureAppRoleAuth enables the AppRole auth method and provisions the eos‑role.
func EnsureAppRoleAuth(client *api.Client, log *zap.Logger) error {
	// 1) Enable the approle auth method if not already
	log.Info("➕ Enabling AppRole auth method")
	if err := client.Sys().EnableAuthWithOptions("approle", &api.EnableAuthOptions{Type: "approle"}); err != nil {
		if !strings.Contains(err.Error(), "path is already in use") {
			return fmt.Errorf("failed to enable approle auth: %w", err)
		}
	}
	log.Info("✅ AppRole auth method is enabled")

	// 2) Create the role
	log.Info("🛠 Provisioning AppRole", zap.String("role", roleName))
	_, err := client.Logical().Write(rolePath, map[string]interface{}{
		"policies":      []string{EosVaultPolicy},
		"token_ttl":     "4h",
		"token_max_ttl": "24h",
		"secret_id_ttl": "24h",
	})
	if err != nil {
		return fmt.Errorf("failed to create AppRole %s: %w", roleName, err)
	}
	log.Info("✅ AppRole provisioned", zap.String("role", roleName))
	return nil
}

// VaultUpdate reads existing secret and applies a patch map
func UpdateVault(path string, update map[string]interface{}, log *zap.Logger) error {
	client, err := GetPrivilegedVaultClient(log)
	if err != nil {
		return err
	}
	kv := client.KVv2("secret")

	secret, err := kv.Get(context.Background(), path)
	if err != nil {
		return err
	}

	existing := secret.Data
	for k, v := range update {
		existing[k] = v
	}
	_, err = kv.Put(context.Background(), path, existing)
	return err
}

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

	if _, exists := audits[auditID]; exists {
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
