// pkg/vault/phase9_enable_auth_and_policy.go

package vault

import (
	"context"
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

//--------------------------------------------------------------------
// 9. Enable Auth Methods and Apply Policies
//--------------------------------------------------------------------

// PHASE 9 — PhaseEnableAuthMethodsAndPolicies()
//           └── EnsureKVv2Enabled()
//           └── BootstrapKV()
//           └── EnsureVaultAuthMethods()
//               └── EnsureAuthMethod()
//           └── EnsurePolicy()
//           └── PromptForEosPassword()
//           └── ApplyAdminPolicy()
//               └── WriteKVv2()
//           └── EnableFileAudit()

// PhaseEnableAuthMethodsAndPolicies enables Vault auth methods and applies the EOS policy.
func PhaseEnableKVv2(client *api.Client) error {
	zap.L().Info("🔒 [Phase 9/15] Enabling Vault KV engine")

	// 1️⃣ Ensure KVv2 is enabled
	if err := EnsureKVv2Enabled(client, shared.VaultMountKV); err != nil {
		return fmt.Errorf("kvv2 enable failed: %w", err)
	}

	// 2️⃣ Bootstrap test secret to validate KV is working
	if err := BootstrapKV(client, "bootstrap/test"); err != nil {
		return fmt.Errorf("bootstrap KV failed: %w", err)
	}

	// 4️⃣ Upload eos-policy
	if err := EnsurePolicy(client); err != nil {
		return fmt.Errorf("apply EOS policy: %w", err)
	}

	zap.L().Info("✅ Auth methods, policy, eos user, and auditing successfully configured")
	return nil
}

// IsMountEnabled checks whether a Vault mount exists at the given path.
func IsMountEnabled(client *api.Client, mount string) (bool, error) {
	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return false, err
	}
	_, exists := mounts[mount]
	return exists, nil
}

// VaultUpdate reads existing secret and applies a patch map
func UpdateVault(path string, update map[string]interface{}) error {
	client, err := GetPrivilegedVaultClient()
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

// EnsureKVv2Enabled makes sure the KV‑v2 secrets engine is mounted at mountPath.
func EnsureKVv2Enabled(client *api.Client, mountPath string) error {
	zap.L().Info("➕ Ensuring KV‑v2 secrets engine", zap.String("path", mountPath))

	// Vault mounts always include a trailing slash in the map key
	normalized := strings.TrimSuffix(mountPath, "/") + "/"

	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return fmt.Errorf("could not list mounts: %w", err)
	}
	if m, ok := mounts[normalized]; ok {
		if m.Type == "kv" && m.Options["version"] == "2" {
			zap.L().Info("✅ KV‑v2 already enabled", zap.String("path", mountPath))
			return nil
		}
		// if it’s kv v1, we’ll unmount then re‑enable v2
		if m.Type == "kv" {
			zap.L().Warn("🔄 KV engine mounted as v1, unmounting to reconfigure v2", zap.String("path", mountPath))
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
	zap.L().Info("✅ KV‑v2 enabled", zap.String("path", mountPath))
	return nil
}

// BootstrapKV puts a little “ok” into secret/bootstrap/test.
func BootstrapKV(client *api.Client, kvPath string) error {
	zap.L().Info("🧪 Writing bootstrap secret", zap.String("path", kvPath))

	// get a KV v2 client for the "secret/" mount
	kvClient := client.KVv2(strings.TrimSuffix(shared.KVNamespaceSecrets, "/"))

	// debug: show exactly what we're about to write
	payload := map[string]interface{}{"value": "ok"}
	zap.L().Debug("🔃 KV v2 put",
		zap.String("mount", strings.TrimSuffix(shared.KVNamespaceSecrets, "/")),
		zap.String("path", kvPath),
		zap.Any("data", payload),
	)

	// ignore the returned *KVSecret, just catch the error
	if _, err := kvClient.Put(context.Background(), kvPath, payload); err != nil {
		zap.L().Error("❌ Failed to write bootstrap secret",
			zap.String("path", kvPath),
			zap.Error(err),
		)
		return fmt.Errorf("failed to write bootstrap secret at %s: %w", kvPath, err)
	}

	zap.L().Info("✅ Bootstrap secret written", zap.String("path", kvPath))
	return nil
}
