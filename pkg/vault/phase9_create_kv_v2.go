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

func PhaseEnableKVv2(client *api.Client) error {
	zap.L().Info("🔒 [Phase 9] Enabling Vault KV engine")

	// ✅ Get privileged client (root or agent token, validated)
	privilegedClient, err := GetRootClient()
	if err != nil {
		zap.L().Error("❌ Failed to get privileged Vault client", zap.Error(err))
		return err
	}
	zap.L().Info("✅ Privileged Vault client ready")

	// ✅ Run privileged operations
	zap.L().Info("🔨 Ensuring KV‑v2 secrets engine")
	if err := EnsureKVv2Enabled(privilegedClient, shared.VaultMountKV); err != nil {
		zap.L().Error("❌ Failed to enable KV‑v2", zap.Error(err))
		return err
	}

	zap.L().Info("🧪 Bootstrapping test secret")
	if err := BootstrapKV(privilegedClient, shared.VaultTestPath); err != nil {
		zap.L().Error("❌ Failed to bootstrap KV", zap.Error(err))
		return err
	}

	zap.L().Info("📜 Applying EOS policy")
	if err := EnsurePolicy(); err != nil {
		zap.L().Error("❌ Failed to apply EOS policy", zap.Error(err))
		return err
	}

	zap.L().Info("✅ Auth methods, policy, eos user, and auditing successfully configured")
	return nil
}

// IsMountEnabled checks whether a Vault mount exists at the given path.
func IsMountEnabled(client *api.Client, mount string) (bool, error) {
	zap.L().Debug("🔍 Checking if mount is enabled", zap.String("mount", mount))

	mounts, err := client.Sys().ListMounts()
	if err != nil {
		zap.L().Error("❌ Failed to list mounts", zap.Error(err))
		return false, err
	}
	_, exists := mounts[mount]
	zap.L().Debug("✅ Mount check complete", zap.String("mount", mount), zap.Bool("exists", exists))
	return exists, nil
}

// VaultUpdate reads existing secret and applies a patch map
func UpdateVault(path string, update map[string]interface{}) error {
	zap.L().Info("✏️ Updating Vault secret", zap.String("path", path))

	client, err := GetRootClient()
	if err != nil {
		zap.L().Error("❌ Failed to get privileged Vault client", zap.Error(err))
		return err
	}

	kv := client.KVv2("secret")

	secret, err := kv.Get(context.Background(), path)
	if err != nil {
		zap.L().Error("❌ Failed to retrieve existing secret", zap.String("path", path), zap.Error(err))
		return err
	}

	existing := secret.Data
	for k, v := range update {
		existing[k] = v
	}
	zap.L().Debug("🔃 Merged updated data", zap.Any("data", existing))

	if _, err = kv.Put(context.Background(), path, existing); err != nil {
		zap.L().Error("❌ Failed to write updated secret", zap.String("path", path), zap.Error(err))
		return err
	}

	zap.L().Info("✅ Secret updated successfully", zap.String("path", path))
	return nil
}

// EnsureKVv2Enabled makes sure the KV‑v2 secrets engine is mounted at mountPath.
func EnsureKVv2Enabled(client *api.Client, mountPath string) error {
	zap.L().Info("➕ Ensuring KV‑v2 secrets engine", zap.String("path", mountPath))

	normalized := strings.TrimSuffix(mountPath, "/") + "/"

	mounts, err := client.Sys().ListMounts()
	if err != nil {
		zap.L().Error("❌ Could not list mounts", zap.Error(err))
		return fmt.Errorf("could not list mounts: %w", err)
	}
	if m, ok := mounts[normalized]; ok {
		zap.L().Debug("ℹ️ Existing mount found", zap.String("type", m.Type), zap.Any("options", m.Options))
		if m.Type == "kv" && m.Options["version"] == "2" {
			zap.L().Info("✅ KV‑v2 already enabled", zap.String("path", mountPath))
			return nil
		}
		if m.Type == "kv" {
			zap.L().Warn("🔄 KV engine is v1; unmounting to reconfigure v2", zap.String("path", mountPath))
			if err := client.Sys().Unmount(mountPath); err != nil {
				zap.L().Error("❌ Failed to unmount KV v1", zap.String("path", mountPath), zap.Error(err))
				return fmt.Errorf("failed to unmount existing KV v1 at %s: %w", mountPath, err)
			}
		}
	}

	if err := client.Sys().Mount(mountPath, &api.MountInput{
		Type:    "kv",
		Options: map[string]string{"version": "2"},
	}); err != nil {
		zap.L().Error("❌ Failed to enable KV‑v2", zap.String("path", mountPath), zap.Error(err))
		return fmt.Errorf("failed to enable KV‑v2 at %s: %w", mountPath, err)
	}
	zap.L().Info("✅ KV‑v2 enabled", zap.String("path", mountPath))
	return nil
}

// BootstrapKV puts a little “ok” into secret/bootstrap/test.
func BootstrapKV(client *api.Client, kvPath string) error {
	zap.L().Info("🧪 Writing bootstrap secret", zap.String("path", kvPath))

	kvClient := client.KVv2(shared.VaultMountKV)

	payload := map[string]interface{}{"value": "ok"}
	zap.L().Debug("🔃 KV v2 put payload prepared", zap.String("path", kvPath), zap.Any("data", payload))

	if _, err := kvClient.Put(context.Background(), kvPath, payload); err != nil {
		zap.L().Error("❌ Failed to write bootstrap secret", zap.String("path", kvPath), zap.Error(err))
		return fmt.Errorf("failed to write bootstrap secret at %s: %w", kvPath, err)
	}

	zap.L().Info("✅ Bootstrap secret written", zap.String("path", kvPath))
	return nil
}
