// pkg/vault/phase9_enable_auth_and_policy.go

package vault

import (
	"context"
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
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

func PhaseEnableKVv2(rc *eos_io.RuntimeContext, client *api.Client) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info("🔒 [Phase 9a] Enabling Vault KV engine")

	// Log if current client has token
	if currentToken := client.Token(); currentToken != "" {
		log.Info("🔍 Current client has token set")
	} else {
		log.Warn("⚠️ Current client has no token set")
	}

	// ✅ Get privileged client (root or agent token, validated)
	log.Info("🔑 Requesting privileged Vault client")
	privilegedClient, err := GetRootClient(rc)
	if err != nil {
		log.Error("❌ Failed to get privileged Vault client", zap.Error(err))
		return err
	}

	// Log what token the privileged client is using
	if privToken := privilegedClient.Token(); privToken != "" {
		log.Info("✅ Privileged Vault client ready")
	} else {
		log.Error("❌ Privileged client has no token set")
		return fmt.Errorf("privileged client has no token")
	}

	// ✅ Run privileged operations
	otelzap.Ctx(rc.Ctx).Info("🔨 Ensuring KV‑v2 secrets engine")
	if err := EnsureKVv2Enabled(rc, privilegedClient, shared.VaultMountKV); err != nil {
		otelzap.Ctx(rc.Ctx).Error("❌ Failed to enable KV‑v2", zap.Error(err))
		return err
	}

	otelzap.Ctx(rc.Ctx).Info("🧪 Bootstrapping test secret")
	if err := BootstrapKV(rc, privilegedClient, shared.VaultTestPath); err != nil {
		otelzap.Ctx(rc.Ctx).Error("❌ Failed to bootstrap KV", zap.Error(err))
		return err
	}

	otelzap.Ctx(rc.Ctx).Info("✅ KV v2 secrets engine successfully configured")
	return nil
}

// IsMountEnabled checks whether a Vault mount exists at the given path.
func IsMountEnabled(rc *eos_io.RuntimeContext, client *api.Client, mount string) (bool, error) {
	otelzap.Ctx(rc.Ctx).Debug("🔍 Checking if mount is enabled", zap.String("mount", mount))

	mounts, err := client.Sys().ListMounts()
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error("❌ Failed to list mounts", zap.Error(err))
		return false, err
	}
	_, exists := mounts[mount]
	otelzap.Ctx(rc.Ctx).Debug("✅ Mount check complete", zap.String("mount", mount), zap.Bool("exists", exists))
	return exists, nil
}

// VaultUpdate reads existing secret and applies a patch map
func UpdateVault(rc *eos_io.RuntimeContext, path string, update map[string]interface{}) error {
	otelzap.Ctx(rc.Ctx).Info("✏️ Updating Vault secret", zap.String("path", path))

	client, err := GetRootClient(rc)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error("❌ Failed to get privileged Vault client", zap.Error(err))
		return err
	}

	kv := client.KVv2("secret")

	secret, err := kv.Get(context.Background(), path)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error("❌ Failed to retrieve existing secret", zap.String("path", path), zap.Error(err))
		return err
	}

	existing := secret.Data
	for k, v := range update {
		existing[k] = v
	}
	otelzap.Ctx(rc.Ctx).Debug("🔃 Merged updated data", zap.Any("data", existing))

	if _, err = kv.Put(context.Background(), path, existing); err != nil {
		otelzap.Ctx(rc.Ctx).Error("❌ Failed to write updated secret", zap.String("path", path), zap.Error(err))
		return err
	}

	otelzap.Ctx(rc.Ctx).Info("✅ Secret updated successfully", zap.String("path", path))
	return nil
}

// EnsureKVv2Enabled makes sure the KV‑v2 secrets engine is mounted at mountPath.
func EnsureKVv2Enabled(rc *eos_io.RuntimeContext, client *api.Client, mountPath string) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info("➕ Ensuring KV‑v2 secrets engine", zap.String("path", mountPath))

	// Log client details before making API call
	if token := client.Token(); token != "" {
		log.Info("🔍 Making API call with token",
			zap.String("vault_addr", client.Address()),
			zap.String("api_endpoint", "GET /v1/sys/mounts"))
	} else {
		log.Error("❌ No token set on client for API call")
		return fmt.Errorf("no token set on Vault client")
	}

	normalized := strings.TrimSuffix(mountPath, "/") + "/"

	log.Info("📞 Calling Vault API: sys/mounts")
	mounts, err := client.Sys().ListMounts()
	if err != nil {
		log.Error("❌ Could not list mounts - API call failed",
			zap.Error(err),
			zap.String("vault_addr", client.Address()))
		return fmt.Errorf("could not list mounts: %w", err)
	}
	log.Info("✅ Successfully listed mounts",
		zap.Int("mount_count", len(mounts)))
	if m, ok := mounts[normalized]; ok {
		otelzap.Ctx(rc.Ctx).Debug("ℹ️ Existing mount found", zap.String("type", m.Type), zap.Any("options", m.Options))
		if m.Type == "kv" && m.Options["version"] == "2" {
			otelzap.Ctx(rc.Ctx).Info("✅ KV‑v2 already enabled", zap.String("path", mountPath))
			return nil
		}
		if m.Type == "kv" {
			otelzap.Ctx(rc.Ctx).Warn("🔄 KV engine is v1; unmounting to reconfigure v2", zap.String("path", mountPath))
			if err := client.Sys().Unmount(mountPath); err != nil {
				otelzap.Ctx(rc.Ctx).Error("❌ Failed to unmount KV v1", zap.String("path", mountPath), zap.Error(err))
				return fmt.Errorf("failed to unmount existing KV v1 at %s: %w", mountPath, err)
			}
		}
	}

	if err := client.Sys().Mount(mountPath, &api.MountInput{
		Type:    "kv",
		Options: map[string]string{"version": "2"},
	}); err != nil {
		otelzap.Ctx(rc.Ctx).Error("❌ Failed to enable KV‑v2", zap.String("path", mountPath), zap.Error(err))
		return fmt.Errorf("failed to enable KV‑v2 at %s: %w", mountPath, err)
	}
	otelzap.Ctx(rc.Ctx).Info("✅ KV‑v2 enabled", zap.String("path", mountPath))
	return nil
}

// BootstrapKV puts a little “ok” into secret/bootstrap/test.
func BootstrapKV(rc *eos_io.RuntimeContext, client *api.Client, kvPath string) error {
	otelzap.Ctx(rc.Ctx).Info("🧪 Writing bootstrap secret", zap.String("path", kvPath))

	kvClient := client.KVv2(shared.VaultMountKV)

	payload := map[string]interface{}{"value": "ok"}
	otelzap.Ctx(rc.Ctx).Debug("🔃 KV v2 put payload prepared", zap.String("path", kvPath), zap.Any("data", payload))

	if _, err := kvClient.Put(context.Background(), kvPath, payload); err != nil {
		otelzap.Ctx(rc.Ctx).Error("❌ Failed to write bootstrap secret", zap.String("path", kvPath), zap.Error(err))
		return fmt.Errorf("failed to write bootstrap secret at %s: %w", kvPath, err)
	}

	otelzap.Ctx(rc.Ctx).Info("✅ Bootstrap secret written", zap.String("path", kvPath))
	return nil
}
