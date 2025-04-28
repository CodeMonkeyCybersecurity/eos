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
func PhaseEnableAuthMethodsAndPolicies(client *api.Client, log *zap.Logger) error {
	log.Info("🚀 Phase [9/12]: Enable Vault Authentication + Policies")

	// 1️⃣ Ensure KVv2 is enabled
	if err := EnsureKVv2Enabled(client, shared.VaultMountKV, log); err != nil {
		return fmt.Errorf("kvv2 enable failed: %w", err)
	}

	// 2️⃣ Bootstrap test secret to validate KV is working
	if err := BootstrapKV(client, "bootstrap/test", log); err != nil {
		return fmt.Errorf("bootstrap KV failed: %w", err)
	}

	// 3️⃣ Enable userpass/approle auth methods
	if err := EnsureVaultAuthMethods(client, log); err != nil {
		return fmt.Errorf("enable auth methods: %w", err)
	}

	// 4️⃣ Upload eos-policy
	if err := EnsurePolicy(client, log); err != nil {
		return fmt.Errorf("apply EOS policy: %w", err)
	}

	// 5️⃣ Prompt for EOS admin password
	eosCreds, err := PromptForEosPassword(log)
	if err != nil {
		return fmt.Errorf("prompt eos password: %w", err)
	}
	if len(eosCreds.Password) < 8 {
		log.Error("eos user password too short", zap.Int("length", len(eosCreds.Password)))
		return fmt.Errorf("eos password must be at least 8 characters")
	}

	// 6️⃣ Create the eos user with full policy
	if err := ApplyAdminPolicy(*eosCreds, client, log); err != nil {
		return fmt.Errorf("apply admin policy: %w", err)
	}

	// 7️⃣ Enable file audit logging (mandatory)
	if err := EnableFileAudit(client, log); err != nil {
		log.Error("❌ Failed to enable file audit logging", zap.Error(err))
		return fmt.Errorf("enable file audit failed: %w", err)
	}

	log.Info("✅ Auth methods, policy, eos user, and auditing successfully configured")
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
	kvClient := client.KVv2(strings.TrimSuffix(shared.KVNamespaceSecrets, "/"))

	// debug: show exactly what we're about to write
	payload := map[string]interface{}{"value": "ok"}
	log.Debug("🔃 KV v2 put",
		zap.String("mount", strings.TrimSuffix(shared.KVNamespaceSecrets, "/")),
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
