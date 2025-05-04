package vault

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

// PhaseWriteBootstrapSecretAndRecheck writes a test secret and verifies Vault health.
func PhaseWriteBootstrapSecretAndRecheck(_ *api.Client) error {
	zap.L().Info("🧪 [Phase 9A] Writing bootstrap test secret and verifying Vault health")

	// ✅ Get privileged client (root or agent token, validated)
	privilegedClient, err := GetRootClient()
	if err != nil {
		zap.L().Error("❌ Failed to get privileged Vault client", zap.Error(err))
		return err
	}
	zap.L().Info("✅ Privileged Vault client ready")

	// ✅ Run privileged operations
	if err := PhaseWriteTestSecret(privilegedClient, shared.VaultTestPath, map[string]string{"example_key": "example_value"}); err != nil {
		zap.L().Error("❌ Failed to write bootstrap test secret", zap.Error(err))
		return fmt.Errorf("bootstrap test secret write failed: %w", err)
	}

	// ✅ Check Vault health after writing secret
	healthy, err := CheckVaultHealth()
	if err != nil {
		zap.L().Error("❌ Vault health check failed", zap.Error(err))
		return fmt.Errorf("vault health recheck failed: %w", err)
	}
	if !healthy {
		zap.L().Error("❌ Vault unhealthy after bootstrap secret phase")
		return fmt.Errorf("vault unhealthy after bootstrap secret phase")
	}

	zap.L().Info("✅ Bootstrap secret written and Vault healthy")
	return nil
}

// PhaseWriteTestSecret writes harmless test data into Vault at the given KV path.
func PhaseWriteTestSecret(client *api.Client, kvPath string, kvData map[string]string) error {
	zap.L().Info("🧪 Writing bootstrap test secret", zap.String("path", kvPath))

	kv := client.KVv2("secret")

	if kvData == nil {
		zap.L().Warn("⚠️ No data provided for bootstrap secret — initializing empty payload")
		kvData = make(map[string]string)
	}

	data, err := json.Marshal(kvData)
	if err != nil {
		zap.L().Error("❌ Failed to marshal bootstrap data", zap.Error(err))
		return fmt.Errorf("marshal bootstrap kv data: %w", err)
	}
	payload := map[string]interface{}{"json": string(data)}

	if _, err := kv.Put(context.Background(), kvPath, payload); err != nil {
		zap.L().Error("❌ Failed to write bootstrap secret", zap.Error(err))
		return fmt.Errorf("write bootstrap secret at %s: %w", kvPath, err)
	}

	zap.L().Info("✅ Bootstrap test secret written",
		zap.String("path", kvPath),
		zap.Int("keys", len(kvData)),
		zap.Any("data", kvData),
	)
	return nil
}
