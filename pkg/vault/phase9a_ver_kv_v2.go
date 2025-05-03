// pkg/vault/phase9_ver_kv_v2.go

package vault

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

//--------------------------------------------------------------------
// Phase 9B: Write Bootstrap Secret and Recheck Vault Health
//--------------------------------------------------------------------

// PhaseWriteBootstrapSecretAndRecheck writes a test secret and verifies Vault health.
func PhaseWriteBootstrapSecretAndRecheck(client *api.Client) error {
	zap.L().Info("🧪 [Phase 9B] Writing bootstrap test secret and verifying Vault health")

	if err := PhaseWriteTestSecret(client, shared.VaultTestPath, map[string]string{"example_key": "example_value"}); err != nil {
		return fmt.Errorf("bootstrap test secret write failed: %w", err)
	}

	healthy, err := CheckVaultHealth()
	if err != nil {
		return fmt.Errorf("vault health recheck failed: %w", err)
	}
	if !healthy {
		return fmt.Errorf("vault unhealthy after bootstrap secret phase")
	}

	zap.L().Info("✅ Bootstrap secret written and Vault healthy")
	return nil
}

// PhaseWriteTestSecret writes harmless test data into Vault at the given KV path.
func PhaseWriteTestSecret(client *api.Client, kvPath string, kvData map[string]string) error {
	zap.L().Info("🧪 Writing bootstrap test secret", zap.String("path", kvPath))

	kv := client.KVv2("secret")

	// Initialize an empty map if needed
	if kvData == nil {
		zap.L().Warn("⚠️ No data provided for bootstrap secret — initializing empty payload")
		kvData = make(map[string]string)
	}

	// Encode payload
	data, err := json.Marshal(kvData)
	if err != nil {
		return fmt.Errorf("marshal bootstrap kv data: %w", err)
	}
	payload := map[string]interface{}{"json": string(data)}

	// Write secret
	if _, err := kv.Put(context.Background(), kvPath, payload); err != nil {
		return fmt.Errorf("write bootstrap secret at %s: %w", kvPath, err)
	}

	zap.L().Info("✅ Bootstrap test secret written", zap.String("path", kvPath), zap.Int("keys", len(kvData)))
	return nil
}
