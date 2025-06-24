package vault

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// PhaseWriteBootstrapSecretAndRecheck writes a test secret and verifies Vault health.
func PhaseWriteBootstrapSecretAndRecheck(rc *eos_io.RuntimeContext, _ *api.Client) error {
	otelzap.Ctx(rc.Ctx).Info(" [Phase 9b] Writing bootstrap test secret and verifying Vault health")

	//  Get privileged client (root or agent token, validated)
	privilegedClient, err := GetRootClient(rc)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error(" Failed to get privileged Vault client", zap.Error(err))
		return err
	}
	otelzap.Ctx(rc.Ctx).Info(" Privileged Vault client ready")

	//  Run privileged operations
	if err := PhaseWriteTestSecret(rc, privilegedClient, shared.VaultTestPath, map[string]string{"example_key": "example_value"}); err != nil {
		otelzap.Ctx(rc.Ctx).Error(" Failed to write bootstrap test secret", zap.Error(err))
		return fmt.Errorf("bootstrap test secret write failed: %w", err)
	}

	//  Check Vault health after writing secret
	healthy, err := CheckVaultHealth(rc)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error(" Vault health check failed", zap.Error(err))
		return fmt.Errorf("vault health recheck failed: %w", err)
	}
	if !healthy {
		otelzap.Ctx(rc.Ctx).Error(" Vault unhealthy after bootstrap secret phase")
		return fmt.Errorf("vault unhealthy after bootstrap secret phase")
	}

	otelzap.Ctx(rc.Ctx).Info(" Bootstrap secret written and Vault healthy")
	return nil
}

// PhaseWriteTestSecret writes harmless test data into Vault at the given KV path.
func PhaseWriteTestSecret(rc *eos_io.RuntimeContext, client *api.Client, kvPath string, kvData map[string]string) error {
	otelzap.Ctx(rc.Ctx).Info(" Writing bootstrap test secret", zap.String("path", kvPath))

	kv := client.KVv2("secret")

	if kvData == nil {
		otelzap.Ctx(rc.Ctx).Warn("No data provided for bootstrap secret — initializing empty payload")
		kvData = make(map[string]string)
	}

	data, err := json.Marshal(kvData)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error(" Failed to marshal bootstrap data", zap.Error(err))
		return fmt.Errorf("marshal bootstrap kv data: %w", err)
	}
	payload := map[string]interface{}{"json": string(data)}

	if _, err := kv.Put(context.Background(), kvPath, payload); err != nil {
		otelzap.Ctx(rc.Ctx).Error(" Failed to write bootstrap secret", zap.Error(err))
		return fmt.Errorf("write bootstrap secret at %s: %w", kvPath, err)
	}

	otelzap.Ctx(rc.Ctx).Info(" Bootstrap test secret written",
		zap.String("path", kvPath),
		zap.Int("keys", len(kvData)),
		zap.Any("data", kvData),
	)
	return nil
}
