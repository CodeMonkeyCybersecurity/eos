package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// PhaseWriteBootstrapSecretAndRecheck writes a test secret and verifies Vault health.
// CRITICAL: This function uses the client parameter passed from Phase 6 (UnsealVault)
// which contains the root token. This must run immediately after Phase 9a (KV v2 enablement)
// and BEFORE Phase 14 (Vault Agent setup) to ensure the root token is still valid.
func PhaseWriteBootstrapSecretAndRecheck(rc *eos_io.RuntimeContext, client *api.Client) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" [Phase 9b] Writing bootstrap test secret and verifying Vault health")

	// CRITICAL: Use the passed client (authenticated in Phase 6) instead of
	// retrieving from context which may have been modified by later phases
	if client == nil {
		logger.Error(" [Phase 9b] Vault client is nil",
			zap.String("remediation", "This should never happen - Phase 6 should have passed authenticated client"))
		return fmt.Errorf("vault client cannot be nil")
	}

	// Verify client has a token and log details for troubleshooting
	token := client.Token()
	if token == "" {
		logger.Error(" [Phase 9b] Client has no authentication token",
			zap.String("vault_addr", client.Address()),
			zap.String("remediation", "Phase 6 should have set the root token"))
		return fmt.Errorf("client has no authentication token")
	}

	// Log token type for diagnostic purposes
	logger.Debug(" [Phase 9b] Using Vault client from Phase 6",
		zap.String("vault_addr", client.Address()),
		zap.Int("token_length", len(token)),
		zap.Bool("appears_to_be_root_token", strings.HasPrefix(token, "hvs.") && len(token) > 20),
		zap.Bool("appears_to_be_service_token", strings.HasPrefix(token, "s.")))

	logger.Info(" [Phase 9b] Vault client verified, proceeding with bootstrap secret write")

	//  Write bootstrap test secret using the root-authenticated client from Phase 6
	if err := PhaseWriteTestSecret(rc, client, shared.VaultTestPath, map[string]string{"example_key": "example_value"}); err != nil {
		logger.Error(" [Phase 9b] Failed to write bootstrap test secret", zap.Error(err))
		return fmt.Errorf("bootstrap test secret write failed: %w", err)
	}

	//  Check Vault health after writing secret
	healthy, err := CheckVaultHealth(rc)
	if err != nil {
		logger.Error(" [Phase 9b] Vault health check failed", zap.Error(err))
		return fmt.Errorf("vault health recheck failed: %w", err)
	}
	if !healthy {
		logger.Error(" [Phase 9b] Vault unhealthy after bootstrap secret phase")
		return fmt.Errorf("vault unhealthy after bootstrap secret phase")
	}

	logger.Info(" [Phase 9b] Bootstrap secret written and Vault healthy")
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
