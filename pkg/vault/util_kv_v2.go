// pkg/vault/lifecycle_kv.go

package vault

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

//
// ========================== DELETE ==========================
//

// DeployAndStoreSecrets automates Vault setup and stores secrets after confirmation.
func DeployAndStoreSecrets(rc *eos_io.RuntimeContext, client *api.Client, path string, secrets map[string]string) error {
	otelzap.Ctx(rc.Ctx).Info(" Starting Vault deployment")

	if err := execute.RunSimple(rc.Ctx, shared.EosID, "deploy", "vault"); err != nil && !strings.Contains(err.Error(), "already installed") {
		otelzap.Ctx(rc.Ctx).Error("Vault deploy failed", zap.Error(err))
		return fmt.Errorf("vault deploy failed: %w", err)
	}

	if err := execute.RunSimple(rc.Ctx, shared.EosID, "enable", "vault"); err != nil {
		otelzap.Ctx(rc.Ctx).Warn("Vault enable failed — manual unseal may be required", zap.Error(err))
		return fmt.Errorf("vault enable failed: %w", err)
	}

	if err := execute.RunSimple(rc.Ctx, shared.EosID, "secure", "vault"); err != nil {
		otelzap.Ctx(rc.Ctx).Error("Vault secure failed", zap.Error(err))
		return fmt.Errorf("vault secure failed: %w", err)
	}

	report, client := Check(rc, client, nil, "")
	if !report.Initialized || report.Sealed || !report.KVWorking {
		otelzap.Ctx(rc.Ctx).Error("Vault is not fully operational after setup", zap.Any("report", report))
		return fmt.Errorf("vault does not appear to be running after setup. Try 'eos logs vault'")
	}

	otelzap.Ctx(rc.Ctx).Info(" Vault is ready. Proceeding to store secrets...", zap.String("path", path))

	// Convert string map to interface{}
	data := make(map[string]interface{}, len(secrets))
	for k, v := range secrets {
		data[k] = v
	}

	if err := WriteSecret(client, path, data); err != nil {
		otelzap.Ctx(rc.Ctx).Error("Failed to write secrets to Vault", zap.String("path", path), zap.Error(err))
		return err
	}

	otelzap.Ctx(rc.Ctx).Info(" Secrets written to Vault successfully", zap.String("path", path))
	return nil
}
