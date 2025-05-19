// pkg/vault/lifecycle_kv.go

package vault

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

//
// ========================== DELETE ==========================
//

// DeployAndStoreSecrets automates Vault setup and stores secrets after confirmation.
func DeployAndStoreSecrets(client *api.Client, path string, secrets map[string]string) error {
	zap.L().Info("🚀 Starting Vault deployment")

	if err := execute.RunSimple(shared.EosID, "deploy", "vault"); err != nil && !strings.Contains(err.Error(), "already installed") {
		zap.L().Error("Vault deploy failed", zap.Error(err))
		return fmt.Errorf("vault deploy failed: %w", err)
	}

	if err := execute.RunSimple(shared.EosID, "enable", "vault"); err != nil {
		zap.L().Warn("Vault enable failed — manual unseal may be required", zap.Error(err))
		return fmt.Errorf("vault enable failed: %w", err)
	}

	if err := execute.RunSimple(shared.EosID, "secure", "vault"); err != nil {
		zap.L().Error("Vault secure failed", zap.Error(err))
		return fmt.Errorf("vault secure failed: %w", err)
	}

	report, client := Check(client, nil, "")
	if !report.Initialized || report.Sealed || !report.KVWorking {
		zap.L().Error("Vault is not fully operational after setup", zap.Any("report", report))
		return fmt.Errorf("vault does not appear to be running after setup. Try 'eos logs vault'")
	}

	zap.L().Info("✅ Vault is ready. Proceeding to store secrets...", zap.String("path", path))

	// Convert string map to interface{}
	data := make(map[string]interface{}, len(secrets))
	for k, v := range secrets {
		data[k] = v
	}

	if err := WriteSecret(client, path, data); err != nil {
		zap.L().Error("Failed to write secrets to Vault", zap.String("path", path), zap.Error(err))
		return err
	}

	zap.L().Info("✅ Secrets written to Vault successfully", zap.String("path", path))
	return nil
}
