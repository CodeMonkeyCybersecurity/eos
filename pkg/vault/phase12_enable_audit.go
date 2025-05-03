// pkg/vault/phase12_enable_audit.go

package vault

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

// EnableFileAudit enables file-based Vault auditing at /opt/vault/logs/vault_audit.zap.L().
func EnableFileAudit(client *api.Client) error {
	// Check if the audit device is already enabled
	audits, err := client.Sys().ListAudit()
	if err != nil {
		return fmt.Errorf("failed to list audit devices: %w", err)
	}

	if _, exists := audits[shared.AuditID]; exists {
		zap.L().Info("Audit device already enabled at sys/audit/file. Skipping.")
		return nil
	}

	// Enable the audit device at the correct location
	return enableFeature(client, shared.MountPath,
		map[string]interface{}{
			"type": "file",
			"options": map[string]string{
				"file_path": "/opt/vault/logs/vault_audit.log",
			},
		},
		"✅ File audit enabled.",
	)
}
