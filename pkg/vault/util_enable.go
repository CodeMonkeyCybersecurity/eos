// pkg/vault/util_enable.go

package vault

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

/* enableFeature is a generic Logical().Write wrapper for enabling things like audit devices, etc. */
func enableFeature(rc *eos_io.RuntimeContext, client *api.Client, path string, payload map[string]interface{}, successMsg string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Enabling Vault feature",
		zap.String("path", path),
		zap.Any("payload", payload))

	_, err := client.Logical().Write(path, payload)
	if err != nil {
		if strings.Contains(err.Error(), "already enabled") || strings.Contains(err.Error(), "already exists") {
			logger.Info("Feature already enabled",
				zap.String("path", path))
			return nil
		}
		logger.Error("Failed to enable feature",
			zap.String("path", path),
			zap.Error(err))
		return fmt.Errorf("failed to enable feature at %s: %w", path, err)
	}

	logger.Info("Feature enabled successfully",
		zap.String("path", path),
		zap.String("message", successMsg))
	return nil
}
