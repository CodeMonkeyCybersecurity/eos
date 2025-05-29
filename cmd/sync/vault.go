// cmd/sync/vault.go

package sync

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

const VaultEosSecretPrefix = "secret/eos/"

var SyncVaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Syncs fallback secrets into Vault",
	Long: `Syncs all fallback secrets stored locally (e.g. from /var/lib/eos/secrets)
into Vault, then removes them from disk if the sync is successful.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := otelzap.Ctx(rc.Ctx)

		_, err := vault.EnsureVaultEnv(rc)
		if err != nil {
			log.Error("Vault environment preparation failed", zap.Error(err))
			return err
		}

		client, err := vault.NewClient(rc)
		if err != nil {
			log.Error("Failed to create Vault client", zap.Error(err))
			return err
		}

		report, client := vault.Check(rc, client, nil, "")
		if !report.Initialized || report.Sealed {
			log.Warn("Vault is not ready", zap.Bool("initialized", report.Initialized), zap.Bool("sealed", report.Sealed))
			return fmt.Errorf("vault is not ready")
		}

		secretsDir := shared.SecretsDir
		files, err := os.ReadDir(secretsDir)
		if err != nil {
			return fmt.Errorf("failed to read fallback secrets dir: %w", err)
		}

		for _, f := range files {
			if f.IsDir() || !strings.HasSuffix(f.Name(), ".yaml") {
				continue
			}

			fullPath := filepath.Join(secretsDir, f.Name())
			base := strings.TrimSuffix(f.Name(), "-fallback.yaml")
			vaultPath := fmt.Sprintf("%s%s/config", VaultEosSecretPrefix, base)

			if err := syncFallbackFile(rc, fullPath, base, vaultPath, client); err != nil {
				log.Warn("Failed to sync fallback file", zap.String("file", fullPath), zap.Error(err))
				continue
			}
		}

		log.Info("Completed Vault fallback secrets sync.")
		return nil
	}),
}

func init() {
	SyncCmd.AddCommand(SyncVaultCmd)
}

func syncFallbackFile(rc *eos_io.RuntimeContext, fullPath, base, vaultPath string, client *api.Client) error {
	raw, err := os.ReadFile(fullPath)
	if err != nil {
		return fmt.Errorf("read file failed: %w", err)
	}

	data := make(map[string]string)
	if err := yaml.Unmarshal(raw, &data); err != nil {
		return fmt.Errorf("unmarshal YAML failed: %w", err)
	}

	if err := vault.Write(rc, client, base, data); err != nil {
		return fmt.Errorf("vault write failed: %w", err)
	}

	if err := os.Remove(fullPath); err != nil {
		return fmt.Errorf("delete fallback file failed: %w", err)
	}

	otelzap.Ctx(rc.Ctx).Info("Synced and removed fallback file", zap.String("file", fullPath), zap.String("vault_path", vaultPath))
	return nil
}
