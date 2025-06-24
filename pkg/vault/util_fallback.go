package vault

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// HandleFallbackOrStore determines whether secrets should be written to Vault,
// stored to disk, or handled via user fallback flow, based on Vault availability.
func HandleFallbackOrStore(rc *eos_io.RuntimeContext, name string, secrets map[string]string) error {
	if _, err := EnsureVaultEnv(rc); err != nil {
		otelzap.Ctx(rc.Ctx).Warn("Failed to set VAULT_ADDR environment", zap.Error(err))
	}

	client, err := mustNewClient(rc)
	if err != nil {
		return err
	}

	report, client := Check(rc, client, nil, "")
	if client == nil {
		otelzap.Ctx(rc.Ctx).Warn("Vault check failed: client unavailable")
		return handleVaultUnavailable(rc, name, secrets)
	}

	if report.Initialized && !report.Sealed && report.KVWorking {
		otelzap.Ctx(rc.Ctx).Info(" Vault is available and healthy — storing secrets securely", zap.String("name", name))
		return WriteToVault(rc, name, secrets)
	}

	otelzap.Ctx(rc.Ctx).Info(" Vault unavailable or unhealthy", zap.String("name", name))
	return handleVaultUnavailable(rc, name, secrets)
}

// handleVaultUnavailable prompts the user to select a fallback strategy when Vault is unavailable.
func handleVaultUnavailable(rc *eos_io.RuntimeContext, name string, secrets map[string]string) error {
	choice := interaction.FallbackPrompter(
		rc,
		"Vault not detected or not ready. What would you like to do?",
		[]interaction.FallbackOption{
			{Label: "Deploy local Vault now [recommended]", Code: string(shared.FallbackDeploy)},
			{Label: "Skip and save credentials to disk", Code: string(shared.FallbackDisk)},
			{Label: "Abort", Code: string(shared.FallbackAbort)},
		},
	)

	return interaction.HandleFallbackChoice(rc, choice, map[string]func() error{
		string(shared.FallbackDeploy): func() error {
			client, err := mustNewClient(rc)
			if err != nil {
				return err
			}
			return DeployAndStoreSecrets(rc, client, name, secrets)
		},
		string(shared.FallbackDisk): func() error {
			otelzap.Ctx(rc.Ctx).Warn("Saving secrets to disk fallback", zap.String("fallback", "disk"), zap.String("name", name))
			return WriteFallbackSecrets(rc, name, secrets) //  fixed missing logger arg
		},
		string(shared.FallbackAbort): func() error {
			otelzap.Ctx(rc.Ctx).Warn("User aborted — Vault unavailable and disk fallback declined", zap.String("name", name))
			otelzap.Ctx(rc.Ctx).Info("Secrets were not saved due to user abort", zap.String("name", name))
			return fmt.Errorf("vault unavailable, user aborted")
		},
	}) //  fixed missing logger arg
}

// mustNewClient attempts to create a Vault client and logs any error.
func mustNewClient(rc *eos_io.RuntimeContext) (*api.Client, error) {
	client, err := NewClient(rc)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error("Failed to create Vault client", zap.Error(err))
	}
	return client, err
}

func MaybeWriteVaultInitFallback(rc *eos_io.RuntimeContext, init *api.InitResponse) error {
	fmt.Print(" Save Vault init material to fallback file? (y/N): ")
	var resp string
	shared.SafeScanln(&resp)
	if strings.ToLower(resp) != "y" {
		otelzap.Ctx(rc.Ctx).Warn(" Skipping fallback write at user request")
		return nil
	}
	return SaveInitResult(rc, init)
}

// TryLoadUnsealKeysFromFallback attempts to load the vault-init.json file and parse the keys.
func TryLoadUnsealKeysFromFallback(rc *eos_io.RuntimeContext) (*api.InitResponse, error) {
	path := DiskPath(rc, "vault_init")
	otelzap.Ctx(rc.Ctx).Info(" Attempting fallback unseal using init file", zap.String("path", path))
	initRes := new(api.InitResponse)

	if err := ReadFallbackJSON(path, initRes); err != nil {
		otelzap.Ctx(rc.Ctx).Warn("Failed to read fallback file", zap.Error(err))
		return nil, fmt.Errorf("failed to read vault init fallback file: %w", err)
	}
	if len(initRes.KeysB64) < 3 || initRes.RootToken == "" {
		return nil, fmt.Errorf("invalid or incomplete vault-init.json file")
	}
	otelzap.Ctx(rc.Ctx).Info(" Fallback file validated", zap.Int("keys_found", len(initRes.KeysB64)))
	return initRes, nil
}
