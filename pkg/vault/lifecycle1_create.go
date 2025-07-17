// pkg/vault/lifecycle1_create.go

package vault

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

// TODO: Refactor Vault package to implement shared.ToolInterface:
// 1. Create VaultTool struct that implements Install(), Configure(), Verify() methods
// 2. Consolidate lifecycle phases into the standard Assess → Intervene → Evaluate pattern
// 3. Move installation check to use shared.InstallationChecker
// 4. Use shared.ServiceManager for systemd operations
// 5. Use shared.ConfigManager for configuration file management
// 6. Replace direct exec.Command with shared.RunCommand
// 7. Standardize port management using shared.PortChecker
// 8. Integrate with shared.CaddyManager for reverse proxy setup
// 9. Add Authentik integration for SSO support

func OrchestrateVaultCreate(rc *eos_io.RuntimeContext) error {
	otelzap.Ctx(rc.Ctx).Info(" Starting full Vault create lifecycle")

	// Check if Salt is available and use it if possible
	if err := checkSaltAvailability(rc); err == nil {
		otelzap.Ctx(rc.Ctx).Info("Salt is available, using Salt-based deployment")
		return OrchestrateVaultCreateViaSalt(rc)
	}

	// Fall back to direct deployment
	otelzap.Ctx(rc.Ctx).Info("Salt not available, using direct deployment")

	if err := PhaseInstallVault(rc); err != nil {
		return fmt.Errorf("install vault binary: %w", err)
	}
	if err := PrepareEnvironment(rc); err != nil {
		return fmt.Errorf("prepare environment: %w", err)
	}
	if err := GenerateTLS(rc); err != nil {
		return fmt.Errorf("generate TLS: %w", err)
	}
	if err := WriteAndValidateConfig(rc); err != nil {
		return fmt.Errorf("write and validate config: %w", err)
	}
	if err := StartVaultService(rc); err != nil {
		return fmt.Errorf("start vault: %w", err)
	}
	if err := InitializeVault(rc); err != nil {
		return fmt.Errorf("initialize vault: %w", err)
	}

	otelzap.Ctx(rc.Ctx).Info(" Vault create lifecycle completed successfully")
	return nil
}
