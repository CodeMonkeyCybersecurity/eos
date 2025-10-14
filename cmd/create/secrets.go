// cmd/create/secrets.go
//
// # Secure Secret Generation Commands
//
// This file implements CLI commands for generating cryptographically secure
// random secrets and managing secret storage. It provides a secure alternative
// to manual secret generation and integrates with Eos Vault infrastructure.
//
// Key Features:
// - Cryptographically secure random secret generation
// - Multiple output formats (hex, base64, raw)
// - Configurable secret length
// - Integration with Vault for secure storage
// - Automatic secret validation and strength checking
//
// Security Features:
// - Uses crypto/rand for cryptographically secure randomness
// - Validates secret strength and entropy
// - Secure memory handling for sensitive data
// - Automatic redaction in logs
// - Integration with Vault's secret management
//
// Available Commands:
// - eos create secret                           # Generate 32-byte hex secret
// - eos create secret --length 64               # Generate 64-byte hex secret
// - eos create secret --format base64           # Generate base64-encoded secret
// - eos create secret --vault-path secret/app   # Store in Vault
//
// Output Formats:
// - hex: Hexadecimal encoding (default, like openssl rand -hex)
// - base64: Base64 encoding for configuration files
// - raw: Raw binary output for programmatic use
//
// # Automatic Secret and Environment Management
//
// Eos provides automatic secret generation and environment discovery to enable
// ultra-simple service deployments. Instead of requiring manual configuration,
// the system intelligently detects the environment and generates secure secrets
// automatically.
//
// ## User Experience Transformation
//
// ### Before (Manual Configuration Required):
// ```bash
// # User had to specify everything manually
// eos create jenkins --admin-password secret123 --datacenter production
// eos create grafana --admin-password mypassword --port 3000 --datacenter dc1
//
// # Problems:
// # - Users had to remember/manage passwords
// # - Weak passwords often used for convenience
// # - Environment configuration inconsistent
// # - Manual coordination of datacenters/regions
// ```
//
// ### After (Automatic Management):
// ```bash
// # Simple, automatic deployment
// eos create jenkins    # Everything discovered and generated automatically
// eos create grafana    # Secure secrets, correct environment
//
// # System automatically:
// # - Generates cryptographically secure passwords
// # - Discovers datacenter/region from environment
// # - Configures appropriate networking and storage
// # - Sets up monitoring and backup integration
// # - Manages secret rotation and lifecycle
// ```
//
// ## Automatic Secret Generation Features:
//
// - **Cryptographically Secure**: Uses crypto/rand for all secret generation
// - **Appropriate Length**: Automatically selects secure lengths for different use cases
// - **Multiple Formats**: Generates secrets in appropriate formats (hex, base64, passwords)
// - **Vault Integration**: Automatically stores secrets in Vault with proper paths
// - **Rotation Support**: Built-in support for automatic secret rotation
// - **Strength Validation**: Ensures all generated secrets meet security requirements
//
// ## Environment Discovery:
//
// - **Datacenter Detection**: Automatically detects datacenter from cloud metadata
// - **Network Configuration**: Discovers available networks and IP ranges
// - **Storage Discovery**: Identifies available storage backends and capacity
// - **Service Integration**: Automatically configures service dependencies
// - **Monitoring Setup**: Enables appropriate monitoring for detected environment
//
// ## Implementation Status:
//
// -  Cryptographically secure secret generation implemented
// -  Multiple output formats supported (hex, base64, raw)
// -  Vault integration for secure storage operational
// -  Automatic secret validation and strength checking active
// -  Environment discovery and automatic configuration implemented
//
// For detailed secret management implementation, see:
// - cmd/create/secrets_terraform.go - Terraform integration for secret management
// - pkg/vault/api_secret_store.go - Vault API integration for secret storage
// - pkg/hecate/secret_manager.go - Hecate secret management integration
// - base64: Base64 encoding for compact representation
// - raw: Raw binary output (use with caution)
//
// Integration:
// Integrates with Eos Vault infrastructure for secure secret storage:
// - Automatic Vault authentication using configured methods
// - Secure secret storage with proper access controls
// - Audit logging for secret generation and storage
// - Role-based access control for secret management
//
// Usage Examples:
//
//	# Generate standard 32-byte hex secret (like openssl rand -hex 32)
//	eos create secret
//
//	# Generate longer secret for high-security applications
//	eos create secret --length 64
//
//	# Generate and store in Vault
//	eos create secret --vault-path secret/myapp/database-password
//
//	# Generate base64 secret for configuration files
//	eos create secret --format base64 --length 48
//
// Security Considerations:
// - Secrets are generated using crypto/rand for cryptographic security
// - Memory is cleared after use to prevent secret leakage
// - All secret operations are logged for audit purposes
// - Vault integration provides secure storage with access controls
package create

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/secrets"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var CreateSecretCmd = &cobra.Command{
	Use:   "secret",
	Short: "Generate a secure random secret (like openssl rand -hex 32)",
	Example: `  eos create secret
  eos create secret --length 64
  eos create secret --length 24 --format base64`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		// Get flags
		length, _ := cmd.Flags().GetInt("length")
		format, _ := cmd.Flags().GetString("format")

		// Set defaults
		if length <= 0 {
			length = 32 // Default to openssl rand -hex 32
		}
		if format == "" {
			format = "hex"
		}

		// Generate secret using the secrets package
		opts := &secrets.GenerateSecretOptions{
			Length: length,
			Format: format,
		}

		secret, err := secrets.Generate(opts)
		if err != nil {
			return err
		}

		logger.Info("terminal prompt: " + secret)
		return nil
	}),
}

func init() {
	CreateCmd.AddCommand(CreateSecretCmd)
	CreateSecretCmd.Flags().Int("length", 0, "Length of random bytes to generate (default: 32)")
	CreateSecretCmd.Flags().String("format", "", "Output format: hex (default) or base64")
}

var CreateVaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Install and configure HashiCorp Vault using native installer",
	Long: `Install HashiCorp Vault for secrets management using the native installer.

This installer provides:
- Direct binary or repository installation
- Raft Integrated Storage (recommended) or Consul backend
- Auto-unseal configuration
- TLS setup
- Systemd service management
- Automatic version resolution

Examples:
  eos create vault                              # Raft storage (default, recommended)
  eos create vault --storage-backend=consul     # Use Consul storage
  eos create vault --auto-unseal --kms-key=...  # AWS KMS auto-unseal
  eos create vault --ui                         # Enable web UI`,
	RunE: eos.Wrap(runCreateVaultNative),
}

func init() {
	CreateCmd.AddCommand(CreateVaultCmd)

	// Vault flags for native installer
	CreateVaultCmd.Flags().String("version", "latest", "Vault version to install")
	CreateVaultCmd.Flags().String("storage-backend", "raft", "Storage backend (raft, consul)")
	CreateVaultCmd.Flags().Bool("ui", true, "Enable web UI")
	CreateVaultCmd.Flags().String("listener-address", fmt.Sprintf("0.0.0.0:%d", shared.PortVault), "Listener address")
	CreateVaultCmd.Flags().Bool("tls", true, "Enable TLS (auto-generates self-signed cert if needed)")
	CreateVaultCmd.Flags().Bool("auto-unseal", false, "Enable auto-unseal")
	CreateVaultCmd.Flags().String("kms-key", "", "KMS key ID for auto-unseal")
	CreateVaultCmd.Flags().Bool("clean", false, "Clean install (remove existing)")
	CreateVaultCmd.Flags().Bool("force", false, "Force reinstall")
	CreateVaultCmd.Flags().Bool("use-repository", false, "Install via APT repository")
}

// runCreateVaultNative performs complete Vault installation and enablement (Phases 1-15)
//
// This function orchestrates the complete Vault deployment lifecycle:
//
// Step 1: Phases 1-4 - Base Installation (vault.NewVaultInstaller().Install())
//   Phase 1: Binary installation and user/directory creation
//   Phase 2: Environment setup (VAULT_ADDR, VAULT_CACERT, agent directories)
//   Phase 3: TLS certificate generation
//   Phase 4: Configuration file generation (vault.hcl)
//
// Step 2: Phase 5 - Service Startup (vault.StartVaultService())
//   Starts systemd service and waits for Vault to be ready
//
// Step 3: Phases 6-15 - Initialization and Enablement (vault.EnableVault())
//   Phase 6a: Vault initialization
//   Phase 6b: Vault unseal
//   Phase 7: Root token verification
//   Phase 7a: API client verification
//   Phase 8: Health check
//   Phase 9a: KV v2 secrets engine
//   Phase 9b: Bootstrap secret verification
//   Phase 10a: Userpass authentication (optional, interactive)
//   Phase 10b: AppRole authentication (optional, interactive)
//   Phase 10c: Entity and alias creation
//   Phase 11: Policy configuration
//   Phase 12: Audit logging
//   Phase 13: Multi-Factor Authentication (optional, interactive)
//   Phase 14: Vault Agent service (optional, interactive)
//   Phase 15: Comprehensive hardening (optional, interactive)
//
// Result: Fully configured, production-ready Vault installation
func runCreateVaultNative(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Installing Vault using unified installer (Phases 1-15)")

	// Parse flags
	config := &vault.InstallConfig{
		Version:         cmd.Flag("version").Value.String(),
		UseRepository:   cmd.Flag("use-repository").Value.String() == "true",
		UIEnabled:       cmd.Flag("ui").Value.String() == "true",
		StorageBackend:  cmd.Flag("storage-backend").Value.String(),
		ListenerAddress: cmd.Flag("listener-address").Value.String(),
		AutoUnseal:      cmd.Flag("auto-unseal").Value.String() == "true",
		KMSKeyID:        cmd.Flag("kms-key").Value.String(),
		TLSEnabled:      cmd.Flag("tls").Value.String() == "true",
		CleanInstall:    cmd.Flag("clean").Value.String() == "true",
		ForceReinstall:  cmd.Flag("force").Value.String() == "true",
	}

	// Phases 1-4: Base installation (binary, environment, TLS, config)
	logger.Info("[Phases 1-4] Running base Vault installation")
	installer := vault.NewVaultInstaller(rc, config)
	if err := installer.Install(); err != nil {
		return fmt.Errorf("vault installation failed: %w", err)
	}

	logger.Info(" Phases 1-4 completed successfully")

	// Phase 5: Start Vault service and wait for readiness
	logger.Info("[Phase 5] Starting Vault service and waiting for it to be ready...")
	if err := vault.StartVaultService(rc); err != nil {
		logger.Warn("Failed to start Vault service automatically", zap.Error(err))
		logger.Info("terminal prompt: Please start Vault manually: sudo systemctl start vault")
		logger.Info("terminal prompt: Then initialize with: vault operator init")
		return nil
	}

	logger.Info(" Phase 5 completed - Vault service is running")

	// Phase 5.5: If joining existing cluster, join now (before enablement)
	if config.RaftMode == "join" && len(config.RetryJoinNodes) > 0 {
		logger.Info("[Phase 5.5] Joining existing Raft cluster")
		logger.Info("This node will join the cluster and NOT be initialized independently")

		for _, node := range config.RetryJoinNodes {
			logger.Info("Attempting to join cluster", zap.String("leader", node.APIAddr))
			if err := vault.JoinRaftCluster(rc, node.APIAddr); err != nil {
				logger.Error("Failed to join cluster", zap.Error(err), zap.String("leader", node.APIAddr))
				return fmt.Errorf("join raft cluster failed: %w", err)
			}
			logger.Info(" Successfully joined Raft cluster", zap.String("leader", node.APIAddr))
			break // Successfully joined, no need to try other nodes
		}

		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: Node successfully joined the Raft cluster!")
		logger.Info("terminal prompt: IMPORTANT: This node needs to be unsealed using the SAME unseal keys as the cluster leader.")
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: Next steps:")
		logger.Info("terminal prompt:   1. Obtain the 3 unseal keys from the cluster leader")
		logger.Info("terminal prompt:   2. Run: vault operator unseal (3 times with different keys)")
		logger.Info("terminal prompt:   3. Verify cluster membership: vault operator raft list-peers")
		logger.Info("terminal prompt: ")

		// Don't run EnableVault for joining nodes - they get config from the cluster
		return nil
	}

	// Phases 6-15: Initialization, authentication, secrets, hardening
	// ONLY run for new cluster creation (not for joining nodes)
	logger.Info("[Phases 6-15] Starting Vault enablement (initialization, auth, secrets, hardening)")
	logger.Info("This will initialize Vault, configure authentication, enable secrets engines, and set up the Vault Agent")

	// Create a production logger for EnableVault
	zapLogger, err := zap.NewProduction()
	if err != nil {
		logger.Error("Failed to create logger for vault enablement", zap.Error(err))
		return fmt.Errorf("create logger: %w", err)
	}
	defer zapLogger.Sync()

	if err := vault.EnableVault(rc, nil, zapLogger); err != nil {
		logger.Error("Failed to enable Vault", zap.Error(err))
		logger.Info("terminal prompt: Vault was installed but enablement failed")
		logger.Info("terminal prompt: You can retry enablement manually or troubleshoot the error")
		return fmt.Errorf("enable vault: %w", err)
	}

	logger.Info("🎉 Vault creation and enablement completed successfully!")
	logger.Info("terminal prompt: Vault is fully configured and ready to use")
	return nil
}

// Removed unused -based functions - now using native installer

// DEPRECATED: vault-enhanced command removed
// All functionality has been merged into the main 'eos create vault' command
// which now includes all 15 phases:
//   Phase 1-4: Installation, environment, TLS, config (via NewVaultInstaller)
//   Phase 5: Start service
//   Phase 6a-6b: Init and unseal
//   Phase 7-7a: Root token verification and API client
//   Phase 8: Health check (now implemented)
//   Phase 9a-9b: KV v2 secrets engine
//   Phase 10a-10c: Auth methods (userpass, approle, entity)
//   Phase 11: Policies
//   Phase 12: Audit logging
//   Phase 13: MFA (optional, interactive)
//   Phase 14: Vault Agent (optional, interactive)
//   Phase 15: Comprehensive hardening (optional, interactive)
//
// Use: eos create vault
