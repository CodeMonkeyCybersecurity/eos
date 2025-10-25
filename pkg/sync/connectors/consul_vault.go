// Package connectors provides service connector implementations
package connectors

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	consulapi "github.com/hashicorp/consul/api"
	vaultapi "github.com/hashicorp/vault/api"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul/acl"
	consulconfig "github.com/CodeMonkeyCybersecurity/eos/pkg/consul/config"
	consulenv "github.com/CodeMonkeyCybersecurity/eos/pkg/consul/environment"
	consulsecrets "github.com/CodeMonkeyCybersecurity/eos/pkg/consul/secrets"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/prompt"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/synctypes"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ConsulVaultConnector implements bidirectional Consul ↔ Vault integration
type ConsulVaultConnector struct{}

// NewConsulVaultConnector creates a new Consul-Vault connector
func NewConsulVaultConnector() *ConsulVaultConnector {
	return &ConsulVaultConnector{}
}

// Name returns the connector name
func (c *ConsulVaultConnector) Name() string {
	return "ConsulVaultConnector"
}

// Description returns a human-readable description
func (c *ConsulVaultConnector) Description() string {
	return "Connects Consul and Vault: enables Vault Consul secrets engine for dynamic Consul ACL token generation and registers Vault in Consul service catalog"
}

// ServicePair returns the normalized service pair identifier
func (c *ConsulVaultConnector) ServicePair() string {
	return "consul-vault"
}

// PreflightCheck verifies both services are installed and running
func (c *ConsulVaultConnector) PreflightCheck(rc *eos_io.RuntimeContext, config *synctypes.SyncConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("[ASSESS] Pre-operation environment scan",
		zap.String("phase", "preflight"),
		zap.String("operation_type", "consul_vault_sync"),
		zap.String("connector", c.Name()))

	// Check Consul status
	logger.Info("[ASSESS] Checking Consul service state")
	consulStatus, err := consul.CheckStatus(rc)
	if err != nil {
		return fmt.Errorf("failed to check Consul status: %w", err)
	}

	if !consulStatus.Installed {
		return eos_err.NewUserError(
			"Consul is not installed. Please install Consul first:\n" +
				"  sudo eos create consul")
	}

	if !consulStatus.Running {
		return eos_err.NewUserError(
			"Consul is not running. Please start Consul:\n" +
				"  sudo systemctl start consul")
	}

	logger.Info("[ASSESS] Consul service state verified",
		zap.String("version", consulStatus.Version),
		zap.String("status", consulStatus.ServiceStatus),
		zap.Bool("installed", consulStatus.Installed),
		zap.Bool("running", consulStatus.Running))

	// CRITICAL: Check if Consul ACLs are enabled (required for Vault integration)
	// This fast-fail check prevents attempting ACL bootstrap on disabled ACL system
	logger.Debug("Checking if Consul ACLs are enabled")

	aclsEnabled, err := acl.DetectACLMode(rc.Ctx)
	if err != nil {
		logger.Warn("Could not detect Consul ACL mode (may indicate configuration issues)",
			zap.Error(err))
		// Continue - will fail with better error during bootstrap attempt
	} else if !aclsEnabled {
		// ACLs are disabled - offer to enable them automatically
		logger.Warn("Consul ACLs are disabled",
			zap.String("config_file", consul.ConsulConfigFile))

		// If --force flag is set, enable ACLs automatically without prompting
		// Otherwise, prompt the user for consent
		autoEnable := config.Force

		if !config.Force {
			logger.Info("terminal prompt: ")
			logger.Info("terminal prompt: Consul ACLs are currently DISABLED")
			logger.Info("terminal prompt: ")
			logger.Info("terminal prompt: Vault-Consul integration requires ACLs to be enabled for secure")
			logger.Info("terminal prompt: token management and access control.")
			logger.Info("terminal prompt: ")
			logger.Info("terminal prompt: This operation will:")
			logger.Info("terminal prompt:   1. Backup current configuration to /etc/consul.d/consul.hcl.backup.TIMESTAMP")
			logger.Info("terminal prompt:   2. Modify /etc/consul.d/consul.hcl to enable ACLs")
			logger.Info("terminal prompt:   3. Restart Consul service (brief downtime)")
			logger.Info("terminal prompt:   4. Continue with Vault-Consul sync")
			logger.Info("terminal prompt: ")

			proceed, err := prompt.YesNo(rc, "Enable Consul ACLs automatically?", false)
			if err != nil {
				return fmt.Errorf("failed to get user input: %w", err)
			}
			autoEnable = proceed
		}

		if !autoEnable {
			// User declined auto-enablement - provide manual instructions
			return eos_err.NewUserError(
				"Consul ACLs are not enabled\n\n" +
					"Vault-Consul integration requires Consul ACLs to be enabled for secure\n" +
					"token management and access control.\n\n" +
					"Current configuration: acl { enabled = false }\n" +
					"Required configuration: acl { enabled = true }\n\n" +
					"MANUAL REMEDIATION STEPS:\n\n" +
					"  1. Edit Consul configuration:\n" +
					"       sudo nano /etc/consul.d/consul.hcl\n\n" +
					"  2. Change the ACL block to:\n" +
					"       acl {\n" +
					"         enabled = true\n" +
					"         default_policy = \"deny\"  # Recommended for security\n" +
					"         enable_token_persistence = true\n" +
					"       }\n\n" +
					"  3. Restart Consul to apply changes:\n" +
					"       sudo systemctl restart consul\n\n" +
					"  4. Verify Consul is healthy:\n" +
					"       consul members\n\n" +
					"  5. Retry this command:\n" +
					"       sudo eos sync --vault --consul\n\n" +
					"Or run with --force to enable ACLs automatically:\n" +
					"  sudo eos sync --vault --consul --force\n\n" +
					"Documentation:\n" +
					"  https://developer.hashicorp.com/consul/docs/security/acl")
		}

		// Auto-enable ACLs
		logger.Info("Enabling Consul ACLs automatically")

		aclConfig := &consulconfig.ACLEnablementConfig{
			ConfigPath:     consul.ConsulConfigFile,
			BackupEnabled:  true,
			ValidateSyntax: true,
			DefaultPolicy:  "deny", // More secure default
		}

		result, err := consulconfig.EnableACLsInConfig(rc, aclConfig)
		if err != nil {
			return fmt.Errorf("failed to enable ACLs in Consul configuration: %w\n\n"+
				"Remediation: Enable ACLs manually following the steps above", err)
		}

		logger.Info("ACL configuration updated",
			zap.Bool("config_changed", result.ConfigChanged),
			zap.String("backup_path", result.BackupPath))

		// Restart Consul service
		logger.Info("Restarting Consul service to apply ACL configuration...")

		if err := consulconfig.RestartConsulService(rc); err != nil {
			// Restart failed - restore backup
			logger.Error("Consul restart failed after ACL enablement",
				zap.Error(err))

			return fmt.Errorf("failed to restart Consul after enabling ACLs: %w\n\n"+
				"Your original configuration has been backed up to: %s\n"+
				"To restore manually:\n"+
				"  sudo cp %s %s\n"+
				"  sudo systemctl restart consul",
				err, result.BackupPath, result.BackupPath, consul.ConsulConfigFile)
		}

		logger.Info("Consul service restarted successfully with ACLs enabled")
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: ✓ Consul ACLs enabled successfully")
		logger.Info("terminal prompt: ")
	}

	logger.Info("Consul ACLs are enabled")

	// Check Vault status
	logger.Debug("Checking Vault status")

	// Check if Vault binary exists
	vaultBinary, err := exec.LookPath("vault")
	if err != nil {
		return eos_err.NewUserError(
			"Vault is not installed. Please install Vault first:\n" +
				"  sudo eos create vault")
	}
	logger.Debug("Vault binary found", zap.String("path", vaultBinary))

	// Check if Vault service exists and is running
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"is-active", "vault"},
		Capture: true,
	})

	vaultRunning := (err == nil && strings.TrimSpace(output) == "active")
	if !vaultRunning {
		return eos_err.NewUserError(
			"Vault is not running. Please start Vault:\n" +
				"  sudo systemctl start vault")
	}

	// CRITICAL: Check Vault seal status BEFORE attempting authentication
	// This unauthenticated check prevents wasting 70+ seconds on futile auth attempts
	logger.Info("[ASSESS] Checking Vault seal status")

	initialized, sealed, err := vault.CheckVaultSealStatusUnauthenticated(rc)
	if err != nil {
		logger.Warn("Could not check Vault seal status", zap.Error(err))
		// Continue - will fail later with clearer error
	} else {
		if !initialized {
			return eos_err.NewUserError(
				"Vault is not initialized. Please initialize Vault first:\n" +
					"  sudo eos init vault")
		}

		if sealed {
			return eos_err.NewUserError(
				"Vault is sealed. Please unseal Vault first:\n" +
					"  vault operator unseal\n\n" +
					"Or use automatic unsealing:\n" +
					"  sudo eos update vault --unseal")
		}

		logger.Info("[ASSESS] Vault service state verified",
			zap.Bool("initialized", initialized),
			zap.Bool("sealed", sealed),
			zap.String("vault_addr", os.Getenv("VAULT_ADDR")))
	}

	logger.Info("[ASSESS] Pre-flight checks completed successfully",
		zap.String("consul_version", consulStatus.Version),
		zap.Bool("consul_running", consulStatus.Running),
		zap.Bool("vault_initialized", initialized),
		zap.Bool("vault_unsealed", !sealed))

	return nil
}

// CheckConnection returns the current connection state
func (c *ConsulVaultConnector) CheckConnection(rc *eos_io.RuntimeContext, config *synctypes.SyncConfig) (*synctypes.SyncState, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Checking Consul-Vault connection state")

	state := &synctypes.SyncState{}

	// ASSESS - Check Consul status
	consulStatus, err := consul.CheckStatus(rc)
	if err != nil {
		return state, fmt.Errorf("failed to check Consul status: %w", err)
	}
	state.Service1Installed = consulStatus.Installed
	state.Service1Running = consulStatus.Running
	state.Service1Healthy = consulStatus.Running && consulStatus.ConfigValid

	// ASSESS - Check Vault status
	vaultBinary, err := exec.LookPath("vault")
	state.Service2Installed = (err == nil && vaultBinary != "")

	if state.Service2Installed {
		output, err := execute.Run(rc.Ctx, execute.Options{
			Command: "systemctl",
			Args:    []string{"is-active", "vault"},
			Capture: true,
		})
		state.Service2Running = (err == nil && strings.TrimSpace(output) == "active")
		state.Service2Healthy = state.Service2Running
	}

	// ASSESS - Check if Vault Consul secrets engine is configured (Pattern 3)
	if !state.Service2Running {
		state.ConfigurationComplete = false
		state.ConfigurationValid = false
		state.Connected = false
		state.Reason = "Vault is not running"
		return state, nil
	}

	// ASSESS - Check Vault seal status BEFORE authentication (fast check)
	// CRITICAL: Prevents wasting 40+ seconds on authentication when Vault is sealed
	initialized, sealed, err := vault.CheckVaultSealStatusUnauthenticated(rc)
	if err != nil {
		logger.Warn("Could not check Vault seal status",
			zap.Error(err))
		state.ConfigurationComplete = false
		state.ConfigurationValid = false
		state.Connected = false
		state.Reason = "Cannot connect to Vault API"
		return state, nil
	}

	if !initialized {
		state.ConfigurationComplete = false
		state.ConfigurationValid = false
		state.Connected = false
		state.Reason = "Vault is not initialized - run: sudo eos init vault"
		return state, nil
	}

	if sealed {
		state.ConfigurationComplete = false
		state.ConfigurationValid = false
		state.Connected = false
		state.Reason = "Vault is sealed - run: vault operator unseal OR sudo eos update vault --unseal"
		return state, nil
	}

	// Get Vault client to check secrets engine configuration (seal check passed)
	vaultClient, err := vault.GetVaultClient(rc)
	if err != nil {
		logger.Warn("Could not get Vault client",
			zap.Error(err))
		state.ConfigurationComplete = false
		state.ConfigurationValid = false
		state.Connected = false
		state.Reason = "Cannot authenticate to Vault"
		return state, nil
	}

	// Check if Consul secrets engine is enabled
	mounts, err := vaultClient.Sys().ListMounts()
	if err != nil {
		logger.Warn("Could not list Vault mounts",
			zap.Error(err))
		state.ConfigurationComplete = false
		state.ConfigurationValid = false
		state.Connected = false
		state.Reason = "Cannot check Vault secrets engines (Vault may be sealed)"
		return state, nil
	}

	hasConsulEngine := false
	if _, exists := mounts["consul/"]; exists {
		hasConsulEngine = true
	}

	// Check if Consul secrets engine is configured
	engineConfigured := false
	if hasConsulEngine {
		secret, err := vaultClient.Logical().Read("consul/config/access")
		if err == nil && secret != nil && secret.Data != nil {
			if addr, ok := secret.Data["address"]; ok && addr != nil {
				engineConfigured = true
			}
		}
	}

	// Check if roles exist
	rolesConfigured := false
	if hasConsulEngine && engineConfigured {
		roles, err := vaultClient.Logical().List("consul/roles")
		if err == nil && roles != nil && roles.Data != nil {
			if keys, ok := roles.Data["keys"].([]interface{}); ok && len(keys) > 0 {
				rolesConfigured = true
			}
		}
	}

	state.ConfigurationComplete = hasConsulEngine && engineConfigured && rolesConfigured
	state.ConfigurationValid = state.ConfigurationComplete
	state.Connected = state.ConfigurationComplete && state.Service1Healthy && state.Service2Healthy

	if state.Connected {
		state.Healthy = true
		state.Reason = "Vault Consul secrets engine enabled and configured"
	} else if !hasConsulEngine {
		state.Reason = "Vault Consul secrets engine not enabled"
	} else if !engineConfigured {
		state.Reason = "Vault Consul secrets engine enabled but not configured"
	} else if !rolesConfigured {
		state.Reason = "Vault Consul secrets engine configured but no roles defined"
	} else {
		state.Reason = "Configuration incomplete or services unhealthy"
	}

	logger.Info("Connection state checked",
		zap.Bool("connected", state.Connected),
		zap.Bool("healthy", state.Healthy),
		zap.String("reason", state.Reason))

	return state, nil
}

// Backup creates backups of service configurations
func (c *ConsulVaultConnector) Backup(rc *eos_io.RuntimeContext, config *synctypes.SyncConfig) (*synctypes.BackupMetadata, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Creating configuration backups")

	// Create backup directory
	timestamp := time.Now().Format("20060102-150405")
	backupDir := filepath.Join("/opt/eos/backups/sync", fmt.Sprintf("consul-vault-%s", timestamp))

	if err := os.MkdirAll(backupDir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create backup directory: %w", err)
	}

	metadata := &synctypes.BackupMetadata{
		BackupDir:   backupDir,
		BackupTime:  timestamp,
		BackupFiles: make(map[string]string),
	}

	// Backup Vault configuration
	vaultConfigPath := vault.VaultConfigPath
	vaultBackupPath := filepath.Join(backupDir, "vault.hcl.backup")

	if err := copyFile(vaultConfigPath, vaultBackupPath); err != nil {
		logger.Warn("Could not backup Vault config (may not exist)",
			zap.String("source", vaultConfigPath),
			zap.Error(err))
	} else {
		metadata.BackupFiles[vaultConfigPath] = vaultBackupPath
		metadata.Service2ConfigPath = vaultConfigPath
		logger.Info("Backed up Vault configuration",
			zap.String("backup_path", vaultBackupPath))
	}

	// Note: Consul config typically doesn't need modification for Vault integration
	// But we'll note the path for completeness
	metadata.Service1ConfigPath = consul.ConsulConfigFile

	logger.Info("Configuration backup completed",
		zap.String("backup_dir", backupDir),
		zap.Int("files_backed_up", len(metadata.BackupFiles)))

	return metadata, nil
}

// Connect establishes the connection between Consul and Vault (Pattern 3: Consul Secrets Engine)
func (c *ConsulVaultConnector) Connect(rc *eos_io.RuntimeContext, config *synctypes.SyncConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Connecting Consul and Vault (Pattern 3: Consul Secrets Engine)")

	// ASSESS - Get Consul client (no auth required)
	logger.Info(" [ASSESS] Connecting to Consul")

	consulConfig := consulapi.DefaultConfig()
	consulConfig.Address = shared.GetConsulHostPort()
	consulClient, err := consulapi.NewClient(consulConfig)
	if err != nil {
		return fmt.Errorf("failed to get Consul client: %w", err)
	}

	// ASSESS - Check Vault seal status BEFORE authentication (unauthenticated check)
	// CRITICAL: Prevents wasting 70+ seconds on authentication when Vault is sealed
	logger.Info(" [ASSESS] Checking Vault status (before authentication)")

	initialized, sealed, err := vault.CheckVaultSealStatusUnauthenticated(rc)
	if err != nil {
		return fmt.Errorf("failed to check Vault seal status: %w", err)
	}

	if !initialized {
		return eos_err.NewUserError("Vault must be initialized first:\n" +
			"  sudo eos init vault")
	}

	if sealed {
		return eos_err.NewUserError("Vault is sealed - unseal it first:\n" +
			"  vault operator unseal\n\n" +
			"Or use automatic unsealing:\n" +
			"  sudo eos update vault --unseal")
	}

	logger.Info("Vault is initialized and unsealed")

	// NOW get authenticated Vault client (seal check passed)
	logger.Info(" [ASSESS] Connecting to Vault (authenticated)")

	vaultClient, err := vault.GetVaultClient(rc)
	if err != nil {
		return fmt.Errorf("failed to get authenticated Vault client: %w", err)
	}

	// SAFETY CHECK: Warn if Vault is using Consul storage (Pattern 1)
	vaultConfigPath := vault.VaultConfigPath
	configContent, err := os.ReadFile(vaultConfigPath)
	if err == nil {
		configStr := string(configContent)
		if strings.Contains(configStr, `storage "consul"`) {
			logger.Warn("NOTICE: Vault is using Consul storage backend (Pattern 1)")
			logger.Warn("This command configures Consul SECRETS ENGINE (Pattern 3), not storage")
			logger.Warn("Your existing Consul storage configuration will NOT be modified")
			logger.Warn("Both patterns can coexist, but you may want to migrate storage to Raft")
			logger.Warn("For more info: https://developer.hashicorp.com/vault/docs/commands/operator/migrate")

			if !config.Force {
				proceed, err := prompt.YesNo(rc, "Continue with Consul secrets engine setup?", false)
				if err != nil || !proceed {
					return eos_err.NewUserError("Operation cancelled by user")
				}
			}
		}
	}

	// Discover environment from Consul (required for Vault paths)
	env, err := consulenv.DiscoverFromConsul(rc)
	if err != nil {
		return fmt.Errorf("failed to discover environment: %w\n\n"+
			"Consul-Vault integration requires knowing the environment.\n"+
			"Consul is the authoritative source for environment configuration.\n\n"+
			"Remediation:\n"+
			"  1. Ensure Consul is running: systemctl status consul\n"+
			"  2. Set environment: eos update consul --environment <env>\n"+
			"  3. Emergency override (Consul unavailable):\n"+
			"     CONSUL_EMERGENCY_OVERRIDE=true eos sync consul vault --environment <env>",
			err)
	}

	logger.Info("Using environment for Vault secret paths",
		zap.String("environment", string(env)))

	// STEP 1: Bootstrap Consul ACLs (if not already done)
	logger.Info(" [STEP 1/7] Bootstrapping Consul ACL system")

	bootstrapResult, err := acl.BootstrapConsulACLs(rc, consulClient, vaultClient, env, true)
	if err != nil {
		return fmt.Errorf("failed to bootstrap Consul ACLs: %w", err)
	}

	masterToken := ""
	if bootstrapResult.AlreadyDone {
		logger.Info("Consul ACLs already bootstrapped, retrieving master token from Vault")
		masterToken, err = acl.GetBootstrapTokenFromVault(rc, vaultClient, env)
		if err != nil {
			// Token not in Vault - need to prompt user for it
			logger.Warn("Bootstrap token not found in Vault, prompting user for recovery",
				zap.Error(err))

			// Use recovery flow: prompt user for token and store it
			recoveryResult, recoveryErr := acl.PromptAndStoreBootstrapToken(rc, vaultClient, env)
			if recoveryErr != nil {
				return fmt.Errorf("failed to recover bootstrap token: %w\n\n"+
					"Consul ACLs are already initialized but the bootstrap token is not in Vault.\n"+
					"You provided an invalid token or cancelled the operation.\n\n"+
					"Remediation:\n"+
					"  1. Find your Consul bootstrap token (created during initial 'consul acl bootstrap')\n"+
					"  2. Verify it works: consul acl token read -self -token=<your-token>\n"+
					"  3. Run this command again and provide the correct token when prompted",
					recoveryErr)
			}

			masterToken = recoveryResult.MasterToken
			logger.Info("Bootstrap token recovered and stored in Vault successfully")
		}
	} else {
		masterToken = bootstrapResult.MasterToken
		logger.Info("Consul ACLs bootstrapped successfully",
			zap.String("accessor", bootstrapResult.Accessor))
	}

	// Use master token for subsequent Consul operations
	// Recreate Consul client with master token
	consulConfig.Token = masterToken
	consulClient, err = consulapi.NewClient(consulConfig)
	if err != nil {
		return fmt.Errorf("failed to create Consul client with master token: %w", err)
	}

	// STEP 2: Create Consul ACL policies
	logger.Info(" [STEP 2/7] Creating Consul ACL policies")

	policies, err := acl.CreateDefaultPolicies(rc, consulClient)
	if err != nil {
		return fmt.Errorf("failed to create Consul ACL policies: %w", err)
	}
	logger.Info("Created Consul ACL policies",
		zap.Strings("policies", policies))

	// STEP 3: Create Vault management token in Consul
	logger.Info(" [STEP 3/7] Creating Vault management token in Consul")

	tokenInfo, err := acl.CreateManagementToken(rc, consulClient,
		"Vault Consul Secrets Engine",
		[]string{"vault-mgmt-policy"})
	if err != nil {
		return fmt.Errorf("failed to create Vault management token: %w", err)
	}
	logger.Info("Created Vault management token",
		zap.String("accessor", tokenInfo.Accessor))

	// STEP 4: Enable Vault Consul secrets engine
	logger.Info(" [STEP 4/7] Enabling Vault Consul secrets engine")

	manager := vault.NewConsulSecretsEngineManager(rc, vaultClient, consulClient)

	engineConfig := &vault.ConsulSecretsEngineConfig{
		ConsulAddress: shared.GetConsulHostPort(),
		ConsulScheme:  "http",
		ConsulToken:   tokenInfo.Token,
		Roles:         vault.CreateDefaultConsulRoles(),
		DefaultTTL:    "1h",
		MaxTTL:        "24h",
	}

	if err := manager.EnableConsulSecretsEngine(engineConfig); err != nil {
		return fmt.Errorf("failed to enable Consul secrets engine: %w", err)
	}
	logger.Info("Consul secrets engine enabled and configured")

	// STEP 5: Test dynamic token generation
	logger.Info(" [STEP 5/7] Testing dynamic Consul token generation")

	testToken, err := manager.TestTokenGeneration("eos-role")
	if err != nil {
		return fmt.Errorf("failed to test token generation: %w", err)
	}
	logger.Info("Test token generated successfully",
		zap.String("accessor", testToken.Accessor),
		zap.Duration("ttl", testToken.LeaseDuration))

	// STEP 6: Store Consul gossip encryption key in Vault (if exists)
	logger.Info(" [STEP 6/8] Storing Consul secrets in Vault (gossip key, TLS certs)")

	if err := c.storeConsulSecretsInVault(rc, consulClient, vaultClient); err != nil {
		logger.Warn("Failed to store Consul secrets in Vault",
			zap.Error(err),
			zap.String("note", "This is non-fatal, but recommended for production"))
		// Non-fatal - continue with integration
	}

	// STEP 7: Register Vault in Consul service catalog (if not already registered)
	logger.Info(" [STEP 7/8] Registering Vault in Consul service catalog")

	// Check if Vault service is already registered
	services, _, err := consulClient.Catalog().Service("vault", "", nil)
	if err != nil {
		logger.Warn("Could not check if Vault is registered in Consul",
			zap.Error(err))
	} else if len(services) > 0 {
		logger.Info("Vault already registered in Consul service catalog")
	} else {
		logger.Info("Vault service registration will be handled by vault.hcl service_registration block")
	}

	// STEP 8: Verify end-to-end
	logger.Info(" [STEP 8/8] Verifying integration")

	if err := c.Verify(rc, config); err != nil {
		return fmt.Errorf("integration verification failed: %w", err)
	}

	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: ✓ Consul and Vault connected successfully (Pattern 3)")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Consul secrets engine enabled at: consul/")
	logger.Info("terminal prompt: Available roles:")
	logger.Info("terminal prompt:   - eos-role (1h TTL, eos-policy)")
	logger.Info("terminal prompt:   - service-role (2h TTL, service-policy)")
	logger.Info("terminal prompt:   - readonly-role (8h TTL, readonly-policy)")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Generate dynamic Consul tokens:")
	logger.Info("terminal prompt:   vault read consul/creds/eos-role")
	logger.Info("terminal prompt: ")

	return nil
}

// Verify validates the connection is working correctly (Pattern 3: Consul Secrets Engine)
func (c *ConsulVaultConnector) Verify(rc *eos_io.RuntimeContext, config *synctypes.SyncConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" [EVALUATE] Verifying Consul-Vault connection (Pattern 3)")

	// EVALUATE - Check Vault service is active
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"is-active", vault.VaultServiceName},
		Capture: true,
	})
	if err != nil || strings.TrimSpace(output) != "active" {
		return fmt.Errorf("vault service is not active")
	}
	logger.Info("Vault service is active")

	// EVALUATE - Check Vault seal status (defensive check)
	initialized, sealed, err := vault.CheckVaultSealStatusUnauthenticated(rc)
	if err != nil {
		return fmt.Errorf("failed to check Vault seal status: %w", err)
	}
	if !initialized {
		return fmt.Errorf("vault is not initialized")
	}
	if sealed {
		return fmt.Errorf("vault is sealed")
	}
	logger.Info("Vault is initialized and unsealed")

	// EVALUATE - Verify Vault health (get authenticated client)
	vaultClient, err := vault.GetVaultClient(rc)
	if err != nil {
		return fmt.Errorf("failed to get Vault client: %w", err)
	}

	health, err := vaultClient.Sys().Health()
	if err != nil {
		logger.Warn("Vault health check returned error (may be sealed)", zap.Error(err))
	} else {
		logger.Info("Vault health check passed",
			zap.Bool("initialized", health.Initialized),
			zap.Bool("sealed", health.Sealed))
	}

	// EVALUATE - Check Consul secrets engine is enabled
	mounts, err := vaultClient.Sys().ListMounts()
	if err != nil {
		return fmt.Errorf("failed to list Vault mounts: %w", err)
	}

	if _, exists := mounts["consul/"]; !exists {
		return fmt.Errorf("Consul secrets engine is not enabled")
	}
	logger.Info("Consul secrets engine is enabled")

	// EVALUATE - Check Consul secrets engine is configured
	secret, err := vaultClient.Logical().Read("consul/config/access")
	if err != nil {
		return fmt.Errorf("failed to read Consul secrets engine config: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return fmt.Errorf("Consul secrets engine is not configured")
	}
	logger.Info("Consul secrets engine is configured",
		zap.String("consul_address", secret.Data["address"].(string)))

	// EVALUATE - Check roles exist
	roles, err := vaultClient.Logical().List("consul/roles")
	if err != nil {
		return fmt.Errorf("failed to list Consul roles: %w", err)
	}
	if roles == nil || roles.Data == nil {
		return fmt.Errorf("no Consul roles configured")
	}

	roleKeys, ok := roles.Data["keys"].([]interface{})
	if !ok || len(roleKeys) == 0 {
		return fmt.Errorf("no Consul roles configured")
	}
	logger.Info("Consul roles configured",
		zap.Int("role_count", len(roleKeys)))

	// EVALUATE - Test token generation
	logger.Info("Testing dynamic token generation")

	consulConfig := consulapi.DefaultConfig()
	consulConfig.Address = shared.GetConsulHostPort()
	consulClient, err := consulapi.NewClient(consulConfig)
	if err != nil {
		return fmt.Errorf("failed to get Consul client: %w", err)
	}

	manager := vault.NewConsulSecretsEngineManager(rc, vaultClient, consulClient)
	testToken, err := manager.TestTokenGeneration("eos-role")
	if err != nil {
		return fmt.Errorf("failed to generate test token: %w", err)
	}
	logger.Info("Successfully generated test token",
		zap.String("accessor", testToken.Accessor),
		zap.Duration("ttl", testToken.LeaseDuration))

	logger.Info("Connection verified successfully (Pattern 3)")

	return nil
}

// storeConsulSecretsInVault stores Consul secrets (gossip key, TLS certs) in Vault
//
// This implements HashiCorp best practices for Pattern 3 integration by storing
// Consul-specific secrets in Vault for centralized management and rotation.
//
// Secrets stored:
// 1. Gossip encryption key (if configured in Consul)
// 2. TLS certificates (future enhancement)
//
// Reference: https://developer.hashicorp.com/consul/tutorials/vault-secure/vault-kv-consul-secure-gossip
func (c *ConsulVaultConnector) storeConsulSecretsInVault(
	rc *eos_io.RuntimeContext,
	consulClient *consulapi.Client,
	vaultClient *vaultapi.Client,
) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Migrating Consul secrets to Vault for centralized management")

	// STEP 1: Enable KV v2 engine at consul/ mount (if not already enabled)
	logger.Debug("Ensuring Vault KV v2 engine is enabled for Consul secrets")

	if err := consulsecrets.EnableGossipKeyRotation(rc, vaultClient); err != nil {
		return fmt.Errorf("failed to enable KV engine for Consul secrets: %w", err)
	}

	// STEP 2: Read gossip encryption key from Consul configuration
	logger.Debug("Reading gossip encryption key from Consul configuration")

	// Read Consul config file to extract gossip key
	consulConfigPath := consul.ConsulConfigFile // /etc/consul.d/consul.hcl
	configContent, err := os.ReadFile(consulConfigPath)
	if err != nil {
		return fmt.Errorf("failed to read Consul configuration: %w", err)
	}

	// Parse gossip key from config using regex
	// Match: encrypt = "base64-key-here"
	configStr := string(configContent)
	gossipKeyRegex := regexp.MustCompile(`encrypt\s*=\s*"([^"]+)"`)
	matches := gossipKeyRegex.FindStringSubmatch(configStr)

	if len(matches) < 2 {
		logger.Info("No gossip encryption key found in Consul configuration")
		logger.Info("Gossip encryption is optional but recommended for production")
		logger.Info("To enable: generate key with 'consul keygen' and add to config")
		// Not an error - gossip encryption is optional
		return nil
	}

	gossipKey := matches[1]
	logger.Info("Found gossip encryption key in Consul configuration")

	// Validate key format
	if err := consulsecrets.ValidateGossipKey(gossipKey); err != nil {
		logger.Warn("Gossip key validation failed",
			zap.Error(err),
			zap.String("note", "Key may be invalid or corrupted"))
		return fmt.Errorf("invalid gossip key in Consul config: %w", err)
	}

	// STEP 3: Check if gossip key already exists in Vault
	logger.Debug("Checking if gossip key is already stored in Vault")

	existingKey, err := consulsecrets.GetGossipKeyFromVault(rc.Ctx, vaultClient)
	if err == nil && existingKey != nil {
		// Key already in Vault - check if it matches
		if existingKey.Key == gossipKey {
			logger.Info("Gossip key already stored in Vault and matches Consul config",
				zap.String("vault_path", consulsecrets.GossipKeyVaultPath),
				zap.Int("rotation_index", existingKey.RotationIndex))
			return nil
		}

		// Keys don't match - this is a problem
		logger.Warn("Gossip key in Vault does not match Consul configuration",
			zap.String("note", "This may indicate key rotation or configuration drift"))
		// We'll update the key in Vault to match current Consul config
	}

	// STEP 4: Store gossip key in Vault
	logger.Info("Storing gossip encryption key in Vault")

	metadata := &consulsecrets.GossipKeyMetadata{
		Key:           gossipKey,
		GeneratedAt:   time.Now(),
		GeneratedBy:   "eos sync --vault --consul (migrated from config)",
		RotationDue:   time.Now().Add(consulsecrets.GossipKeyRotationTTL),
		Primary:       true,
		RotationIndex: 1,
		VaultPath:     consulsecrets.GossipKeyVaultPath,
	}

	if err := consulsecrets.StoreGossipKeyInVault(rc, vaultClient, gossipKey, metadata); err != nil {
		return fmt.Errorf("failed to store gossip key in Vault: %w", err)
	}

	logger.Info("Gossip encryption key stored in Vault successfully",
		zap.String("vault_path", consulsecrets.GossipKeyVaultPath),
		zap.Time("rotation_due", metadata.RotationDue))

	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: ✓ Consul gossip encryption key stored in Vault")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Key location: " + consulsecrets.GossipKeyVaultPath)
	logger.Info("terminal prompt: Rotation recommended: " + metadata.RotationDue.Format("2006-01-02"))
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: To enable automatic key rotation:")
	logger.Info("terminal prompt:   1. Configure Consul Template for gossip key retrieval")
	logger.Info("terminal prompt:   2. Set up rotation schedule in Vault")
	logger.Info("terminal prompt:   3. See: https://developer.hashicorp.com/consul/tutorials/vault-secure/vault-kv-consul-secure-gossip")
	logger.Info("terminal prompt: ")

	return nil
}

// Rollback reverts configuration changes using backup metadata
func (c *ConsulVaultConnector) Rollback(rc *eos_io.RuntimeContext, config *synctypes.SyncConfig, backup *synctypes.BackupMetadata) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Rolling back configuration changes",
		zap.String("backup_dir", backup.BackupDir))

	// Restore Vault configuration
	if vaultBackup, exists := backup.BackupFiles[vault.VaultConfigPath]; exists {
		logger.Info("Restoring Vault configuration",
			zap.String("backup", vaultBackup))

		if err := copyFile(vaultBackup, vault.VaultConfigPath); err != nil {
			return fmt.Errorf("failed to restore Vault config: %w", err)
		}

		// Restart Vault to apply restored config
		_, err := execute.Run(rc.Ctx, execute.Options{
			Command: "systemctl",
			Args:    []string{"restart", vault.VaultServiceName},
			Capture: true,
		})
		if err != nil {
			logger.Warn("Failed to restart Vault after rollback", zap.Error(err))
			// Continue with rollback even if restart fails
		}
	}

	logger.Info("Rollback completed")
	return nil
}

// copyFile copies a file from src to dst
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("failed to read source file: %w", err)
	}

	// Use Vault config permission for Vault config files
	if err := os.WriteFile(dst, data, vault.VaultConfigPerm); err != nil {
		return fmt.Errorf("failed to write destination file: %w", err)
	}

	return nil
}
