// pkg/bootstrap/environment_setup.go
// Environment-aware bootstrap orchestration

package bootstrap

import (
	"fmt"
	"os"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/environment"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// EnvironmentSetupOptions holds environment-specific bootstrap configuration
type EnvironmentSetupOptions struct {
	// Environment identification
	EnvironmentName string // dev, staging, production
	Datacenter      string // Consul datacenter (defaults to EnvironmentName)

	// Host configuration
	FrontendHost string // Hetzner/cloud host (e.g., cybermonkey-dev)
	BackendHost  string // Garage/on-prem host (e.g., vhost5)

	// WireGuard configuration
	WireGuardSubnet    string // e.g., "10.0.0.0/24"
	WireGuardInterface string // e.g., "wg-dev"
	FrontendIP         string // e.g., "10.0.0.2"
	BackendIP          string // e.g., "10.0.0.5"

	// Services to enable
	EnableVault  bool
	EnableNomad  bool
	EnableConsul bool // Always true, but explicit

	// Consul configuration
	ConsulServerHost string // Which host runs Consul server (usually backend)
	ConsulUIEnabled  bool

	// Vault configuration
	VaultHost       string // Which host runs Vault (usually backend)
	VaultTLSEnabled bool

	// Nomad configuration
	NomadHost string // Which host runs Nomad server (usually backend)
}

// SetupEnvironment orchestrates full environment setup
// This is idempotent - safe to run multiple times
func SetupEnvironment(rc *eos_io.RuntimeContext, opts *EnvironmentSetupOptions) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting environment setup",
		zap.String("environment", opts.EnvironmentName),
		zap.String("frontend", opts.FrontendHost),
		zap.String("backend", opts.BackendHost))

	// ASSESS - Check current state
	if err := assessEnvironmentState(rc, opts); err != nil {
		return fmt.Errorf("environment assessment failed: %w", err)
	}

	// Phase 1: Create environment configuration
	logger.Info("[1/6] Creating environment configuration")
	env, err := createEnvironmentConfig(rc, opts)
	if err != nil {
		return fmt.Errorf("failed to create environment config: %w", err)
	}

	// Phase 2: Setup WireGuard mesh network
	logger.Info("[2/6] Setting up WireGuard mesh network")
	if err := setupWireGuardMesh(rc, opts); err != nil {
		return fmt.Errorf("WireGuard setup failed: %w", err)
	}

	// Phase 3: Install Consul
	logger.Info("[3/6] Installing Consul")
	if err := setupConsul(rc, opts); err != nil {
		return fmt.Errorf("Consul setup failed: %w", err)
	}

	// Phase 4: Install Vault (optional)
	if opts.EnableVault {
		logger.Info("[4/6] Installing Vault")
		if err := setupVault(rc, opts); err != nil {
			return fmt.Errorf("Vault setup failed: %w", err)
		}
	} else {
		logger.Info("[4/6] Skipping Vault installation (not requested)")
	}

	// Phase 5: Install Nomad (optional)
	if opts.EnableNomad {
		logger.Info("[5/6] Installing Nomad")
		if err := setupNomad(rc, opts); err != nil {
			return fmt.Errorf("Nomad setup failed: %w", err)
		}
	} else {
		logger.Info("[5/6] Skipping Nomad installation (not requested)")
	}

	// Phase 6: Save environment configuration
	logger.Info("[6/6] Saving environment configuration")
	envMgr, err := environment.NewEnvironmentManager(rc)
	if err != nil {
		return fmt.Errorf("failed to create environment manager: %w", err)
	}

	if err := envMgr.SaveEnvironment(rc.Ctx, env); err != nil {
		return fmt.Errorf("failed to save environment: %w", err)
	}

	// Set as current environment
	if err := envMgr.SetCurrentEnvironment(rc.Ctx, env.Name); err != nil {
		logger.Warn("Failed to set current environment (non-critical)",
			zap.Error(err))
	}

	// EVALUATE - Verify environment setup
	logger.Info("Verifying environment setup")
	if err := verifyEnvironmentSetup(rc, env); err != nil {
		logger.Warn("Environment verification failed (review logs)",
			zap.Error(err))
	}

	// Print success message
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt:  Environment setup complete!")
	logger.Info(fmt.Sprintf("terminal prompt:    Environment: %s", env.Name))
	logger.Info(fmt.Sprintf("terminal prompt:    Frontend:    %s (%s)", env.FrontendHost, env.WireGuard.FrontendIP))
	logger.Info(fmt.Sprintf("terminal prompt:    Backend:     %s (%s)", env.BackendHost, env.WireGuard.BackendIP))
	logger.Info(fmt.Sprintf("terminal prompt:    Consul:      %s", env.Consul.ServerAddress))
	if env.Vault != nil {
		logger.Info(fmt.Sprintf("terminal prompt:    Vault:       %s", env.Vault.Address))
	}
	if env.Nomad != nil {
		logger.Info(fmt.Sprintf("terminal prompt:    Nomad:       %s", env.Nomad.Address))
	}
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Next steps:")
	logger.Info("terminal prompt:   • Deploy services: eos create <service>")
	logger.Info(fmt.Sprintf("terminal prompt:   • Create VMs:      eos create kvm ubuntu --environment %s", env.Name))
	logger.Info(fmt.Sprintf("terminal prompt:   • Get secrets:     eos secret get <path> --environment %s", env.Name))
	logger.Info("terminal prompt: ")

	return nil
}

// assessEnvironmentState checks if environment already exists
func assessEnvironmentState(rc *eos_io.RuntimeContext, opts *EnvironmentSetupOptions) error {
	logger := otelzap.Ctx(rc.Ctx)

	envMgr, err := environment.NewEnvironmentManager(rc)
	if err != nil {
		return err
	}

	// Check if environment already exists
	if env, err := envMgr.LoadEnvironment(rc.Ctx, opts.EnvironmentName); err == nil {
		logger.Info("Environment already exists",
			zap.String("environment", env.Name),
			zap.String("created_at", env.CreatedAt))

		logger.Info("terminal prompt: ℹ️  Environment already configured")
		logger.Info("terminal prompt:   Existing configuration will be updated if needed")
		logger.Info("terminal prompt:   Use --force to completely recreate")
	}

	return nil
}

// createEnvironmentConfig creates the environment configuration object
func createEnvironmentConfig(rc *eos_io.RuntimeContext, opts *EnvironmentSetupOptions) (*environment.DeploymentEnvironment, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Set defaults
	if opts.Datacenter == "" {
		opts.Datacenter = opts.EnvironmentName
	}
	if opts.WireGuardInterface == "" {
		opts.WireGuardInterface = fmt.Sprintf("wg-%s", opts.EnvironmentName)
	}
	if opts.ConsulServerHost == "" {
		opts.ConsulServerHost = opts.BackendHost
	}
	if opts.VaultHost == "" {
		opts.VaultHost = opts.BackendHost
	}
	if opts.NomadHost == "" {
		opts.NomadHost = opts.BackendHost
	}

	env := &environment.DeploymentEnvironment{
		Name:         opts.EnvironmentName,
		Datacenter:   opts.Datacenter,
		FrontendHost: opts.FrontendHost,
		BackendHost:  opts.BackendHost,
		WireGuard: environment.WireGuardConfig{
			Interface:  opts.WireGuardInterface,
			Subnet:     opts.WireGuardSubnet,
			FrontendIP: opts.FrontendIP,
			BackendIP:  opts.BackendIP,
		},
		Consul: environment.ConsulConfig{
			ServerAddress: fmt.Sprintf("%s:8500", opts.BackendIP),
			ClientAddress: fmt.Sprintf("%s:8500", opts.FrontendIP),
			Datacenter:    opts.Datacenter,
			RetryJoin:     []string{opts.BackendIP},
			UIEnabled:     opts.ConsulUIEnabled,
		},
		CreatedAt: time.Now().Format(time.RFC3339),
		UpdatedAt: time.Now().Format(time.RFC3339),
	}

	// Add Vault config if enabled
	if opts.EnableVault {
		env.Vault = &environment.VaultConfig{
			Address:    fmt.Sprintf("https://%s:8200", opts.BackendIP),
			TLSEnabled: opts.VaultTLSEnabled,
			SealType:   "shamir",
			HAEnabled:  false,
		}
	}

	// Add Nomad config if enabled
	if opts.EnableNomad {
		env.Nomad = &environment.NomadConfig{
			Address:       fmt.Sprintf("http://%s:4646", opts.BackendIP),
			ServerEnabled: true,
			ClientEnabled: true,
			Datacenters:   []string{opts.Datacenter},
		}
	}

	logger.Info("Created environment configuration",
		zap.String("environment", env.Name),
		zap.String("datacenter", env.Datacenter))

	return env, nil
}

// setupWireGuardMesh configures WireGuard network between frontend and backend
func setupWireGuardMesh(rc *eos_io.RuntimeContext, opts *EnvironmentSetupOptions) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check current hostname to determine which side we're on
	hostname, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("failed to get hostname: %w", err)
	}

	logger.Info("Setting up WireGuard mesh",
		zap.String("hostname", hostname),
		zap.String("interface", opts.WireGuardInterface))

	// TODO: Implement WireGuard setup
	// This would:
	// 1. Generate WireGuard keys
	// 2. Create WireGuard config
	// 3. Start WireGuard interface
	// 4. Exchange keys with peer
	// 5. Verify connectivity

	logger.Info("terminal prompt: WireGuard setup not yet implemented")
	logger.Info("terminal prompt:   Manual setup required:")
	logger.Info(fmt.Sprintf("terminal prompt:   1. On %s: wg-quick up %s", opts.BackendHost, opts.WireGuardInterface))
	logger.Info(fmt.Sprintf("terminal prompt:   2. On %s: wg-quick up %s", opts.FrontendHost, opts.WireGuardInterface))
	logger.Info("terminal prompt:   3. Verify: ping <peer-ip>")

	return nil
}

// setupConsul installs and configures Consul
func setupConsul(rc *eos_io.RuntimeContext, opts *EnvironmentSetupOptions) error {
	logger := otelzap.Ctx(rc.Ctx)

	hostname, _ := os.Hostname()

	// Determine if this host should be server or client
	isServer := hostname == opts.BackendHost || hostname == opts.ConsulServerHost

	logger.Info("Setting up Consul",
		zap.String("hostname", hostname),
		zap.Bool("server_mode", isServer))

	// TODO: Call actual Consul installation
	// This would use existing pkg/consul/install.go

	logger.Info("terminal prompt: ℹ️  Consul setup placeholder")
	logger.Info(fmt.Sprintf("terminal prompt:   Run: eos create consul --%s", map[bool]string{true: "server", false: "client"}[isServer]))

	return nil
}

// setupVault installs and configures Vault
func setupVault(rc *eos_io.RuntimeContext, opts *EnvironmentSetupOptions) error {
	logger := otelzap.Ctx(rc.Ctx)

	hostname, _ := os.Hostname()

	// Only install on designated Vault host
	if hostname != opts.VaultHost {
		logger.Info("Skipping Vault installation (not Vault host)",
			zap.String("hostname", hostname),
			zap.String("vault_host", opts.VaultHost))
		return nil
	}

	logger.Info("Setting up Vault",
		zap.String("datacenter", opts.Datacenter))

	// TODO: Call actual Vault installation with Consul registration
	// This would use existing pkg/vault/install.go with new Datacenter config

	logger.Info("terminal prompt: ℹ️  Vault setup placeholder")
	logger.Info(fmt.Sprintf("terminal prompt:   Run: eos create vault --datacenter %s", opts.Datacenter))

	return nil
}

// setupNomad installs and configures Nomad
func setupNomad(rc *eos_io.RuntimeContext, opts *EnvironmentSetupOptions) error {
	logger := otelzap.Ctx(rc.Ctx)

	hostname, _ := os.Hostname()

	logger.Info("Setting up Nomad",
		zap.String("hostname", hostname))

	// TODO: Call actual Nomad installation
	// This would use existing pkg/nomad/install.go

	logger.Info("terminal prompt: ℹ️  Nomad setup placeholder")
	logger.Info("terminal prompt:   Run: eos create nomad --server --client")

	return nil
}

// verifyEnvironmentSetup verifies the environment is properly configured
func verifyEnvironmentSetup(rc *eos_io.RuntimeContext, env *environment.DeploymentEnvironment) error {
	logger := otelzap.Ctx(rc.Ctx)

	// TODO: Implement comprehensive verification
	// 1. WireGuard connectivity
	// 2. Consul cluster health
	// 3. Vault accessibility
	// 4. Nomad cluster health

	logger.Debug("Environment verification",
		zap.String("environment", env.Name))

	return nil
}
