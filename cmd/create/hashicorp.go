package create

import (
	"context"
	"fmt"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/saltstack"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var hashicorpCmd = &cobra.Command{
	Use:   "hashicorp [component]",
	Short: "Install HashiCorp tools via Salt states",
	Long: `Install HashiCorp tools using Salt states for configuration management.

This command uses Salt states to install and configure HashiCorp tools following
the architectural principle that Salt manages all physical infrastructure.

Available components:
  vault  - HashiCorp Vault for secrets management
  nomad  - HashiCorp Nomad for container orchestration
  
Examples:
  eos create hashicorp vault                    # Install Vault
  eos create hashicorp nomad                    # Install Nomad
  eos create hashicorp vault --server-mode     # Install Vault in server mode
  eos create hashicorp nomad --client-only     # Install Nomad in client-only mode`,
	Args: cobra.ExactArgs(1),
	RunE: eos.Wrap(runHashicorp),
}

func init() {
	hashicorpCmd.Flags().Bool("server-mode", true, "Install in server mode")
	hashicorpCmd.Flags().Bool("client-mode", true, "Install in client mode")
	hashicorpCmd.Flags().Bool("client-only", false, "Install in client-only mode (disables server)")
	hashicorpCmd.Flags().String("datacenter", "dc1", "Datacenter name")
	hashicorpCmd.Flags().String("region", "global", "Region name (Nomad only)")
	hashicorpCmd.Flags().String("version", "latest", "Version to install")
	hashicorpCmd.Flags().Int("bootstrap-expect", 1, "Number of servers to expect for bootstrap")
	hashicorpCmd.Flags().Bool("enable-acl", false, "Enable ACL system")
	hashicorpCmd.Flags().Bool("enable-tls", false, "Enable TLS encryption")
	hashicorpCmd.Flags().String("consul-address", "127.0.0.1:8500", "Consul address for integration")
	hashicorpCmd.Flags().String("vault-address", "https://127.0.0.1:8200", "Vault address for integration")
	hashicorpCmd.Flags().Duration("timeout", 300*time.Second, "Installation timeout")
	hashicorpCmd.Flags().Bool("test", false, "Test mode - show what would be installed")

	CreateCmd.AddCommand(hashicorpCmd)
}

func runHashicorp(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	component := args[0]

	// Parse flags
	serverMode, _ := cmd.Flags().GetBool("server-mode")
	clientMode, _ := cmd.Flags().GetBool("client-mode")
	clientOnly, _ := cmd.Flags().GetBool("client-only")
	datacenter, _ := cmd.Flags().GetString("datacenter")
	region, _ := cmd.Flags().GetString("region")
	version, _ := cmd.Flags().GetString("version")
	bootstrapExpect, _ := cmd.Flags().GetInt("bootstrap-expect")
	enableACL, _ := cmd.Flags().GetBool("enable-acl")
	enableTLS, _ := cmd.Flags().GetBool("enable-tls")
	consulAddress, _ := cmd.Flags().GetString("consul-address")
	vaultAddress, _ := cmd.Flags().GetString("vault-address")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	testMode, _ := cmd.Flags().GetBool("test")

	// Handle client-only mode
	if clientOnly {
		serverMode = false
		clientMode = true
	}

	logger.Info("Installing HashiCorp component via Salt",
		zap.String("component", component),
		zap.Bool("server_mode", serverMode),
		zap.Bool("client_mode", clientMode),
		zap.String("datacenter", datacenter),
		zap.String("version", version),
		zap.Bool("test_mode", testMode))

	if testMode {
		logger.Info("terminal prompt: DRY RUN: Would install HashiCorp component")
		logger.Info(fmt.Sprintf("terminal prompt:   Component: %s", component))
		logger.Info(fmt.Sprintf("terminal prompt:   Server mode: %v", serverMode))
		logger.Info(fmt.Sprintf("terminal prompt:   Client mode: %v", clientMode))
		logger.Info(fmt.Sprintf("terminal prompt:   Datacenter: %s", datacenter))
		logger.Info(fmt.Sprintf("terminal prompt:   Version: %s", version))
		return nil
	}

	// Validate component
	validComponents := []string{"vault", "nomad"}
	if !contains(validComponents, component) {
		return fmt.Errorf("invalid component '%s'. Valid components: %v", component, validComponents)
	}

	// Create Salt client
	saltClient := saltstack.NewClient(logger)

	// Create context with timeout
	ctx, cancel := context.WithTimeout(rc.Ctx, timeout)
	defer cancel()

	// Prepare pillar data
	pillarData := map[string]interface{}{
		component: map[string]interface{}{
			"version":    version,
			"datacenter": datacenter,
		},
	}

	// Component-specific configuration
	switch component {
	case "vault":
		pillarData["vault"].(map[string]interface{})["server_mode"] = serverMode
		pillarData["vault"].(map[string]interface{})["bootstrap_expect"] = bootstrapExpect
		pillarData["vault"].(map[string]interface{})["acl_enabled"] = enableACL
		pillarData["vault"].(map[string]interface{})["tls_enabled"] = enableTLS
		if consulAddress != "127.0.0.1:8500" {
			pillarData["vault"].(map[string]interface{})["consul_enabled"] = true
			pillarData["vault"].(map[string]interface{})["consul_address"] = consulAddress
		}

	case "nomad":
		pillarData["nomad"].(map[string]interface{})["server_mode"] = serverMode
		pillarData["nomad"].(map[string]interface{})["client_mode"] = clientMode
		pillarData["nomad"].(map[string]interface{})["region"] = region
		pillarData["nomad"].(map[string]interface{})["bootstrap_expect"] = bootstrapExpect
		pillarData["nomad"].(map[string]interface{})["acl_enabled"] = enableACL
		pillarData["nomad"].(map[string]interface{})["tls_enabled"] = enableTLS
		if consulAddress != "127.0.0.1:8500" {
			pillarData["nomad"].(map[string]interface{})["consul_enabled"] = true
			pillarData["nomad"].(map[string]interface{})["consul_address"] = consulAddress
		}
		if vaultAddress != "https://127.0.0.1:8200" {
			pillarData["nomad"].(map[string]interface{})["vault_enabled"] = true
			pillarData["nomad"].(map[string]interface{})["vault_address"] = vaultAddress
		}
	}

	// Apply Salt state
	logger.Info("Applying Salt state", zap.String("state", fmt.Sprintf("hashicorp.%s", component)))
	
	// Use salt-call for masterless mode
	stateName := fmt.Sprintf("hashicorp.%s", component)
	err := saltClient.StateApplyLocal(ctx, stateName, pillarData)
	if err != nil {
		logger.Error("Salt state application failed",
			zap.String("state", stateName),
			zap.Error(err))
		return fmt.Errorf("failed to apply Salt state %s: %w", stateName, err)
	}

	logger.Info("HashiCorp component installed successfully",
		zap.String("component", component),
		zap.String("state", stateName))

	// Verify installation
	if err := verifyHashicorpInstallation(ctx, saltClient, component); err != nil {
		logger.Warn("Installation verification failed", zap.Error(err))
		return fmt.Errorf("installation verification failed: %w", err)
	}

	logger.Info("HashiCorp component installation completed successfully",
		zap.String("component", component))

	return nil
}

func verifyHashicorpInstallation(ctx context.Context, saltClient *saltstack.Client, component string) error {
	logger := otelzap.Ctx(ctx)
	logger.Info("Verifying installation", zap.String("component", component))

	// Check if binary is available
	binaryCheck := fmt.Sprintf("which %s", component)
	result, err := saltClient.CmdRunLocal(ctx, binaryCheck)
	if err != nil {
		return fmt.Errorf("binary check failed: %w", err)
	}

	logger.Info("Binary check passed", 
		zap.String("component", component),
		zap.Any("result", result))

	// Check if service is running
	serviceCheck := fmt.Sprintf("systemctl is-active %s", component)
	result, err = saltClient.CmdRunLocal(ctx, serviceCheck)
	if err != nil {
		logger.Warn("Service check failed", zap.Error(err))
		// Don't fail here as service might not be started yet
	} else {
		logger.Info("Service check passed", 
			zap.String("component", component),
			zap.Any("result", result))
	}

	return nil
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}