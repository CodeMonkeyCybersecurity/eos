package create

import (
	"context"
	"fmt"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
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
	_ = cmd.Flag("vault-address").Value.String() // Unused in Nomad implementation
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

	// Use Nomad orchestration instead of Salt
	logger.Info("Using Nomad orchestration for HashiCorp stack deployment")

	// Create context with timeout
	ctx, cancel := context.WithTimeout(rc.Ctx, timeout)
	defer cancel()

	logger.Info("Deploying via Nomad orchestration",
		zap.String("component", component),
		zap.String("version", version),
		zap.String("datacenter", datacenter))

	// Prepare Nomad job configuration (replacing Salt pillar)
	nomadConfig := map[string]interface{}{
		component: map[string]interface{}{
			"version":    version,
			"datacenter": datacenter,
		},
	}

	// Component-specific configuration
	switch component {
	case "vault":
		nomadConfig["vault"].(map[string]interface{})["server_mode"] = serverMode
		nomadConfig["vault"].(map[string]interface{})["bootstrap_expect"] = bootstrapExpect
		nomadConfig["vault"].(map[string]interface{})["acl_enabled"] = enableACL
		nomadConfig["vault"].(map[string]interface{})["tls_enabled"] = enableTLS
		if consulAddress != "127.0.0.1:8500" {
			nomadConfig["vault"].(map[string]interface{})["consul_enabled"] = true
			nomadConfig["vault"].(map[string]interface{})["consul_address"] = consulAddress
		}

	case "nomad":
		nomadConfig["nomad"].(map[string]interface{})["server_mode"] = serverMode
		nomadConfig["nomad"].(map[string]interface{})["client_mode"] = clientMode
		nomadConfig["nomad"].(map[string]interface{})["region"] = region
		nomadConfig["nomad"].(map[string]interface{})["bootstrap_expect"] = bootstrapExpect
		nomadConfig["nomad"].(map[string]interface{})["acl_enabled"] = enableACL
	}

	// TODO: Implement Nomad job deployment for HashiCorp components
	_ = nomadConfig
	_ = ctx // TODO: Use context for Nomad API calls
	return fmt.Errorf("%s Nomad deployment not yet implemented", component)
}


func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}