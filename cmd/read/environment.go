// cmd/read/environment.go
package read

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/environment"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ReadEnvironmentCmd displays current environment configuration and topology
var ReadEnvironmentCmd = &cobra.Command{
	Use:   "environment",
	Short: "Display current environment configuration and cluster topology",
	Long: `Display comprehensive information about the current environment including:
- Environment profile (development, single-node, homelab, small-cluster, enterprise, cloud)
- Cluster topology and node roles
- Namespace configuration  
- Resource allocation strategy
- Service placement preferences
- Discovered vs configured settings

This command reads the environment configuration discovered by , Consul,
and Nomad to provide a complete picture of the deployment architecture.

Examples:
  eos read environment                    # Display environment overview
  eos read environment --json            # Output as JSON
  eos read environment --topology        # Focus on cluster topology
  eos read environment --services        # Show service placement details`,

	RunE: eos.Wrap(runReadEnvironment),
}

func runReadEnvironment(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Get flags
	jsonOutput, _ := cmd.Flags().GetBool("json")
	topologyFocus, _ := cmd.Flags().GetBool("topology")
	servicesFocus, _ := cmd.Flags().GetBool("services")

	logger.Info("Reading environment configuration")

	// Try to load enhanced environment configuration first
	enhancedConfig, err := loadEnhancedEnvironmentConfig()
	if err != nil {
		logger.Warn("Enhanced environment config not found, using basic config", zap.Error(err))
		return displayBasicEnvironment(rc, cmd, jsonOutput)
	}

	if jsonOutput {
		return outputEnvironmentJSON(enhancedConfig)
	}

	if topologyFocus {
		return displayTopologyFocus(enhancedConfig)
	}

	if servicesFocus {
		return displayServicesFocus(enhancedConfig)
	}

	return displayFullEnvironment(enhancedConfig)
}

// loadEnhancedEnvironmentConfig loads the enhanced environment configuration
func loadEnhancedEnvironmentConfig() (*environment.EnhancedEnvironmentConfig, error) {
	configPath := "/opt/eos/config/enhanced_environment.json"

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("enhanced environment config not found")
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read enhanced config: %w", err)
	}

	var config environment.EnhancedEnvironmentConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse enhanced config: %w", err)
	}

	return &config, nil
}

// displayBasicEnvironment displays basic environment information
func displayBasicEnvironment(rc *eos_io.RuntimeContext, _ *cobra.Command, jsonOutput bool) error {
	// Fallback to basic discovery
	basicConfig, err := environment.DiscoverEnvironment(rc)
	if err != nil {
		return fmt.Errorf("failed to discover environment: %w", err)
	}

	if jsonOutput {
		data, err := json.MarshalIndent(basicConfig, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal config: %w", err)
		}
		fmt.Println(string(data))
		return nil
	}

	// Display basic environment info
	fmt.Printf(" Environment Configuration (Basic Mode)\n")
	fmt.Printf("========================================\n\n")
	fmt.Printf("Environment:     %s\n", basicConfig.Environment)
	fmt.Printf("Datacenter:      %s\n", basicConfig.Datacenter)
	fmt.Printf("Region:          %s\n", basicConfig.Region)
	fmt.Printf("Node Role:       %s\n", basicConfig.NodeRole)
	fmt.Printf("Secret Backend:  %s\n", "Vault")

	if len(basicConfig.ClusterNodes) > 0 {
		fmt.Printf("\nCluster Nodes:   %v\n", basicConfig.ClusterNodes)
	}

	return nil
}

// outputEnvironmentJSON outputs the environment configuration as JSON
func outputEnvironmentJSON(config *environment.EnhancedEnvironmentConfig) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	fmt.Println(string(data))
	return nil
}

// displayTopologyFocus displays cluster topology information
func displayTopologyFocus(config *environment.EnhancedEnvironmentConfig) error {
	fmt.Printf("🏗️  Cluster Topology\n")
	fmt.Printf("==================\n\n")
	fmt.Printf("Profile:         %s\n", config.Profile)
	fmt.Printf("Cluster Size:    %d nodes\n", config.ClusterSize)
	fmt.Printf("Environment:     %s\n", config.Environment)
	fmt.Printf("Datacenter:      %s\n", config.Datacenter)
	fmt.Printf("Resource Strategy: %s\n", config.ResourceStrategy)

	fmt.Printf("\n Node Inventory:\n")
	for nodeId, roles := range config.NodeRoles {
		fmt.Printf("  ├─ %-15s → %v\n", nodeId, roles)
	}

	fmt.Printf("\n🏷️  Namespace Configuration:\n")
	fmt.Printf("  Primary:       %s\n", config.Namespaces.Primary)
	fmt.Printf("  Secondary:     %v\n", config.Namespaces.Secondary)
	fmt.Printf("  Admin Separate: %t\n", config.Namespaces.Admin)

	return nil
}

// displayServicesFocus displays service placement information
func displayServicesFocus(config *environment.EnhancedEnvironmentConfig) error {
	fmt.Printf(" Service Placement\n")
	fmt.Printf("===================\n\n")
	fmt.Printf("Profile:         %s\n", config.Profile)
	fmt.Printf("Resource Strategy: %s\n", config.ResourceStrategy)

	fmt.Printf("\n📍 Service → Node Role Mapping:\n")
	for service, nodeRole := range config.ServicePlacement {
		fmt.Printf("  ├─ %-12s → %s\n", service, nodeRole)
	}

	fmt.Printf("\n Resource Allocation by Environment:\n")
	for env, resources := range config.Services.Resources {
		fmt.Printf("  %s:\n", env)
		fmt.Printf("    CPU:         %d MHz\n", resources.CPU)
		fmt.Printf("    Memory:      %d MB\n", resources.Memory)
		fmt.Printf("    Replicas:    %d (max: %d)\n", resources.Replicas, resources.MaxReplicas)
		fmt.Println()
	}

	fmt.Printf(" Default Service Ports:\n")
	for service, port := range config.Services.DefaultPorts {
		fmt.Printf("  ├─ %-12s → :%d\n", service, port)
	}

	return nil
}

// displayFullEnvironment displays complete environment information
func displayFullEnvironment(config *environment.EnhancedEnvironmentConfig) error {
	fmt.Printf(" Enhanced Environment Configuration\n")
	fmt.Printf("====================================\n\n")

	// Profile and basic info
	fmt.Printf(" Deployment Profile: %s\n", config.Profile)
	fmt.Printf(" Environment:        %s\n", config.Environment)
	fmt.Printf(" Datacenter:         %s\n", config.Datacenter)
	fmt.Printf("🌎 Region:             %s\n", config.Region)
	fmt.Printf(" Cluster Size:       %d nodes\n", config.ClusterSize)
	fmt.Printf("  Resource Strategy:  %s\n", config.ResourceStrategy)

	// Node topology
	fmt.Printf("\n🏗️  Cluster Topology:\n")
	for nodeId, roles := range config.NodeRoles {
		fmt.Printf("  ├─ %-15s → %v\n", nodeId, roles)
	}

	// Namespaces
	fmt.Printf("\n🏷️  Namespace Configuration:\n")
	fmt.Printf("  Primary:       %s\n", config.Namespaces.Primary)
	fmt.Printf("  Secondary:     %v\n", config.Namespaces.Secondary)
	fmt.Printf("  Admin Separate: %t\n", config.Namespaces.Admin)

	// Resource allocation
	fmt.Printf("\n Resource Allocation:\n")
	for env, resources := range config.Services.Resources {
		fmt.Printf("  %s: %dMHz CPU, %dMB RAM, %d replica(s)\n",
			env, resources.CPU, resources.Memory, resources.Replicas)
	}

	// Secret management
	fmt.Printf("\n🔐 Secret Management:\n")
	fmt.Printf("  Backend:       %s\n", config.SecretBackend)
	if config.VaultAddr != "" {
		fmt.Printf("  Vault Address: %s\n", config.VaultAddr)
	}

	// Service placement
	fmt.Printf("\n📍 Service Placement Preferences:\n")
	for service, nodeRole := range config.ServicePlacement {
		fmt.Printf("  ├─ %-12s → %s role\n", service, nodeRole)
	}

	fmt.Printf("\n Use 'eos read environment --topology' for cluster details")
	fmt.Printf("\n Use 'eos read environment --services' for service details")
	fmt.Printf("\n Use 'eos read environment --json' for machine-readable output\n")

	return nil
}

func init() {
	ReadCmd.AddCommand(ReadEnvironmentCmd)

	ReadEnvironmentCmd.Flags().Bool("json", false, "Output as JSON")
	ReadEnvironmentCmd.Flags().Bool("topology", false, "Focus on cluster topology")
	ReadEnvironmentCmd.Flags().Bool("services", false, "Focus on service placement")
}
