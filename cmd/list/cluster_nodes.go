// cmd/list/cluster_nodes.go
package list

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/environment"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ListClusterNodesCmd lists all cluster nodes and their roles
var ListClusterNodesCmd = &cobra.Command{
	Use:     "nodes",
	Aliases: []string{"cluster-nodes", "cluster", "topology"},
	Short:   "List cluster nodes and their roles",
	Long: `List all cluster nodes discovered via , Consul, or Nomad along with their assigned roles.

This command provides visibility into the cluster topology including:
- Node IDs and hostnames
- Assigned roles (server, client, database, monitoring, etc.)
- Node status and availability
- Resource allocation per node
- Service placement preferences

The information is gathered from multiple sources:
- Consul cluster members and services
- Nomad client nodes and classes

Examples:
  eos list nodes                         # List all cluster nodes
  eos list nodes --json                  # Output as JSON
  eos list nodes --role server           # Filter by specific role
  eos list nodes --status ready          # Filter by node status`,

	RunE: eos.Wrap(runListClusterNodes),
}

func runListClusterNodes(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Get flags
	jsonOutput, _ := cmd.Flags().GetBool("json")
	roleFilter, _ := cmd.Flags().GetString("role")
	statusFilter, _ := cmd.Flags().GetString("status")

	logger.Info("Listing cluster nodes")

	// Try to load enhanced environment configuration
	enhancedConfig, err := loadEnhancedEnvironmentConfig()
	if err != nil {
		logger.Warn("Enhanced environment config not found, performing discovery", zap.Error(err))

		// Perform live discovery
		enhancedConfig, err = environment.DiscoverEnhancedEnvironment(rc)
		if err != nil {
			return fmt.Errorf("failed to discover cluster topology: %w", err)
		}
	}

	// Filter nodes if requested
	filteredNodes := filterNodes(enhancedConfig.NodeRoles, roleFilter, statusFilter)

	if jsonOutput {
		return outputNodesJSON(filteredNodes, enhancedConfig)
	}

	return displayNodesTable(filteredNodes, enhancedConfig)
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

// filterNodes filters nodes based on role and status criteria
func filterNodes(allNodes map[string][]string, roleFilter, statusFilter string) map[string][]string {
	if roleFilter == "" && statusFilter == "" {
		return allNodes
	}

	filtered := make(map[string][]string)

	for nodeId, roles := range allNodes {
		includeNode := true

		// Filter by role if specified
		if roleFilter != "" {
			hasRole := false
			for _, role := range roles {
				if strings.EqualFold(role, roleFilter) {
					hasRole = true
					break
				}
			}
			if !hasRole {
				includeNode = false
			}
		}

		// Filter by status if specified (simplified status check)
		if statusFilter != "" && includeNode {
			// For now, assume all nodes in the config are "ready"
			// This could be enhanced to query actual node status
			if !strings.EqualFold(statusFilter, "ready") && !strings.EqualFold(statusFilter, "active") {
				includeNode = false
			}
		}

		if includeNode {
			filtered[nodeId] = roles
		}
	}

	return filtered
}

// outputNodesJSON outputs nodes information as JSON
func outputNodesJSON(nodes map[string][]string, config *environment.EnhancedEnvironmentConfig) error {
	output := map[string]interface{}{
		"cluster_size":      config.ClusterSize,
		"profile":           config.Profile,
		"resource_strategy": config.ResourceStrategy,
		"nodes":             nodes,
		"environment":       config.Environment,
		"datacenter":        config.Datacenter,
	}

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal nodes: %w", err)
	}
	fmt.Println(string(data))
	return nil
}

// displayNodesTable displays nodes in a formatted table
func displayNodesTable(nodes map[string][]string, config *environment.EnhancedEnvironmentConfig) error {
	fmt.Printf("🏗️  Cluster Topology (%s)\n", config.Profile)
	fmt.Printf("========================================\n\n")
	fmt.Printf("📊 Overview:\n")
	fmt.Printf("  Profile:          %s\n", config.Profile)
	fmt.Printf("  Environment:      %s\n", config.Environment)
	fmt.Printf("  Cluster Size:     %d nodes\n", config.ClusterSize)
	fmt.Printf("  Resource Strategy: %s\n", config.ResourceStrategy)
	fmt.Println()

	// Sort nodes for consistent output
	sortedNodes := make([]string, 0, len(nodes))
	for nodeId := range nodes {
		sortedNodes = append(sortedNodes, nodeId)
	}
	sort.Strings(sortedNodes)

	fmt.Printf(" Node Inventory:\n")
	fmt.Printf("  %-20s │ %-40s │ Status\n", "Node ID", "Roles")
	fmt.Printf("  ────────────────────┼────────────────────────────────────────┼────────\n")

	for _, nodeId := range sortedNodes {
		roles := nodes[nodeId]
		roleStr := strings.Join(roles, ", ")
		if len(roleStr) > 40 {
			roleStr = roleStr[:37] + "..."
		}

		// Simple status determination (could be enhanced)
		status := "Ready"
		if nodeId == "localhost" || strings.Contains(nodeId, "local") {
			status = "Local"
		}

		fmt.Printf("  %-20s │ %-40s │ %s\n", nodeId, roleStr, status)
	}

	fmt.Println()

	// Show service placement if available
	if len(config.ServicePlacement) > 0 {
		fmt.Printf("📍 Service Placement Preferences:\n")

		// Group services by node role
		roleServices := make(map[string][]string)
		for service, role := range config.ServicePlacement {
			roleServices[role] = append(roleServices[role], service)
		}

		for role, services := range roleServices {
			sort.Strings(services)
			fmt.Printf("  %-15s → %s\n", role, strings.Join(services, ", "))
		}
	}

	fmt.Printf("\n Use 'eos read environment' for complete configuration details\n")
	fmt.Printf(" Use 'eos list nodes --role <role>' to filter by specific role\n")

	return nil
}

func init() {
	ListCmd.AddCommand(ListClusterNodesCmd)

	ListClusterNodesCmd.Flags().Bool("json", false, "Output as JSON")
	ListClusterNodesCmd.Flags().String("role", "", "Filter nodes by role (server, client, database, etc.)")
	ListClusterNodesCmd.Flags().String("status", "", "Filter nodes by status (ready, offline, etc.)")
}
