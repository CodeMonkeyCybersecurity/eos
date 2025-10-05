// cmd/list/consul.go
// List Consul cluster resources

package list

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

var (
	consulListServices bool
	consulListNodes    bool
	consulListMembers  bool
	consulListKV       bool
	consulFormat       string
	consulKVPrefix     string
)

var consulCmd = &cobra.Command{
	Use:   "consul",
	Short: "List Consul cluster resources",
	Long: `List Consul cluster resources including services, nodes, members, and KV entries.

This command connects to the local Consul agent and retrieves information about
the cluster, including registered services, cluster members, and key-value store entries.

EXAMPLES:
  # List cluster members (default)
  eos list consul

  # List all services
  eos list consul --services

  # List all nodes
  eos list consul --nodes

  # List KV store entries
  eos list consul --kv
  eos list consul --kv --prefix=eos/

  # JSON output for scripting
  eos list consul --services --format=json`,

	RunE: eos_cli.Wrap(runListConsul),
}

func init() {
	ListCmd.AddCommand(consulCmd)

	consulCmd.Flags().BoolVar(&consulListServices, "services", false, "List registered services")
	consulCmd.Flags().BoolVar(&consulListNodes, "nodes", false, "List cluster nodes")
	consulCmd.Flags().BoolVar(&consulListMembers, "members", false, "List cluster members (default)")
	consulCmd.Flags().BoolVar(&consulListKV, "kv", false, "List KV store entries")
	consulCmd.Flags().StringVar(&consulFormat, "format", "table", "Output format (table, json, yaml)")
	consulCmd.Flags().StringVar(&consulKVPrefix, "prefix", "", "KV prefix to list (only with --kv)")
}

func runListConsul(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Default to members if nothing specified
	if !consulListServices && !consulListNodes && !consulListMembers && !consulListKV {
		consulListMembers = true
	}

	logger.Info("Listing Consul resources",
		zap.Bool("services", consulListServices),
		zap.Bool("nodes", consulListNodes),
		zap.Bool("members", consulListMembers),
		zap.Bool("kv", consulListKV),
		zap.String("format", consulFormat))

	if consulListMembers {
		return listConsulMembers(rc, consulFormat)
	}

	if consulListServices {
		return listConsulServices(rc, consulFormat)
	}

	if consulListNodes {
		return listConsulNodes(rc, consulFormat)
	}

	if consulListKV {
		return listConsulKV(rc, consulFormat, consulKVPrefix)
	}

	return nil
}

func listConsulMembers(rc *eos_io.RuntimeContext, format string) error {
	logger := otelzap.Ctx(rc.Ctx)

	members, err := consul.GetClusterMembers(rc.Ctx)
	if err != nil {
		logger.Error("Failed to get cluster members", zap.Error(err))
		return fmt.Errorf("failed to get cluster members: %w", err)
	}

	if len(members) == 0 {
		logger.Info("No cluster members found")
		fmt.Println("No cluster members found")
		return nil
	}

	switch format {
	case "json":
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(members)
	case "yaml":
		encoder := yaml.NewEncoder(os.Stdout)
		defer encoder.Close()
		return encoder.Encode(members)
	default:
		table := tablewriter.NewWriter(os.Stdout)
		table.Header("NAME", "ADDRESS", "STATUS", "TYPE", "DATACENTER")

		for _, member := range members {
			table.Append(
				member.Name,
				member.Address,
				member.Status,
				member.Type,
				member.Datacenter,
			)
		}

		table.Render()
		fmt.Printf("\nTotal members: %d\n", len(members))
	}

	return nil
}

func listConsulServices(rc *eos_io.RuntimeContext, format string) error {
	logger := otelzap.Ctx(rc.Ctx)

	services, err := consul.GetServices(rc.Ctx)
	if err != nil {
		logger.Error("Failed to get services", zap.Error(err))
		return fmt.Errorf("failed to get services: %w", err)
	}

	if len(services) == 0 {
		logger.Info("No services found")
		fmt.Println("No services found")
		return nil
	}

	switch format {
	case "json":
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(services)
	case "yaml":
		encoder := yaml.NewEncoder(os.Stdout)
		defer encoder.Close()
		return encoder.Encode(services)
	default:
		table := tablewriter.NewWriter(os.Stdout)
		table.Header("SERVICE", "TAGS", "PORT", "ADDRESS")

		for _, svc := range services {
			tags := "none"
			if len(svc.Tags) > 0 {
				tags = fmt.Sprintf("%v", svc.Tags)
			}

			table.Append(
				svc.Name,
				tags,
				fmt.Sprintf("%d", svc.Port),
				svc.Address,
			)
		}

		table.Render()
		fmt.Printf("\nTotal services: %d\n", len(services))
	}

	return nil
}

func listConsulNodes(rc *eos_io.RuntimeContext, format string) error {
	logger := otelzap.Ctx(rc.Ctx)

	nodes, err := consul.GetNodes(rc.Ctx)
	if err != nil {
		logger.Error("Failed to get nodes", zap.Error(err))
		return fmt.Errorf("failed to get nodes: %w", err)
	}

	if len(nodes) == 0 {
		logger.Info("No nodes found")
		fmt.Println("No nodes found")
		return nil
	}

	switch format {
	case "json":
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(nodes)
	case "yaml":
		encoder := yaml.NewEncoder(os.Stdout)
		defer encoder.Close()
		return encoder.Encode(nodes)
	default:
		table := tablewriter.NewWriter(os.Stdout)
		table.Header("NODE", "ADDRESS", "DATACENTER", "META")

		for _, node := range nodes {
			meta := "none"
			if len(node.Meta) > 0 {
				meta = fmt.Sprintf("%v", node.Meta)
			}

			table.Append(
				node.Name,
				node.Address,
				node.Datacenter,
				meta,
			)
		}

		table.Render()
		fmt.Printf("\nTotal nodes: %d\n", len(nodes))
	}

	return nil
}

func listConsulKV(rc *eos_io.RuntimeContext, format, prefix string) error {
	logger := otelzap.Ctx(rc.Ctx)

	kvPairs, err := consul.GetKVList(rc.Ctx, prefix)
	if err != nil {
		logger.Error("Failed to get KV entries", zap.Error(err))
		return fmt.Errorf("failed to get KV entries: %w", err)
	}

	if len(kvPairs) == 0 {
		logger.Info("No KV entries found", zap.String("prefix", prefix))
		fmt.Printf("No KV entries found for prefix: %s\n", prefix)
		return nil
	}

	switch format {
	case "json":
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(kvPairs)
	case "yaml":
		encoder := yaml.NewEncoder(os.Stdout)
		defer encoder.Close()
		return encoder.Encode(kvPairs)
	default:
		table := tablewriter.NewWriter(os.Stdout)
		table.Header("KEY", "VALUE", "FLAGS", "MODIFY_INDEX")

		for _, kv := range kvPairs {
			value := string(kv.Value)
			if len(value) > 50 {
				value = value[:47] + "..."
			}

			table.Append(
				kv.Key,
				value,
				fmt.Sprintf("%d", kv.Flags),
				fmt.Sprintf("%d", kv.ModifyIndex),
			)
		}

		table.Render()
		fmt.Printf("\nTotal KV entries: %d\n", len(kvPairs))
	}

	return nil
}
