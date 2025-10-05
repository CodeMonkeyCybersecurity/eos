// cmd/list/nomad.go
// List Nomad cluster resources

package list

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/nomad"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

var (
	nomadListJobs        bool
	nomadListAllocations bool
	nomadListNodes       bool
	nomadListServers     bool
	nomadListVolumes     bool
	nomadFormat          string
	nomadJobStatus       string
	nomadNodeStatus      string
)

var nomadCmd = &cobra.Command{
	Use:   "nomad",
	Short: "List Nomad cluster resources",
	Long: `List Nomad cluster resources including jobs, allocations, nodes, and volumes.

This command connects to the local Nomad agent and retrieves information about
the cluster, including running jobs, allocations, cluster nodes, and CSI volumes.

EXAMPLES:
  # List all jobs (default)
  eos list nomad

  # List cluster nodes
  eos list nomad --nodes

  # List server members
  eos list nomad --servers

  # List allocations
  eos list nomad --allocations

  # List CSI volumes
  eos list nomad --volumes

  # Filter jobs by status
  eos list nomad --jobs --status=running

  # JSON output for scripting
  eos list nomad --jobs --format=json`,

	RunE: eos_cli.Wrap(runListNomad),
}

func init() {
	ListCmd.AddCommand(nomadCmd)

	nomadCmd.Flags().BoolVar(&nomadListJobs, "jobs", false, "List jobs (default)")
	nomadCmd.Flags().BoolVar(&nomadListAllocations, "allocations", false, "List allocations")
	nomadCmd.Flags().BoolVar(&nomadListNodes, "nodes", false, "List client nodes")
	nomadCmd.Flags().BoolVar(&nomadListServers, "servers", false, "List server members")
	nomadCmd.Flags().BoolVar(&nomadListVolumes, "volumes", false, "List CSI volumes")
	nomadCmd.Flags().StringVar(&nomadFormat, "format", "table", "Output format (table, json, yaml)")
	nomadCmd.Flags().StringVar(&nomadJobStatus, "status", "", "Filter jobs by status (running, pending, dead)")
	nomadCmd.Flags().StringVar(&nomadNodeStatus, "node-status", "", "Filter nodes by status (ready, down)")
}

func runListNomad(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Default to jobs if nothing specified
	if !nomadListJobs && !nomadListAllocations && !nomadListNodes && !nomadListServers && !nomadListVolumes {
		nomadListJobs = true
	}

	logger.Info("Listing Nomad resources",
		zap.Bool("jobs", nomadListJobs),
		zap.Bool("allocations", nomadListAllocations),
		zap.Bool("nodes", nomadListNodes),
		zap.Bool("servers", nomadListServers),
		zap.Bool("volumes", nomadListVolumes),
		zap.String("format", nomadFormat))

	if nomadListJobs {
		return listNomadJobs(rc, nomadFormat, nomadJobStatus)
	}

	if nomadListAllocations {
		return listNomadAllocations(rc, nomadFormat)
	}

	if nomadListNodes {
		return listNomadNodes(rc, nomadFormat, nomadNodeStatus)
	}

	if nomadListServers {
		return listNomadServers(rc, nomadFormat)
	}

	if nomadListVolumes {
		return listNomadVolumes(rc, nomadFormat)
	}

	return nil
}

func listNomadJobs(rc *eos_io.RuntimeContext, format, statusFilter string) error {
	logger := otelzap.Ctx(rc.Ctx)

	jobs, err := nomad.GetJobs(rc.Ctx)
	if err != nil {
		logger.Error("Failed to get jobs", zap.Error(err))
		return fmt.Errorf("failed to get jobs: %w", err)
	}

	// Filter by status if specified
	if statusFilter != "" {
		jobs = nomad.FilterJobsByStatus(jobs, statusFilter)
	}

	if len(jobs) == 0 {
		logger.Info("No jobs found")
		fmt.Println("No jobs found")
		return nil
	}

	switch format {
	case "json":
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(jobs)
	case "yaml":
		encoder := yaml.NewEncoder(os.Stdout)
		defer encoder.Close()
		return encoder.Encode(jobs)
	default:
		table := tablewriter.NewWriter(os.Stdout)
		table.Header("ID", "NAME", "TYPE", "STATUS", "PRIORITY", "GROUPS")

		for _, job := range jobs {
			table.Append(
				job.ID,
				job.Name,
				job.Type,
				job.Status,
				fmt.Sprintf("%d", job.Priority),
				fmt.Sprintf("%d", job.TaskGroups),
			)
		}

		table.Render()
		fmt.Printf("\nTotal jobs: %d\n", len(jobs))
	}

	return nil
}

func listNomadAllocations(rc *eos_io.RuntimeContext, format string) error {
	logger := otelzap.Ctx(rc.Ctx)

	allocs, err := nomad.GetAllocations(rc.Ctx)
	if err != nil {
		logger.Error("Failed to get allocations", zap.Error(err))
		return fmt.Errorf("failed to get allocations: %w", err)
	}

	if len(allocs) == 0 {
		logger.Info("No allocations found")
		fmt.Println("No allocations found")
		return nil
	}

	switch format {
	case "json":
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(allocs)
	case "yaml":
		encoder := yaml.NewEncoder(os.Stdout)
		defer encoder.Close()
		return encoder.Encode(allocs)
	default:
		table := tablewriter.NewWriter(os.Stdout)
		table.Header("ID", "JOB", "TASK_GROUP", "NODE", "STATUS", "DESIRED")

		for _, alloc := range allocs {
			table.Append(
				alloc.ID[:8], // Short ID
				alloc.JobID,
				alloc.TaskGroup,
				alloc.NodeName,
				alloc.ClientStatus,
				alloc.DesiredStatus,
			)
		}

		table.Render()
		fmt.Printf("\nTotal allocations: %d\n", len(allocs))
	}

	return nil
}

func listNomadNodes(rc *eos_io.RuntimeContext, format, statusFilter string) error {
	logger := otelzap.Ctx(rc.Ctx)

	nodes, err := nomad.GetNodes(rc.Ctx)
	if err != nil {
		logger.Error("Failed to get nodes", zap.Error(err))
		return fmt.Errorf("failed to get nodes: %w", err)
	}

	// Filter by status if specified
	if statusFilter != "" {
		nodes = nomad.FilterNodesByStatus(nodes, statusFilter)
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
		table.Header("ID", "NAME", "STATUS", "DATACENTER", "DRAIN", "ALLOCATIONS")

		for _, node := range nodes {
			drainStatus := "no"
			if node.Drain {
				drainStatus = "yes"
			}

			table.Append(
				node.ID[:8], // Short ID
				node.Name,
				node.Status,
				node.Datacenter,
				drainStatus,
				fmt.Sprintf("%d", node.AllocCount),
			)
		}

		table.Render()
		fmt.Printf("\nTotal nodes: %d\n", len(nodes))
	}

	return nil
}

func listNomadServers(rc *eos_io.RuntimeContext, format string) error {
	logger := otelzap.Ctx(rc.Ctx)

	servers, err := nomad.GetServerMembers(rc.Ctx)
	if err != nil {
		logger.Error("Failed to get server members", zap.Error(err))
		return fmt.Errorf("failed to get server members: %w", err)
	}

	if len(servers) == 0 {
		logger.Info("No server members found")
		fmt.Println("No server members found")
		return nil
	}

	switch format {
	case "json":
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(servers)
	case "yaml":
		encoder := yaml.NewEncoder(os.Stdout)
		defer encoder.Close()
		return encoder.Encode(servers)
	default:
		table := tablewriter.NewWriter(os.Stdout)
		table.Header("NAME", "ADDRESS", "STATUS", "LEADER", "DATACENTER", "REGION")

		for _, server := range servers {
			leader := "no"
			if server.Leader {
				leader = "yes"
			}

			table.Append(
				server.Name,
				server.Address,
				server.Status,
				leader,
				server.Datacenter,
				server.Region,
			)
		}

		table.Render()
		fmt.Printf("\nTotal servers: %d\n", len(servers))
	}

	return nil
}

func listNomadVolumes(rc *eos_io.RuntimeContext, format string) error {
	logger := otelzap.Ctx(rc.Ctx)

	volumes, err := nomad.GetVolumes(rc.Ctx)
	if err != nil {
		logger.Error("Failed to get volumes", zap.Error(err))
		return fmt.Errorf("failed to get volumes: %w", err)
	}

	if len(volumes) == 0 {
		logger.Info("No volumes found")
		fmt.Println("No volumes found")
		return nil
	}

	switch format {
	case "json":
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(volumes)
	case "yaml":
		encoder := yaml.NewEncoder(os.Stdout)
		defer encoder.Close()
		return encoder.Encode(volumes)
	default:
		table := tablewriter.NewWriter(os.Stdout)
		table.Header("ID", "NAME", "PLUGIN", "SCHEDULABLE", "CONTROLLERS", "NODES")

		for _, vol := range volumes {
			schedulable := "yes"
			if !vol.Schedulable {
				schedulable = "no"
			}

			table.Append(
				vol.ID,
				vol.Name,
				vol.PluginID,
				schedulable,
				fmt.Sprintf("%d", vol.ControllersHealthy),
				fmt.Sprintf("%d", vol.NodesHealthy),
			)
		}

		table.Render()
		fmt.Printf("\nTotal volumes: %d\n", len(volumes))
	}

	return nil
}
