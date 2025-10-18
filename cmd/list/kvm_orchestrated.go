//go:build linux

package list

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/kvm/orchestration"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)
// TODO: refactor
var (
	consulAddr string
	nomadAddr  string
)

// ListKVMOrchestratedCmd lists orchestrated KVM VMs
var ListKVMOrchestratedCmd = &cobra.Command{
	Use:   "kvm-orchestrated",
	Short: "List orchestrated KVM VMs managed by Consul and Nomad",
	Long: `List all KVM virtual machines that are registered with Consul for orchestration.
Shows VM name, IP address, health status, and Nomad job information.

Examples:
  # List all orchestrated VMs
  eos list kvm-orchestrated

  # List with custom Consul address
  eos list kvm-orchestrated --consul-addr 192.168.122.10:8500`,
	Args: cobra.NoArgs,
	RunE: eos_cli.Wrap(listOrchestratedKVMs),
}

// ListKVMPoolsCmd lists VM pools
var ListKVMPoolsCmd = &cobra.Command{
	Use:   "kvm-pools",
	Short: "List KVM VM pools",
	Long: `List all KVM virtual machine pools with their current status.
Shows pool name, current size, min/max limits, and auto-scaling status.

Examples:
  # List all VM pools
  eos list kvm-pools

  # List with custom addresses
  eos list kvm-pools --consul-addr 192.168.122.10:8500`,
	Args: cobra.NoArgs,
	RunE: eos_cli.Wrap(listKVMPools),
}

func init() {
	// Register orchestrated VM list command
	ListCmd.AddCommand(ListKVMOrchestratedCmd)
	ListKVMOrchestratedCmd.Flags().StringVar(&consulAddr, "consul-addr", "", "Consul server address")
	ListKVMOrchestratedCmd.Flags().StringVar(&nomadAddr, "nomad-addr", "", "Nomad server address")

	// Register pool list command
	ListCmd.AddCommand(ListKVMPoolsCmd)
	ListKVMPoolsCmd.Flags().StringVar(&consulAddr, "consul-addr", "", "Consul server address")
	ListKVMPoolsCmd.Flags().StringVar(&nomadAddr, "nomad-addr", "", "Nomad server address")
}
// TODO: refactor
func listOrchestratedKVMs(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Listing orchestrated KVM VMs")

	// Create orchestrated VM manager
	manager, err := orchestration.NewOrchestratedVMManager(rc, consulAddr, nomadAddr)
	if err != nil {
		return fmt.Errorf("failed to initialize orchestration manager: %w", err)
	}

	// List VMs
	vms, err := manager.ListOrchestratedVMs()
	if err != nil {
		return fmt.Errorf("failed to list orchestrated VMs: %w", err)
	}

	if len(vms) == 0 {
		fmt.Println("No orchestrated VMs found")
		return nil
	}

	// Display results in table format
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "NAME\tIP ADDRESS\tHEALTH\tCONSUL ID\tNOMAD JOB\tCREATED")
	_, _ = fmt.Fprintln(w, "----\t----------\t------\t---------\t---------\t-------")

	for _, vm := range vms {
		nomadJob := vm.NomadJobID
		if nomadJob == "" {
			nomadJob = "-"
		}

		created := "-"
		if !vm.CreatedAt.IsZero() {
			created = vm.CreatedAt.Format("2006-01-02 15:04")
		} else if vm.Meta != nil && vm.Meta["created_at"] != "" {
			created = vm.Meta["created_at"]
		}

		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			vm.Name,
			vm.IPAddress,
			vm.Health,
			vm.ConsulServiceID,
			nomadJob,
			created)
	}

	w.Flush()

	fmt.Printf("\nTotal orchestrated VMs: %d\n", len(vms))
	return nil
}
// TODO: refactor
func listKVMPools(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Listing VM pools")

	// Create pool manager
	poolManager, err := orchestration.NewVMPoolManager(rc, consulAddr, nomadAddr)
	if err != nil {
		return fmt.Errorf("failed to initialize pool manager: %w", err)
	}

	// List pools
	pools := poolManager.ListPools()

	if len(pools) == 0 {
		fmt.Println("No VM pools found")
		return nil
	}

	// Display results in table format
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "NAME\tCURRENT\tMIN\tMAX\tAUTO-SCALE\tTAGS")
	_, _ = fmt.Fprintln(w, "----\t-------\t---\t---\t----------\t----")

	for _, pool := range pools {
		autoScale := "Disabled"
		if pool.ScalingRules != nil {
			autoScale = "Enabled"
		}

		tags := "-"
		if len(pool.Tags) > 0 {
			tags = ""
			for i, tag := range pool.Tags {
				if i > 0 {
					tags += ", "
				}
				tags += tag
			}
		}

		_, _ = fmt.Fprintf(w, "%s\t%d\t%d\t%d\t%s\t%s\n",
			pool.Name,
			pool.CurrentSize,
			pool.MinSize,
			pool.MaxSize,
			autoScale,
			tags)
	}

	w.Flush()

	fmt.Printf("\nTotal VM pools: %d\n", len(pools))
	return nil
}
