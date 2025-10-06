package create

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/kvm"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/kvm/orchestration"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	consulAddr  string
	nomadAddr   string
	enableNomad bool
	poolName    string
	poolMinSize int
	poolMaxSize int
	scalePoolTo int
)

// NewKVMOrchestratedCmd creates the orchestrated KVM command
var NewKVMOrchestratedCmd = &cobra.Command{
	Use:   "kvm-orchestrated",
	Short: "Create an orchestrated KVM VM with Consul and Nomad integration",
	Long: `Create a KVM virtual machine with full orchestration support:
- Automatic IP allocation from Consul
- Service registration and health checks
- Optional Nomad job creation for monitoring
- Static IP configuration via cloud-init

Examples:
  # Create orchestrated VM with auto-generated name
  eos create kvm-orchestrated

  # Create with Nomad integration
  eos create kvm-orchestrated --enable-nomad

  # Create with custom Consul/Nomad addresses
  eos create kvm-orchestrated --consul-addr 192.168.122.10:8500 --nomad-addr 192.168.122.10:4646`,
	Args: cobra.NoArgs,
	RunE: eos_cli.Wrap(createOrchestratedKVM),
}

// NewKVMPoolCmd creates the VM pool management command
var NewKVMPoolCmd = &cobra.Command{
	Use:   "kvm-pool",
	Short: "Create and manage a pool of KVM VMs",
	Long: `Create a pool of KVM virtual machines with auto-scaling capabilities:
- Minimum and maximum pool size
- Auto-scaling based on CPU/memory thresholds
- Nomad job management for pool control
- Consul service discovery for all pool VMs

Examples:
  # Create a pool with 3-10 VMs
  eos create kvm-pool --name web-pool --min 3 --max 10

  # Create with custom Consul/Nomad addresses
  eos create kvm-pool --name db-pool --min 2 --max 5 --consul-addr 192.168.122.10:8500`,
	Args: cobra.NoArgs,
	RunE: eos_cli.Wrap(createKVMPool),
}

func init() {
	// Register orchestrated VM command
	CreateCmd.AddCommand(NewKVMOrchestratedCmd)

	// Add flags for orchestrated command
	NewKVMOrchestratedCmd.Flags().StringVar(&consulAddr, "consul-addr", "", "Consul server address (default: localhost:8500)")
	NewKVMOrchestratedCmd.Flags().StringVar(&nomadAddr, "nomad-addr", "", "Nomad server address (default: localhost:4646)")
	NewKVMOrchestratedCmd.Flags().BoolVar(&enableNomad, "enable-nomad", false, "Enable Nomad job creation for VM monitoring")

	// Register pool command
	CreateCmd.AddCommand(NewKVMPoolCmd)

	// Add flags for pool command
	NewKVMPoolCmd.Flags().StringVar(&poolName, "name", "", "Name of the VM pool (required)")
	NewKVMPoolCmd.Flags().IntVar(&poolMinSize, "min", 2, "Minimum number of VMs in the pool")
	NewKVMPoolCmd.Flags().IntVar(&poolMaxSize, "max", 10, "Maximum number of VMs in the pool")
	NewKVMPoolCmd.Flags().StringVar(&consulAddr, "consul-addr", "", "Consul server address")
	NewKVMPoolCmd.Flags().StringVar(&nomadAddr, "nomad-addr", "", "Nomad server address")

	// Mark required flags
	NewKVMPoolCmd.MarkFlagRequired("name")
}

// createOrchestratedKVM creates an orchestrated KVM VM
func createOrchestratedKVM(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Generate VM name
	vmName := kvm.GenerateVMName("eos-kvm")

	logger.Info("Creating orchestrated KVM VM",
		zap.String("name", vmName),
		zap.String("consul_addr", consulAddr),
		zap.String("nomad_addr", nomadAddr),
		zap.Bool("nomad_enabled", enableNomad))

	// Create orchestrated VM manager
	manager, err := orchestration.NewOrchestratedVMManager(rc, consulAddr, nomadAddr)
	if err != nil {
		return fmt.Errorf("failed to initialize orchestration manager: %w", err)
	}

	// Create the orchestrated VM
	if err := manager.CreateOrchestratedVM(vmName, enableNomad); err != nil {
		return fmt.Errorf("failed to create orchestrated VM: %w", err)
	}

	return nil
}

// createKVMPool creates a VM pool
func createKVMPool(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Validate pool size
	if poolMinSize > poolMaxSize {
		return fmt.Errorf("minimum size (%d) cannot exceed maximum size (%d)", poolMinSize, poolMaxSize)
	}

	logger.Info("Creating VM pool",
		zap.String("name", poolName),
		zap.Int("min_size", poolMinSize),
		zap.Int("max_size", poolMaxSize))

	// Create pool manager
	poolManager, err := orchestration.NewVMPoolManager(rc, consulAddr, nomadAddr)
	if err != nil {
		return fmt.Errorf("failed to initialize pool manager: %w", err)
	}

	// Define the pool
	pool := &orchestration.VMPool{
		Name:       poolName,
		MinSize:    poolMinSize,
		MaxSize:    poolMaxSize,
		VMTemplate: "ubuntu-24.04",
		Tags:       []string{"pool", poolName},
		ScalingRules: &orchestration.ScalingRules{
			CPUThresholdUp:     80.0,
			CPUThresholdDown:   20.0,
			MemThresholdUp:     85.0,
			MemThresholdDown:   25.0,
			ScaleUpIncrement:   2,
			ScaleDownDecrement: 1,
			CooldownPeriod:     300, // 5 minutes
		},
	}

	// Create the pool
	if err := poolManager.CreatePool(pool); err != nil {
		return fmt.Errorf("failed to create VM pool: %w", err)
	}

	logger.Info("VM pool created successfully",
		zap.String("name", poolName),
		zap.Int("initial_size", poolMinSize))

	fmt.Printf("\n VM pool '%s' created successfully!\n", poolName)
	fmt.Printf("Minimum VMs: %d\n", poolMinSize)
	fmt.Printf("Maximum VMs: %d\n", poolMaxSize)
	fmt.Printf("Auto-scaling: Enabled\n")
	fmt.Printf("\nManage pool with:\n")
	fmt.Printf("  eos list kvm-pools            # List all pools\n")
	fmt.Printf("  eos update kvm-pool --name %s --scale %d  # Scale pool\n", poolName, poolMinSize+1)
	fmt.Printf("  eos delete kvm-pool --name %s  # Delete pool\n", poolName)

	return nil
}
