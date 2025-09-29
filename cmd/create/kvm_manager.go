package create

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/terraform/kvm"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var kvmManagerCmd = &cobra.Command{
	Use:   "kvm",
	Short: "Manage KVM virtual machines using Terraform",
	Long: `Manage KVM virtual machines using Terraform with libvirt provider.
This command provides comprehensive VM management capabilities including:
- VM creation with custom storage and networking
- Storage pool management
- Cloud-init integration for VM provisioning
- Network configuration
- VM lifecycle management (start, stop, destroy)

Examples:
  # Create a basic Ubuntu VM
  eos create kvm vm --name web-server --memory 2GB --vcpus 2 --disk-size 20GB

  # Create VM with additional storage volumes
  eos create kvm vm --name database --memory 4GB --vcpus 4 --disk-size 50GB --volumes data:100GB:qcow2,logs:20GB:raw

  # Create storage pool
  eos create kvm pool --name fast-storage --type dir --path /var/lib/libvirt/fast

  # List all VMs
  eos create kvm list --type vm

  # List storage pools
  eos create kvm list --type pool

  # Destroy VM
  eos create kvm destroy --name web-server`,
	RunE: eos_cli.Wrap(runKVMManager),
}

var (
	kvmAction      string
	kvmName        string
	kvmMemory      string
	kvmVCPUs       int
	kvmDiskSize    string
	kvmNetwork     string
	kvmOSVariant   string
	kvmImagePath   string
	kvmSSHKeys     []string
	kvmVolumes     []string
	kvmCloudInit   string
	kvmAutostart   bool
	kvmStoragePool string
	kvmPoolType    string
	kvmPoolPath    string
	kvmListType    string
	kvmDryRun      bool
)

// UbuntuVMDefaultConfig contains the recommended defaults for Ubuntu VMs
type UbuntuVMConfig struct {
	Name        string
	Memory      string // e.g., "4GB"
	VCPUs       int
	DiskSize    string // e.g., "40GB"
	OSVariant   string // e.g., "ubuntu24.04"
	Network     string
	StoragePool string
	Autostart   bool
}

// DefaultUbuntuVMConfig returns the recommended defaults for Ubuntu VMs
func DefaultUbuntuVMConfig(name string) *UbuntuVMConfig {
	return &UbuntuVMConfig{
		Name:        name,
		Memory:      "4GB",
		VCPUs:       2,
		DiskSize:    "40GB",
		OSVariant:   "ubuntu24.04",
		Network:     "default",
		StoragePool: "default",
		Autostart:   true,
	}
}

// NewUbuntuVMCmd creates a command for creating Ubuntu VMs with recommended defaults
var NewUbuntuVMCmd = &cobra.Command{
	Use:   "ubuntu-vm [name]",
	Short: "Create a new Ubuntu VM with recommended defaults",
	Long: `Create a new Ubuntu VM with secure, production-ready defaults:
  - 4GB RAM
  - 2 vCPUs
  - 40GB disk (thin provisioned)
  - UEFI boot (if available)
  - VirtIO for disk and network
  - Cloud-init for initial configuration

Example:
  # Create a new Ubuntu 24.04 VM
  eos create ubuntu-vm my-vm --ssh-keys ~/.ssh/id_rsa.pub
`,
	Args: cobra.ExactArgs(1),
	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		// Use default Ubuntu VM config
		config := DefaultUbuntuVMConfig(args[0])

		// Apply any overrides from flags
		if cmd.Flags().Changed("memory") {
			config.Memory = kvmMemory
		}
		if cmd.Flags().Changed("vcpus") {
			config.VCPUs = kvmVCPUs
		}
		if cmd.Flags().Changed("disk-size") {
			config.DiskSize = kvmDiskSize
		}
		if cmd.Flags().Changed("network") {
			config.Network = kvmNetwork
		}
		if cmd.Flags().Changed("storage-pool") {
			config.StoragePool = kvmStoragePool
		}
		if cmd.Flags().Changed("autostart") {
			config.Autostart = kvmAutostart
		}

		// Set the global variables to match our config
		kvmName = config.Name
		kvmMemory = config.Memory
		kvmVCPUs = config.VCPUs
		kvmDiskSize = config.DiskSize
		kvmOSVariant = config.OSVariant
		kvmNetwork = config.Network
		kvmStoragePool = config.StoragePool
		kvmAutostart = config.Autostart

		// Initialize KVM manager
		kvmMgr, err := kvm.NewKVMManager(rc, "")
		if err != nil {
			return fmt.Errorf("failed to initialize KVM manager: %w", err)
		}
		defer kvmMgr.Close()

		return createKVMVM(rc, kvmMgr)
	}),
}

func init() {
	// Original KVM manager command
	kvmManagerCmd.Flags().StringVar(&kvmAction, "action", "vm", "Action to perform (vm, pool, list, destroy)")
	kvmManagerCmd.Flags().StringVar(&kvmName, "name", "", "VM or pool name")
	kvmManagerCmd.Flags().StringVar(&kvmMemory, "memory", "1GB", "Memory allocation (e.g., 1GB, 2048MB)")
	kvmManagerCmd.Flags().IntVar(&kvmVCPUs, "vcpus", 1, "Number of virtual CPUs")
	kvmManagerCmd.Flags().StringVar(&kvmDiskSize, "disk-size", "10GB", "Primary disk size")
	kvmManagerCmd.Flags().StringVar(&kvmNetwork, "network", "default", "Network name")
	kvmManagerCmd.Flags().StringVar(&kvmOSVariant, "os-variant", "ubuntu20.04", "OS variant")
	kvmManagerCmd.Flags().StringVar(&kvmImagePath, "image", "", "Base image path")
	kvmManagerCmd.Flags().StringSliceVar(&kvmSSHKeys, "ssh-keys", []string{}, "SSH public key files")
	kvmManagerCmd.Flags().StringSliceVar(&kvmVolumes, "volumes", []string{}, "Additional volumes (name:size:format)")
	kvmManagerCmd.Flags().StringVar(&kvmCloudInit, "cloud-init", "", "Cloud-init user data file")
	kvmManagerCmd.Flags().BoolVar(&kvmAutostart, "autostart", false, "Enable VM autostart")
	kvmManagerCmd.Flags().StringVar(&kvmStoragePool, "storage-pool", "default", "Storage pool for VM disks")
	kvmManagerCmd.Flags().StringVar(&kvmPoolType, "pool-type", "dir", "Storage pool type (dir, lvm, zfs)")
	kvmManagerCmd.Flags().StringVar(&kvmPoolPath, "pool-path", "", "Storage pool path")
	kvmManagerCmd.Flags().StringVar(&kvmListType, "type", "vm", "List type (vm, pool)")
	kvmManagerCmd.Flags().BoolVar(&kvmDryRun, "dry-run", false, "Show what would be done without executing")

	// Ubuntu VM command with defaults
	NewUbuntuVMCmd.Flags().StringVar(&kvmMemory, "memory", "4GB", "Memory allocation (e.g., 4GB, 8192MB)")
	NewUbuntuVMCmd.Flags().IntVar(&kvmVCPUs, "vcpus", 2, "Number of virtual CPUs")
	NewUbuntuVMCmd.Flags().StringVar(&kvmDiskSize, "disk-size", "40GB", "Primary disk size")
	NewUbuntuVMCmd.Flags().StringVar(&kvmNetwork, "network", "default", "Network name")
	NewUbuntuVMCmd.Flags().StringVar(&kvmStoragePool, "storage-pool", "default", "Storage pool for VM disks")
	NewUbuntuVMCmd.Flags().BoolVar(&kvmAutostart, "autostart", true, "Enable VM autostart")
	NewUbuntuVMCmd.Flags().StringSliceVar(&kvmSSHKeys, "ssh-keys", []string{}, "SSH public key files (required)")
	NewUbuntuVMCmd.Flags().StringSliceVar(&kvmVolumes, "volumes", []string{}, "Additional volumes (name:size:format)")
	NewUbuntuVMCmd.Flags().BoolVar(&kvmDryRun, "dry-run", false, "Show what would be done without executing")
	NewUbuntuVMCmd.MarkFlagRequired("ssh-keys") // Require SSH keys for security
}

func runKVMManager(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting KVM management operation",
		zap.String("action", kvmAction),
		zap.String("name", kvmName),
		zap.Bool("dry_run", kvmDryRun))

	// Initialize KVM manager
	kvmMgr, err := kvm.NewKVMManager(rc, "")
	if err != nil {
		return fmt.Errorf("failed to initialize KVM manager: %w", err)
	}
	defer kvmMgr.Close()

	switch kvmAction {
	case "vm":
		return createKVMVM(rc, kvmMgr)
	case "pool":
		return createKVMPool(rc, kvmMgr)
	case "list":
		return listKVMResources(rc, kvmMgr)
	case "destroy":
		return destroyKVMResource(rc, kvmMgr)
	default:
		return fmt.Errorf("unsupported action: %s", kvmAction)
	}
}

func createKVMVM(rc *eos_io.RuntimeContext, kvmMgr *kvm.KVMManager) error {
	logger := otelzap.Ctx(rc.Ctx)

	if kvmName == "" {
		return fmt.Errorf("VM name is required")
	}

	// Parse memory size
	memoryMB, err := parseKVMMemorySize(kvmMemory)
	if err != nil {
		return fmt.Errorf("invalid memory format: %w", err)
	}

	// Parse disk size
	diskSizeBytes, err := parseKVMDiskSize(kvmDiskSize)
	if err != nil {
		return fmt.Errorf("invalid disk size format: %w", err)
	}

	// Parse additional volumes
	volumes, err := parseKVMVolumes(kvmVolumes)
	if err != nil {
		return fmt.Errorf("invalid volume format: %w", err)
	}

	// Read SSH keys (required for security)
	if len(kvmSSHKeys) == 0 {
		// Try to use default SSH key if none provided
		home, err := os.UserHomeDir()
		if err == nil {
			defaultKey := filepath.Join(home, ".ssh", "id_rsa.pub")
			if _, err := os.Stat(defaultKey); err == nil {
				kvmSSHKeys = []string{defaultKey}
				logger.Info("Using default SSH key", zap.String("path", defaultKey))
			}
		}
		if len(kvmSSHKeys) == 0 {
			return fmt.Errorf("at least one SSH public key is required for secure access")
		}
	}

	// Generate cloud-init data with secure defaults
	userData := generateKVMCloudInit(kvmSSHKeys)
	metaData := generateKVMMetaData(kvmName)

	// Log the VM configuration
	logger.Info("VM configuration",
		zap.String("name", kvmName),
		zap.Uint("memory_mb", memoryMB),
		zap.Int("vcpus", kvmVCPUs),
		zap.Uint64("disk_size", diskSizeBytes),
		zap.String("os_variant", kvmOSVariant),
		zap.Strings("ssh_keys", kvmSSHKeys),
		zap.Bool("autostart", kvmAutostart))

	logger.Info("Creating KVM VM",
		zap.String("name", kvmName),
		zap.Uint("memory", memoryMB),
		zap.Int("vcpus", kvmVCPUs),
		zap.Uint64("disk_size", diskSizeBytes))

	if kvmDryRun {
		fmt.Printf("🔍 DRY RUN - Would create VM:\n")
		fmt.Printf("   Name: %s\n", kvmName)
		fmt.Printf("   Memory: %s (%d MB)\n", kvmMemory, memoryMB)
		fmt.Printf("   vCPUs: %d\n", kvmVCPUs)
		fmt.Printf("   Disk Size: %s\n", kvmDiskSize)
		fmt.Printf("   Network: %s\n", kvmNetwork)
		fmt.Printf("   OS Variant: %s\n", kvmOSVariant)
		fmt.Printf("   Storage Pool: %s\n", kvmStoragePool)
		fmt.Printf("   Autostart: %t\n", kvmAutostart)
		if len(volumes) > 0 {
			fmt.Printf("   Additional Volumes:\n")
			for _, vol := range volumes {
				fmt.Printf("     - %s: %s (%s)\n", vol.Name, formatKVMSize(vol.Size), vol.Format)
			}
		}
		return nil
	}

	vmConfig := &kvm.VMConfig{
		Name:         kvmName,
		Memory:       memoryMB,
		VCPUs:        uint(kvmVCPUs),
		DiskSize:     diskSizeBytes,
		NetworkName:  kvmNetwork,
		OSVariant:    kvmOSVariant,
		ImagePath:    kvmImagePath,
		SSHKeys:      kvmSSHKeys,
		UserData:     userData,
		MetaData:     metaData,
		Volumes:      volumes,
		StoragePool:  kvmStoragePool,
		AutoStart:    kvmAutostart,
		Tags: map[string]string{
			"created_by": "eos-cli",
			"command":    "create_kvm_vm",
		},
	}

	vmInfo, err := kvmMgr.CreateVM(rc.Ctx, vmConfig)
	if err != nil {
		return fmt.Errorf("failed to create VM: %w", err)
	}

	fmt.Printf("✅ VM created successfully:\n")
	fmt.Printf("   Name: %s\n", vmInfo.Name)
	fmt.Printf("   UUID: %s\n", vmInfo.UUID)
	fmt.Printf("   State: %s\n", vmInfo.State)
	fmt.Printf("   Memory: %s\n", formatKVMSize(vmInfo.Memory))
	fmt.Printf("   vCPUs: %d\n", vmInfo.VCPUs)
	fmt.Printf("   Autostart: %t\n", vmInfo.Autostart)
	fmt.Printf("   Persistent: %t\n", vmInfo.Persistent)

	if len(vmInfo.Networks) > 0 {
		fmt.Printf("   Networks:\n")
		for _, net := range vmInfo.Networks {
			fmt.Printf("     - %s (%s)", net.Interface, net.Network)
			if net.IP != "" {
				fmt.Printf(" - %s", net.IP)
			}
			fmt.Printf("\n")
		}
	}

	if len(vmInfo.Disks) > 0 {
		fmt.Printf("   Disks:\n")
		for _, disk := range vmInfo.Disks {
			fmt.Printf("     - %s: %s (%s)\n", disk.Target, formatKVMSize(disk.Size), disk.Format)
		}
	}

	fmt.Printf("\nVM Management Commands:\n")
	fmt.Printf("  Start:   virsh start %s\n", vmInfo.Name)
	fmt.Printf("  Stop:    virsh shutdown %s\n", vmInfo.Name)
	fmt.Printf("  Console: virsh console %s\n", vmInfo.Name)
	fmt.Printf("  Destroy: eos create kvm destroy --name %s\n", vmInfo.Name)

	return nil
}

func createKVMPool(rc *eos_io.RuntimeContext, kvmMgr *kvm.KVMManager) error {
	if kvmName == "" {
		return fmt.Errorf("pool name is required")
	}
	if kvmPoolPath == "" {
		return fmt.Errorf("pool path is required")
	}

	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Creating storage pool",
		zap.String("name", kvmName),
		zap.String("type", kvmPoolType),
		zap.String("path", kvmPoolPath))

	if kvmDryRun {
		fmt.Printf("🔍 DRY RUN - Would create storage pool:\n")
		fmt.Printf("   Name: %s\n", kvmName)
		fmt.Printf("   Type: %s\n", kvmPoolType)
		fmt.Printf("   Path: %s\n", kvmPoolPath)
		return nil
	}

	err := kvmMgr.CreateStoragePool(rc.Ctx, kvmName, kvmPoolType, kvmPoolPath)
	if err != nil {
		return fmt.Errorf("failed to create storage pool: %w", err)
	}

	fmt.Printf("✅ Storage pool created successfully:\n")
	fmt.Printf("   Name: %s\n", kvmName)
	fmt.Printf("   Type: %s\n", kvmPoolType)
	fmt.Printf("   Path: %s\n", kvmPoolPath)

	return nil
}

func listKVMResources(rc *eos_io.RuntimeContext, kvmMgr *kvm.KVMManager) error {
	logger := otelzap.Ctx(rc.Ctx)

	switch kvmListType {
	case "vm":
		logger.Info("Listing VMs")
		vms, err := kvmMgr.ListVMs(rc.Ctx)
		if err != nil {
			return fmt.Errorf("failed to list VMs: %w", err)
		}

		fmt.Printf("🖥️  Found %d VM(s):\n\n", len(vms))
		for _, vm := range vms {
			fmt.Printf("Name: %s\n", vm.Name)
			fmt.Printf("  UUID: %s\n", vm.UUID)
			fmt.Printf("  State: %s\n", vm.State)
			fmt.Printf("  Memory: %s\n", formatKVMSize(vm.Memory))
			fmt.Printf("  vCPUs: %d\n", vm.VCPUs)
			fmt.Printf("  Autostart: %t\n", vm.Autostart)
			fmt.Printf("  Created: %s\n", vm.CreatedAt.Format("2006-01-02 15:04:05"))
			fmt.Println()
		}

	case "pool":
		logger.Info("Listing storage pools")
		pools, err := kvmMgr.ListStoragePools(rc.Ctx)
		if err != nil {
			return fmt.Errorf("failed to list storage pools: %w", err)
		}

		fmt.Printf("💾 Found %d storage pool(s):\n\n", len(pools))
		for _, pool := range pools {
			fmt.Printf("Name: %s\n", pool.Name)
			fmt.Printf("  Type: %s\n", pool.Type)
			fmt.Printf("  Path: %s\n", pool.Path)
			fmt.Printf("  Capacity: %s\n", formatKVMSize(pool.Capacity))
			fmt.Printf("  Available: %s\n", formatKVMSize(pool.Available))
			fmt.Printf("  Active: %t\n", pool.Active)
			fmt.Println()
		}

	default:
		return fmt.Errorf("unsupported list type: %s (use 'vm' or 'pool')", kvmListType)
	}

	return nil
}

func destroyKVMResource(rc *eos_io.RuntimeContext, kvmMgr *kvm.KVMManager) error {
	if kvmName == "" {
		return fmt.Errorf("resource name is required for destruction")
	}

	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Destroying VM", zap.String("name", kvmName))

	if kvmDryRun {
		fmt.Printf("🔍 DRY RUN - Would destroy VM: %s\n", kvmName)
		return nil
	}

	err := kvmMgr.DestroyVM(rc.Ctx, kvmName)
	if err != nil {
		return fmt.Errorf("failed to destroy VM: %w", err)
	}

	fmt.Printf("✅ VM destroyed successfully: %s\n", kvmName)
	return nil
}

// Helper functions
func parseKVMMemorySize(memory string) (uint, error) {
	memory = strings.ToUpper(strings.TrimSpace(memory))
	
	var multiplier uint = 1
	var numStr string

	if strings.HasSuffix(memory, "GB") {
		multiplier = 1024
		numStr = strings.TrimSuffix(memory, "GB")
	} else if strings.HasSuffix(memory, "MB") {
		multiplier = 1
		numStr = strings.TrimSuffix(memory, "MB")
	} else {
		numStr = memory
	}

	var num float64
	if _, err := fmt.Sscanf(numStr, "%f", &num); err != nil {
		return 0, fmt.Errorf("invalid number format: %s", numStr)
	}

	return uint(num * float64(multiplier)), nil
}

func parseKVMDiskSize(size string) (uint64, error) {
	size = strings.ToUpper(strings.TrimSpace(size))
	
	var multiplier uint64 = 1
	var numStr string

	if strings.HasSuffix(size, "TB") {
		multiplier = 1024 * 1024 * 1024 * 1024
		numStr = strings.TrimSuffix(size, "TB")
	} else if strings.HasSuffix(size, "GB") {
		multiplier = 1024 * 1024 * 1024
		numStr = strings.TrimSuffix(size, "GB")
	} else if strings.HasSuffix(size, "MB") {
		multiplier = 1024 * 1024
		numStr = strings.TrimSuffix(size, "MB")
	} else {
		numStr = size
	}

	var num float64
	if _, err := fmt.Sscanf(numStr, "%f", &num); err != nil {
		return 0, fmt.Errorf("invalid number format: %s", numStr)
	}

	return uint64(num * float64(multiplier)), nil
}

func parseKVMVolumes(volumeSpecs []string) ([]kvm.VolumeConfig, error) {
	volumes := make([]kvm.VolumeConfig, 0, len(volumeSpecs))

	for _, spec := range volumeSpecs {
		parts := strings.Split(spec, ":")
		if len(parts) < 2 || len(parts) > 3 {
			return nil, fmt.Errorf("invalid volume format: %s (expected name:size[:format])", spec)
		}

		name := parts[0]
		sizeStr := parts[1]
		format := "qcow2"
		
		if len(parts) == 3 {
			format = parts[2]
		}

		size, err := parseKVMDiskSize(sizeStr)
		if err != nil {
			return nil, fmt.Errorf("invalid volume size: %s", sizeStr)
		}

		volumes = append(volumes, kvm.VolumeConfig{
			Name:   name,
			Size:   size,
			Format: format,
			Pool:   kvmStoragePool,
		})
	}

	return volumes, nil
}

func generateKVMCloudInit(sshKeys []string) string {
	cloudInit := `#cloud-config
users:
  - name: ubuntu
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: false
    ssh_authorized_keys:`

	for _, key := range sshKeys {
		cloudInit += fmt.Sprintf("\n      - %s", key)
	}

	cloudInit += `

packages:
  - qemu-guest-agent
  - cloud-init
  - openssh-server

runcmd:
  - systemctl enable qemu-guest-agent
  - systemctl start qemu-guest-agent
  - systemctl enable ssh
  - systemctl start ssh

final_message: "VM initialization complete"`

	return cloudInit
}

func generateKVMMetaData(vmName string) string {
	return fmt.Sprintf(`instance-id: %s
local-hostname: %s`, vmName, vmName)
}

func formatKVMSize(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
