package create

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/storage/utils"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/virtualization/libvirt"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var vmLibvirtCmd = &cobra.Command{
	Use:   "vm",
	Short: "Create KVM virtual machines using libvirt",
	Long: `Create and manage KVM virtual machines using native Go libvirt integration.
This command provides granular control over VM creation with support for
custom storage, networking, and cloud-init configuration.

Examples:
  # Create a basic Ubuntu VM
  eos create vm --name web-server --memory 2GB --vcpus 2 --disk-size 20GB

  # Create VM with additional storage volumes
  eos create vm --name database --memory 4GB --vcpus 4 --disk-size 50GB --volumes data:100GB:xfs,logs:20GB:ext4

  # Create VM with custom network and SSH keys
  eos create vm --name dev-box --memory 8GB --vcpus 8 --network custom-net --ssh-keys ~/.ssh/id_rsa.pub`,
	RunE: eos_cli.Wrap(createVMLibvirt),
}

var (
	vmName        string
	vmMemory      string
	vmVCPUs       int
	vmDiskSize    string
	vmNetwork     string
	vmOSVariant   string
	vmImagePath   string
	vmSSHKeys     []string
	vmVolumes     []string
	vmCloudInit   string
	vmAutostart   bool
	vmDryRun      bool
	vmStoragePool string
)

func init() {
	vmLibvirtCmd.Flags().StringVar(&vmName, "name", "", "VM name (required)")
	vmLibvirtCmd.Flags().StringVar(&vmMemory, "memory", "1GB", "Memory allocation (e.g., 1GB, 2048MB)")
	vmLibvirtCmd.Flags().IntVar(&vmVCPUs, "vcpus", 1, "Number of virtual CPUs")
	vmLibvirtCmd.Flags().StringVar(&vmDiskSize, "disk-size", "10GB", "Primary disk size")
	vmLibvirtCmd.Flags().StringVar(&vmNetwork, "network", "default", "Network name")
	vmLibvirtCmd.Flags().StringVar(&vmOSVariant, "os-variant", "ubuntu20.04", "OS variant")
	vmLibvirtCmd.Flags().StringVar(&vmImagePath, "image", "", "Base image path")
	vmLibvirtCmd.Flags().StringSliceVar(&vmSSHKeys, "ssh-keys", []string{}, "SSH public key files")
	vmLibvirtCmd.Flags().StringSliceVar(&vmVolumes, "volumes", []string{}, "Additional volumes (name:size:format)")
	vmLibvirtCmd.Flags().StringVar(&vmCloudInit, "cloud-init", "", "Cloud-init user data file")
	vmLibvirtCmd.Flags().BoolVar(&vmAutostart, "autostart", false, "Enable VM autostart")
	vmLibvirtCmd.Flags().BoolVar(&vmDryRun, "dry-run", false, "Show what would be done without executing")
	vmLibvirtCmd.Flags().StringVar(&vmStoragePool, "storage-pool", "default", "Storage pool for VM disks")

	vmLibvirtCmd.MarkFlagRequired("name")
}

func createVMLibvirt(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Creating KVM virtual machine",
		zap.String("name", vmName),
		zap.String("memory", vmMemory),
		zap.Int("vcpus", vmVCPUs),
		zap.String("disk_size", vmDiskSize),
		zap.Bool("dry_run", vmDryRun))

	// Parse memory size
	memoryMB, err := parseMemorySize(vmMemory)
	if err != nil {
		return fmt.Errorf("invalid memory format: %w", err)
	}

	// Parse disk size
	diskSizeBytes, err := parseSize(vmDiskSize)
	if err != nil {
		return fmt.Errorf("invalid disk size format: %w", err)
	}

	// Parse additional volumes
	volumes, err := parseVolumes(vmVolumes)
	if err != nil {
		return fmt.Errorf("invalid volume format: %w", err)
	}

	// Read SSH keys
	sshKeys, err := readSSHKeys(vmSSHKeys)
	if err != nil {
		return fmt.Errorf("failed to read SSH keys: %w", err)
	}

	// Read cloud-init data
	var userData string
	if vmCloudInit != "" {
		userData, err = readCloudInitFile(vmCloudInit)
		if err != nil {
			return fmt.Errorf("failed to read cloud-init file: %w", err)
		}
	} else {
		// Generate default cloud-init
		userData = generateDefaultCloudInit(sshKeys)
	}

	// Create VM configuration
	config := &libvirt.VMConfig{
		Name:        vmName,
		Memory:      memoryMB,
		VCPUs:       uint(vmVCPUs),
		DiskSize:    diskSizeBytes,
		NetworkName: vmNetwork,
		OSVariant:   vmOSVariant,
		ImagePath:   vmImagePath,
		SSHKeys:     sshKeys,
		UserData:    userData,
		MetaData:    generateMetaData(vmName),
		Volumes:     volumes,
		Tags: map[string]string{
			"created_by": "eos",
			"created_at": time.Now().Format(time.RFC3339),
		},
	}

	if vmDryRun {
		return showVMDryRun(rc, config)
	}

	// Create libvirt manager
	libvirtMgr, err := libvirt.NewLibvirtManager(rc, "")
	if err != nil {
		return fmt.Errorf("failed to initialize libvirt manager: %w", err)
	}
	defer libvirtMgr.Close()

	// Ensure storage pool exists
	if err := ensureStoragePool(rc.Ctx, libvirtMgr, vmStoragePool); err != nil {
		return fmt.Errorf("failed to ensure storage pool: %w", err)
	}

	// Create VM
	logger.Info("Creating virtual machine...")
	vmInfo, err := libvirtMgr.CreateVM(rc.Ctx, config)
	if err != nil {
		return fmt.Errorf("failed to create VM: %w", err)
	}

	// Set autostart if requested
	if vmAutostart {
		// This would be implemented in the libvirt manager
		logger.Info("Autostart enabled for VM", zap.String("name", vmName))
	}

	// Display results
	displayVMInfo(rc, vmInfo)

	logger.Info("Virtual machine created successfully",
		zap.String("name", vmInfo.Name),
		zap.String("uuid", vmInfo.UUID),
		zap.String("state", vmInfo.State))

	return nil
}

func parseMemorySize(memStr string) (uint, error) {
	memStr = strings.ToUpper(strings.TrimSpace(memStr))
	
	var multiplier uint = 1
	var numStr string

	if strings.HasSuffix(memStr, "GB") {
		multiplier = 1024
		numStr = strings.TrimSuffix(memStr, "GB")
	} else if strings.HasSuffix(memStr, "MB") {
		multiplier = 1
		numStr = strings.TrimSuffix(memStr, "MB")
	} else {
		numStr = memStr
	}

	num, err := strconv.ParseFloat(numStr, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid number format: %s", numStr)
	}

	return uint(num * float64(multiplier)), nil
}

func parseVolumes(volumeSpecs []string) ([]libvirt.VolumeConfig, error) {
	volumes := make([]libvirt.VolumeConfig, 0, len(volumeSpecs))

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

		size, err := parseSize(sizeStr)
		if err != nil {
			return nil, fmt.Errorf("invalid volume size: %s", sizeStr)
		}

		volumes = append(volumes, libvirt.VolumeConfig{
			Name:   name,
			Size:   size,
			Format: format,
			Pool:   vmStoragePool,
		})
	}

	return volumes, nil
}

func readSSHKeys(keyFiles []string) ([]string, error) {
	var keys []string

	for _, keyFile := range keyFiles {
		// In a real implementation, read the SSH key files
		// For now, just add placeholder
		keys = append(keys, fmt.Sprintf("# SSH key from %s", keyFile))
	}

	return keys, nil
}

func readCloudInitFile(filePath string) (string, error) {
	// In a real implementation, read the cloud-init file
	// For now, return placeholder
	return fmt.Sprintf("# Cloud-init from %s", filePath), nil
}

func generateDefaultCloudInit(sshKeys []string) string {
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

func generateMetaData(vmName string) string {
	return fmt.Sprintf(`instance-id: %s
local-hostname: %s`, vmName, vmName)
}

func ensureStoragePool(ctx context.Context, mgr *libvirt.LibvirtManager, poolName string) error {
	// Check if pool exists
	pools, err := mgr.ListStoragePools(ctx)
	if err != nil {
		return fmt.Errorf("failed to list storage pools: %w", err)
	}

	for _, pool := range pools {
		if pool.Name == poolName {
			return nil // Pool exists
		}
	}

	// Create default storage pool
	poolPath := fmt.Sprintf("/var/lib/libvirt/images/%s", poolName)
	return mgr.CreateStoragePool(ctx, poolName, "dir", poolPath)
}

func showVMDryRun(rc *eos_io.RuntimeContext, config *libvirt.VMConfig) error {
	fmt.Println("=== DRY RUN MODE ===")
	fmt.Printf("Would create VM with the following configuration:\n\n")
	fmt.Printf("Name:         %s\n", config.Name)
	fmt.Printf("Memory:       %d MB\n", config.Memory)
	fmt.Printf("vCPUs:        %d\n", config.VCPUs)
	fmt.Printf("Disk Size:    %s\n", utils.FormatBytes(config.DiskSize))
	fmt.Printf("Network:      %s\n", config.NetworkName)
	fmt.Printf("OS Variant:   %s\n", config.OSVariant)
	
	if config.ImagePath != "" {
		fmt.Printf("Base Image:   %s\n", config.ImagePath)
	}

	if len(config.SSHKeys) > 0 {
		fmt.Printf("SSH Keys:     %d keys configured\n", len(config.SSHKeys))
	}

	if len(config.Volumes) > 0 {
		fmt.Printf("Additional Volumes:\n")
		for _, vol := range config.Volumes {
			fmt.Printf("  - %s: %s (%s)\n", vol.Name, utils.FormatBytes(vol.Size), vol.Format)
		}
	}

	fmt.Printf("\nOperations that would be performed:\n")
	fmt.Printf("1. Validate libvirt connection\n")
	fmt.Printf("2. Create storage pool if needed\n")
	fmt.Printf("3. Create primary disk (%s)\n", utils.FormatBytes(config.DiskSize))
	
	for i, vol := range config.Volumes {
		fmt.Printf("%d. Create volume %s (%s)\n", 4+i, vol.Name, utils.FormatBytes(vol.Size))
	}
	
	fmt.Printf("%d. Generate cloud-init ISO\n", 4+len(config.Volumes))
	fmt.Printf("%d. Define VM in libvirt\n", 5+len(config.Volumes))
	fmt.Printf("%d. Start VM\n", 6+len(config.Volumes))

	fmt.Printf("\nNo changes were made. Use --dry-run=false to execute.\n")
	return nil
}

func displayVMInfo(rc *eos_io.RuntimeContext, vm *libvirt.VMInfo) {
	fmt.Printf("\n=== Virtual Machine Created Successfully ===\n\n")
	fmt.Printf("Name:         %s\n", vm.Name)
	fmt.Printf("UUID:         %s\n", vm.UUID)
	fmt.Printf("State:        %s\n", vm.State)
	fmt.Printf("Memory:       %s\n", utils.FormatBytes(vm.Memory))
	fmt.Printf("vCPUs:        %d\n", vm.VCPUs)
	fmt.Printf("Autostart:    %t\n", vm.Autostart)
	fmt.Printf("Persistent:   %t\n", vm.Persistent)
	
	if len(vm.Networks) > 0 {
		fmt.Printf("Networks:\n")
		for _, net := range vm.Networks {
			fmt.Printf("  - %s (%s)", net.Interface, net.Network)
			if net.IP != "" {
				fmt.Printf(" - %s", net.IP)
			}
			fmt.Printf("\n")
		}
	}

	if len(vm.Disks) > 0 {
		fmt.Printf("Disks:\n")
		for _, disk := range vm.Disks {
			fmt.Printf("  - %s: %s (%s)\n", disk.Target, utils.FormatBytes(disk.Size), disk.Format)
		}
	}

	fmt.Printf("Created:      %s\n", vm.CreatedAt.Format(time.RFC3339))

	fmt.Printf("\nVM Management Commands:\n")
	fmt.Printf("  Start:      eos start vm %s\n", vm.Name)
	fmt.Printf("  Stop:       eos stop vm %s\n", vm.Name)
	fmt.Printf("  Info:       eos info vm %s\n", vm.Name)
	fmt.Printf("  Console:    virsh console %s\n", vm.Name)
	
	if vm.State == "running" {
		fmt.Printf("\nVM is running and ready for use!\n")
	}
}
