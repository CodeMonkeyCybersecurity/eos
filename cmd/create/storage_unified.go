package create

import (
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/storage/unified"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/storage/utils"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var storageUnifiedCmd = &cobra.Command{
	Use:   "storage",
	Short: "Unified storage and virtualization management",
	Long: `Unified storage management that handles both physical storage and virtual machines
through a single interface. This command provides seamless integration between
D-Bus/udisks2 for disk operations and libvirt for VM management.

Examples:
  # Create a disk volume
  eos create storage --type volume --name /dev/sdb --size 50GB --filesystem ext4

  # Create a VM with storage
  eos create storage --type vm --name web-server --size 20GB --memory 2GB --vcpus 2

  # Create encrypted storage
  eos create storage --type volume --name /dev/sdc --encrypted --mount-point /mnt/secure`,
	RunE: eos_cli.Wrap(createStorageUnified),
}

var (
	unifiedType       string
	unifiedName       string
	unifiedSize       string
	unifiedFilesystem string
	unifiedMountPoint string
	unifiedEncrypted  bool
	unifiedMemory     string
	unifiedVCPUs      int
	unifiedNetwork    string
	unifiedOSVariant  string
	unifiedSSHKeys    []string
	unifiedVolumes    []string
	unifiedCloudInit  string
	unifiedDryRun     bool
	unifiedForce      bool
)

func init() {
	storageUnifiedCmd.Flags().StringVar(&unifiedType, "type", "volume", "Storage type (volume, vm)")
	storageUnifiedCmd.Flags().StringVar(&unifiedName, "name", "", "Storage name or device path")
	storageUnifiedCmd.Flags().StringVar(&unifiedSize, "size", "", "Storage size (e.g., 10GB, 500MB)")
	storageUnifiedCmd.Flags().StringVar(&unifiedFilesystem, "filesystem", "ext4", "Filesystem type for volumes")
	storageUnifiedCmd.Flags().StringVar(&unifiedMountPoint, "mount-point", "", "Mount point for volumes")
	storageUnifiedCmd.Flags().BoolVar(&unifiedEncrypted, "encrypted", false, "Enable encryption for volumes")
	storageUnifiedCmd.Flags().StringVar(&unifiedMemory, "memory", "1GB", "Memory for VMs")
	storageUnifiedCmd.Flags().IntVar(&unifiedVCPUs, "vcpus", 1, "vCPUs for VMs")
	storageUnifiedCmd.Flags().StringVar(&unifiedNetwork, "network", "default", "Network for VMs")
	storageUnifiedCmd.Flags().StringVar(&unifiedOSVariant, "os-variant", "ubuntu20.04", "OS variant for VMs")
	storageUnifiedCmd.Flags().StringSliceVar(&unifiedSSHKeys, "ssh-keys", []string{}, "SSH keys for VMs")
	storageUnifiedCmd.Flags().StringSliceVar(&unifiedVolumes, "volumes", []string{}, "Additional volumes for VMs")
	storageUnifiedCmd.Flags().StringVar(&unifiedCloudInit, "cloud-init", "", "Cloud-init data for VMs")
	storageUnifiedCmd.Flags().BoolVar(&unifiedDryRun, "dry-run", false, "Show what would be done")
	storageUnifiedCmd.Flags().BoolVar(&unifiedForce, "force", false, "Force operation")

	_ = storageUnifiedCmd.MarkFlagRequired("name")
}

func createStorageUnified(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Creating unified storage",
		zap.String("type", unifiedType),
		zap.String("name", unifiedName),
		zap.String("size", unifiedSize),
		zap.Bool("dry_run", unifiedDryRun))

	// Parse size
	var sizeBytes uint64
	if unifiedSize != "" {
		var err error
		sizeBytes, err = utils.ParseStorageSize(unifiedSize)
		if err != nil {
			return fmt.Errorf("invalid storage size: %w", err)
		}
	}

	// Create storage request
	request := &unified.StorageRequest{
		Type:       unifiedType,
		Name:       unifiedName,
		Size:       sizeBytes,
		Filesystem: unifiedFilesystem,
		Encrypted:  unifiedEncrypted,
		MountPoint: unifiedMountPoint,
		Metadata: map[string]string{
			"created_by": "eos-cli",
			"command":    "create_storage_unified",
		},
	}

	// Add VM configuration if type is vm
	if unifiedType == "vm" {
		memoryMB, err := utils.ParseMemorySize(vmMemory)
		if err != nil {
			return fmt.Errorf("invalid memory size: %w", err)
		}

		volumes, err := parseVolumeSpecs(vmVolumes)
		if err != nil {
			return fmt.Errorf("invalid volume format: %w", err)
		}

		request.VMConfig = &unified.VMStorageConfig{
			Memory:    memoryMB,
			VCPUs:     uint(vmVCPUs),
			Network:   vmNetwork,
			OSVariant: vmOSVariant,
			SSHKeys:   vmSSHKeys,
			CloudInit: vmCloudInit,
			Volumes:   volumes,
		}
	}

	// Handle dry-run
	if unifiedDryRun {
		return showUnifiedDryRun(rc, request)
	}

	// Initialize storage manager
	storageManager, err := unified.NewUnifiedStorageManager(rc)
	if err != nil {
		return fmt.Errorf("failed to initialize storage manager: %w", err)
	}
	defer func() { _ = storageManager.Close() }()

	// Create storage
	storageInfo, err := storageManager.CreateStorage(rc.Ctx, request)
	if err != nil {
		return fmt.Errorf("failed to create storage: %w", err)
	}

	// Display results
	logger.Info("Storage created successfully",
		zap.String("name", storageInfo.Name),
		zap.String("type", storageInfo.Type),
		zap.String("status", storageInfo.Status))

	displayUnifiedStorageInfo(rc, storageInfo)

	return nil
}


func parseVolumeSpecs(volumeSpecs []string) ([]unified.VolumeSpec, error) {
	volumes := make([]unified.VolumeSpec, 0, len(volumeSpecs))

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

		size, err := utils.ParseStorageSize(sizeStr)
		if err != nil {
			return nil, fmt.Errorf("invalid volume size: %s", sizeStr)
		}

		volumes = append(volumes, unified.VolumeSpec{
			Name:   name,
			Size:   size,
			Format: format,
		})
	}

	return volumes, nil
}

// showUnifiedDryRun displays what would be done in a dry-run mode
func showUnifiedDryRun(_ *eos_io.RuntimeContext, request *unified.StorageRequest) error {
	fmt.Println("=== UNIFIED STORAGE DRY RUN ===")
	fmt.Printf("Would create %s storage with the following configuration:\n\n", request.Type)
	fmt.Printf("Name:         %s\n", request.Name)
	fmt.Printf("Type:         %s\n", request.Type)
	fmt.Printf("Size:         %s\n", utils.FormatBytes(request.Size))

	if request.Type == "volume" {
		fmt.Printf("Filesystem:   %s\n", request.Filesystem)
		fmt.Printf("Mount Point:  %s\n", request.MountPoint)
		fmt.Printf("Encrypted:    %t\n", request.Encrypted)
	}

	if request.Type == "vm" && request.VMConfig != nil {
		fmt.Printf("Memory:       %d MB\n", request.VMConfig.Memory)
		fmt.Printf("vCPUs:        %d\n", request.VMConfig.VCPUs)
		fmt.Printf("Network:      %s\n", request.VMConfig.Network)
		fmt.Printf("OS Variant:   %s\n", request.VMConfig.OSVariant)

		if len(request.VMConfig.SSHKeys) > 0 {
			fmt.Printf("SSH Keys:     %d keys\n", len(request.VMConfig.SSHKeys))
		}

		if len(request.VMConfig.Volumes) > 0 {
			fmt.Printf("Additional Volumes:\n")
			for _, vol := range request.VMConfig.Volumes {
				fmt.Printf("  - %s: %s (%s)\n", vol.Name, utils.FormatBytes(vol.Size), vol.Format)
			}
		}
	}

	fmt.Printf("\nOperations that would be performed:\n")

	switch request.Type {
	case "volume":
		fmt.Printf("1. Validate device %s\n", request.Name)
		fmt.Printf("2. Create partition table if needed\n")
		fmt.Printf("3. Create partition\n")
		if request.Encrypted {
			fmt.Printf("4. Setup encryption\n")
			fmt.Printf("5. Create %s filesystem\n", request.Filesystem)
		} else {
			fmt.Printf("4. Create %s filesystem\n", request.Filesystem)
		}
		if request.MountPoint != "" {
			fmt.Printf("5. Mount at %s\n", request.MountPoint)
		}
	case "vm":
		fmt.Printf("1. Create VM storage volumes\n")
		fmt.Printf("2. Generate cloud-init configuration\n")
		fmt.Printf("3. Define VM in libvirt\n")
		fmt.Printf("4. Start VM\n")
	}

	fmt.Printf("\nNo changes were made. Use --dry-run=false to execute.\n")
	return nil
}

// displayUnifiedStorageInfo displays detailed information about created storage
func displayUnifiedStorageInfo(_ *eos_io.RuntimeContext, storage *unified.StorageInfo) {
	fmt.Printf("\n=== %s Storage Created Successfully ===\n\n", strings.Title(storage.Type))
	fmt.Printf("Name:         %s\n", storage.Name)
	fmt.Printf("Type:         %s\n", storage.Type)
	fmt.Printf("Status:       %s\n", storage.Status)
	fmt.Printf("Size:         %s\n", utils.FormatBytes(storage.Size))

	if storage.Used > 0 {
		fmt.Printf("Used:         %s\n", utils.FormatBytes(storage.Used))
		fmt.Printf("Available:    %s\n", utils.FormatBytes(storage.Available))
		fmt.Printf("Usage:        %.1f%%\n", float64(storage.Used)/float64(storage.Size)*100)
	}

	fmt.Printf("Health:       %s\n", storage.Health)
	fmt.Printf("Location:     %s\n", storage.Location)
	fmt.Printf("Created:      %s\n", storage.CreatedAt.Format(time.RFC3339))

	if len(storage.Metadata) > 0 {
		fmt.Printf("Metadata:\n")
		for key, value := range storage.Metadata {
			fmt.Printf("  %s: %s\n", key, value)
		}
	}

	// Type-specific information
	switch storage.Type {
	case "volume":
		fmt.Printf("\nVolume Management Commands:\n")
		fmt.Printf("  Mount:      eos mount %s /path/to/mount\n", storage.Name)
		fmt.Printf("  Unmount:    eos unmount %s\n", storage.Name)
		fmt.Printf("  Resize:     eos resize storage %s --size 100GB\n", storage.Name)
		fmt.Printf("  Health:     eos health storage %s\n", storage.Name)
	case "vm":
		fmt.Printf("\nVM Management Commands:\n")
		fmt.Printf("  Start:      eos start vm %s\n", storage.Name)
		fmt.Printf("  Stop:       eos stop vm %s\n", storage.Name)
		fmt.Printf("  Console:    virsh console %s\n", storage.Name)
		fmt.Printf("  Info:       eos info vm %s\n", storage.Name)
	}

	fmt.Printf("\nStorage is ready for use!\n")
}
