package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/zfs_management"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// NewZFSCmd creates the zfs command
func NewZFSCmd() *cobra.Command {
	var (
		outputJSON bool
		dryRun     bool
		force      bool
		recursive  bool
	)

	cmd := &cobra.Command{
		Use:   "zfs",
		Short: "Manage ZFS pools and filesystems",
		Long: `Manage ZFS (Z File System) pools, datasets, and filesystems.

ZFS is an advanced filesystem with features like snapshots, compression, 
checksums, and built-in RAID functionality.

This command provides both interactive TUI and direct CLI interfaces:
- Run without subcommands for interactive menu
- Use subcommands for direct operations

Examples:
  eos storage zfs                              # Interactive TUI menu
  eos storage zfs list pools                   # List all ZFS pools
  eos storage zfs list filesystems             # List all ZFS filesystems  
  eos storage zfs expand mypool /dev/sdb       # Add device to pool
  eos storage zfs destroy pool mypool          # Destroy a pool
  eos storage zfs destroy filesystem tank/data # Destroy a filesystem`,
		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)
			logger.Info("Starting interactive ZFS management")

			config := &zfs_management.ZFSConfig{
				DryRun:             dryRun,
				Verbose:            true,
				Force:              force,
				Recursive:          recursive,
				ConfirmDestructive: true,
			}

			manager := zfs_management.NewZFSManager(config)

			// Check if ZFS is available before starting TUI
			if err := manager.CheckZFSAvailable(rc); err != nil {
				return err
			}

			return zfs_management.RunZFSTUI(manager, rc)
		}),
	}

	// Add subcommands
	cmd.AddCommand(NewZFSListCmd())
	cmd.AddCommand(NewZFSExpandCmd())
	cmd.AddCommand(NewZFSDestroyCmd())

	// Add flags
	cmd.PersistentFlags().BoolVar(&outputJSON, "json", false, "Output results in JSON format")
	cmd.PersistentFlags().BoolVar(&dryRun, "dry-run", false, "Show what would be done without making changes")
	cmd.PersistentFlags().BoolVar(&force, "force", false, "Force the operation (use with caution)")
	cmd.PersistentFlags().BoolVar(&recursive, "recursive", false, "Apply operation recursively")

	return cmd
}

// NewZFSListCmd creates the list subcommand
func NewZFSListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list [pools|filesystems]",
		Short: "List ZFS pools or filesystems",
		Long: `List ZFS resources with detailed information.

Available targets:
- pools: List all ZFS storage pools
- filesystems: List all ZFS filesystems and datasets

Examples:
  eos storage zfs list pools        # List all ZFS pools
  eos storage zfs list filesystems  # List all ZFS filesystems`,
		Args:      cobra.ExactArgs(1),
		ValidArgs: []string{"pools", "filesystems"},
		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)

			outputJSON, _ := cmd.Flags().GetBool("json")
			dryRun, _ := cmd.Flags().GetBool("dry-run")

			config := &zfs_management.ZFSConfig{
				DryRun:  dryRun,
				Verbose: true,
			}

			manager := zfs_management.NewZFSManager(config)

			switch args[0] {
			case "pools":
				logger.Info("Listing ZFS pools")
				result, err := manager.ListPools(rc)
				if err != nil {
					return err
				}
				return outputZFSListResult(result, outputJSON, "pools")

			case "filesystems":
				logger.Info("Listing ZFS filesystems")
				result, err := manager.ListFilesystems(rc)
				if err != nil {
					return err
				}
				return outputZFSListResult(result, outputJSON, "filesystems")

			default:
				return fmt.Errorf("invalid list target: %s. Use 'pools' or 'filesystems'", args[0])
			}
		}),
	}

	return cmd
}

// NewZFSExpandCmd creates the expand subcommand
func NewZFSExpandCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "expand <pool> <device>",
		Short: "Expand a ZFS pool by adding a device",
		Long: `Add a device to an existing ZFS pool to expand its capacity.

The device will be added to the pool, increasing the available storage space.
This operation is non-destructive and does not affect existing data.

Examples:
  eos storage zfs expand mypool /dev/sdb      # Add /dev/sdb to mypool
  eos storage zfs expand tank /dev/disk/by-id/scsi-123  # Add device by ID
  eos storage zfs expand --dry-run mypool /dev/sdc      # Preview the operation`,
		Args: cobra.ExactArgs(2),
		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)

			outputJSON, _ := cmd.Flags().GetBool("json")
			dryRun, _ := cmd.Flags().GetBool("dry-run")
			force, _ := cmd.Flags().GetBool("force")

			poolName := args[0]
			device := args[1]

			logger.Info("Expanding ZFS pool",
				zap.String("pool", poolName),
				zap.String("device", device),
				zap.Bool("dry_run", dryRun))

			config := &zfs_management.ZFSConfig{
				DryRun:  dryRun,
				Verbose: true,
				Force:   force,
			}

			manager := zfs_management.NewZFSManager(config)

			// Validate pool exists
			exists, err := manager.ValidatePoolExists(rc, poolName)
			if err != nil {
				return err
			}
			if !exists {
				return fmt.Errorf("ZFS pool '%s' does not exist", poolName)
			}

			result, err := manager.ExpandPool(rc, poolName, device)
			if err != nil {
				return err
			}

			return outputZFSOperationResult(result, outputJSON)
		}),
	}

	return cmd
}

// NewZFSDestroyCmd creates the destroy subcommand
func NewZFSDestroyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "destroy [pool|filesystem] <name>",
		Short: "Destroy a ZFS pool or filesystem",
		Long: `Permanently destroy a ZFS pool or filesystem.

⚠️  WARNING: This operation is DESTRUCTIVE and will permanently delete all data!
Use with extreme caution and ensure you have backups of important data.

Available targets:
- pool: Destroy an entire ZFS pool and all its data
- filesystem: Destroy a specific ZFS filesystem or dataset

Examples:
  eos storage zfs destroy pool mypool           # Destroy entire pool
  eos storage zfs destroy filesystem tank/data  # Destroy specific filesystem
  eos storage zfs destroy --dry-run pool mypool # Preview destruction
  eos storage zfs destroy --force pool mypool   # Force destruction (skip some checks)`,
		Args:      cobra.ExactArgs(2),
		ValidArgs: []string{"pool", "filesystem"},
		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)

			outputJSON, _ := cmd.Flags().GetBool("json")
			dryRun, _ := cmd.Flags().GetBool("dry-run")
			force, _ := cmd.Flags().GetBool("force")
			recursive, _ := cmd.Flags().GetBool("recursive")

			target := args[0]
			name := args[1]

			logger.Info("Destroying ZFS resource",
				zap.String("target", target),
				zap.String("name", name),
				zap.Bool("dry_run", dryRun),
				zap.Bool("force", force))

			config := &zfs_management.ZFSConfig{
				DryRun:    dryRun,
				Verbose:   true,
				Force:     force,
				Recursive: recursive,
			}

			manager := zfs_management.NewZFSManager(config)

			var result *zfs_management.ZFSOperationResult
			var err error

			switch target {
			case "pool":
				// Validate pool exists
				exists, err := manager.ValidatePoolExists(rc, name)
				if err != nil {
					return err
				}
				if !exists {
					return fmt.Errorf("ZFS pool '%s' does not exist", name)
				}

				result, err = manager.DestroyPool(rc, name)

			case "filesystem":
				// Validate filesystem exists
				exists, err := manager.ValidateFilesystemExists(rc, name)
				if err != nil {
					return err
				}
				if !exists {
					return fmt.Errorf("ZFS filesystem '%s' does not exist", name)
				}

				result, err = manager.DestroyFilesystem(rc, name)

			default:
				return fmt.Errorf("invalid destroy target: %s. Use 'pool' or 'filesystem'", target)
			}

			if err != nil {
				return err
			}

			return outputZFSOperationResult(result, outputJSON)
		}),
	}

	return cmd
}

// Helper functions for output formatting

func outputZFSListResult(result *zfs_management.ZFSListResult, outputJSON bool, listType string) error {
	if outputJSON {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(result)
	}

	// Text output
	if listType == "pools" {
		if len(result.Pools) == 0 {
			fmt.Println("No ZFS pools found.")
			return nil
		}

		fmt.Printf("ZFS Pools (found %d):\n", result.Count)
		fmt.Println(strings.Repeat("=", 80))
		fmt.Printf("%-15s %-8s %-8s %-8s %-5s %-5s %-8s %-10s\n",
			"NAME", "SIZE", "ALLOC", "FREE", "FRAG", "CAP", "DEDUP", "HEALTH")
		fmt.Println(strings.Repeat("-", 80))

		for _, pool := range result.Pools {
			fmt.Printf("%-15s %-8s %-8s %-8s %-5s %-5s %-8s %-10s\n",
				pool.Name, pool.Size, pool.Alloc, pool.Free, pool.Frag,
				pool.Cap, pool.Dedup, pool.Health)
		}
	} else {
		if len(result.Filesystems) == 0 {
			fmt.Println("No ZFS filesystems found.")
			return nil
		}

		fmt.Printf("ZFS Filesystems (found %d):\n", result.Count)
		fmt.Println(strings.Repeat("=", 80))
		fmt.Printf("%-30s %-10s %-10s %-10s %-15s\n",
			"NAME", "USED", "AVAIL", "REFER", "MOUNTPOINT")
		fmt.Println(strings.Repeat("-", 80))

		for _, fs := range result.Filesystems {
			mountpoint := fs.Mountpoint
			if mountpoint == "" {
				mountpoint = "-"
			}
			fmt.Printf("%-30s %-10s %-10s %-10s %-15s\n",
				fs.Name, fs.Used, fs.Available, fs.Refer, mountpoint)
		}
	}

	return nil
}

func outputZFSOperationResult(result *zfs_management.ZFSOperationResult, outputJSON bool) error {
	if outputJSON {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(result)
	}

	// Text output
	fmt.Printf("ZFS Operation: %s\n", result.Operation)
	fmt.Printf("Target: %s\n", result.Target)
	fmt.Printf("Timestamp: %s\n", result.Timestamp.Format("2006-01-02 15:04:05"))
	fmt.Println(strings.Repeat("=", 50))

	if result.Success {
		fmt.Println(" Operation completed successfully!")
	} else {
		fmt.Println("❌ Operation failed!")
	}

	if result.Output != "" {
		fmt.Printf("\nOutput:\n%s\n", result.Output)
	}

	if result.Error != "" {
		fmt.Printf("\nError:\n%s\n", result.Error)
	}

	if result.DryRun {
		fmt.Println("\n This was a dry run - no actual changes were made.")
	}

	return nil
}
