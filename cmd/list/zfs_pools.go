// cmd/list/zfs_pools.go
package list

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

var zfsPoolsCmd = &cobra.Command{
	Use:     "zfs-pools",
	Aliases: []string{"zfs-pool", "zpool", "zpools"},
	Short:   "List ZFS storage pools",
	Long: `List all ZFS storage pools with detailed information.

Shows pool name, size, allocation, free space, fragmentation, capacity, deduplication, and health status.

Examples:
  eos list zfs-pools                    # List all ZFS pools
  eos list zfs-pools --json            # Output in JSON format`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info("Listing ZFS pools")

		outputJSON, _ := cmd.Flags().GetBool("json")
		dryRun, _ := cmd.Flags().GetBool("dry-run")

		config := &zfs_management.ZFSConfig{
			DryRun:  dryRun,
			Verbose: true,
		}

		manager := zfs_management.NewZFSManager(config)

		// Check if ZFS is available
		if err := manager.CheckZFSAvailable(rc); err != nil {
			return err
		}

		result, err := manager.ListPools(rc)
		if err != nil {
			logger.Error("Failed to list ZFS pools", zap.Error(err))
			return err
		}

		return outputZFSPoolsResult(result, outputJSON)
	}),
}

func init() {
	zfsPoolsCmd.Flags().Bool("json", false, "Output in JSON format")
	zfsPoolsCmd.Flags().Bool("dry-run", false, "Show what would be done without making changes")

	ListCmd.AddCommand(zfsPoolsCmd)
}

func outputZFSPoolsResult(result *zfs_management.ZFSListResult, outputJSON bool) error {
	if outputJSON {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(result)
	}

	// Text output
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

	return nil
}
