// pkg/backup/display/stats.go
//
// Repository statistics display formatting logic.
// Migrated from cmd/list/backups.go to consolidate backup display operations.

package display

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/backup"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
)

// ShowRepositoryStats displays repository statistics in human-readable format.
// This display logic was previously in cmd/list/backups.go.
//
// Parameters:
//   - rc: Runtime context (not used currently, but kept for consistency)
//   - stats: Repository statistics to display
func ShowRepositoryStats(rc *eos_io.RuntimeContext, stats *backup.RepositoryStats) {
	if stats == nil {
		return
	}

	fmt.Printf("Repository: %s\n", stats.RepositoryID)
	fmt.Printf("Total Size: %s\n", shared.FormatBytes(stats.TotalSize))
	fmt.Printf("Total Files: %d\n", stats.TotalFileCount)
	fmt.Printf("Total Snapshots: %d\n", stats.SnapshotCount)
	fmt.Printf("Compression Ratio: %.2f%%\n", stats.CompressionRatio*100)

	if stats.LastCheck.IsZero() {
		fmt.Printf("Last Check: Never\n")
	} else {
		fmt.Printf("Last Check: %s (%s ago)\n",
			stats.LastCheck.Format("2006-01-02 15:04:05"),
			shared.FormatAge(stats.LastCheck))
	}

	if len(stats.HostStats) > 0 {
		fmt.Printf("\nPer-Host Statistics:\n")
		for host, hostStat := range stats.HostStats {
			fmt.Printf("  %s: %d snapshots, %s\n",
				host, hostStat.SnapshotCount, shared.FormatBytes(hostStat.Size))
		}
	}
}
