// pkg/backup/display/snapshots.go
//
// Snapshot display formatting logic.
// Migrated from cmd/list/backups.go to consolidate backup display operations.

package display

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/backup"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ShowSnapshots displays snapshots in tabular format.
// This display logic was previously in cmd/list/backups.go.
//
// Parameters:
//   - rc: Runtime context for logging
//   - snapshots: List of snapshots to display
//   - detailed: If true, show additional columns (parent, full paths)
func ShowSnapshots(rc *eos_io.RuntimeContext, snapshots []backup.Snapshot, detailed bool) {
	if rc == nil || snapshots == nil {
		return
	}

	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("terminal prompt: \nBackup Snapshots:")
	logger.Info("terminal prompt:", zap.String("output", strings.Repeat("=", 140)))

	if detailed {
		// Detailed format with more information
		fmt.Printf("%-12s %-20s %-8s %-15s %-12s %-40s %s\n",
			"ID", "TIME", "AGE", "HOST", "PARENT", "PATHS", "TAGS")
		logger.Info("terminal prompt:", zap.String("output", strings.Repeat("-", 140)))

		for _, snap := range snapshots {
			id := shared.TruncateString(snap.ID, 12)
			timeStr := snap.Time.Format("2006-01-02 15:04:05")
			age := shared.FormatAge(snap.Time)
			parent := shared.TruncateString(snap.Parent, 12)
			if parent == "" {
				parent = "-"
			}

			paths := strings.Join(snap.Paths, ", ")
			paths = shared.TruncateString(paths, 40)

			tags := strings.Join(snap.Tags, ", ")

			fmt.Printf("%-12s %-20s %-8s %-15s %-12s %-40s %s\n",
				id, timeStr, age, snap.Hostname, parent, paths, tags)
		}
	} else {
		// Compact format
		fmt.Printf("%-12s %-20s %-8s %-15s %-50s %s\n",
			"ID", "TIME", "AGE", "HOST", "PATHS", "TAGS")
		logger.Info("terminal prompt:", zap.String("output", strings.Repeat("-", 140)))

		for _, snap := range snapshots {
			id := shared.TruncateString(snap.ID, 12)
			timeStr := snap.Time.Format("2006-01-02 15:04:05")
			age := shared.FormatAge(snap.Time)

			paths := strings.Join(snap.Paths, ", ")
			paths = shared.TruncateString(paths, 50)

			tags := strings.Join(snap.Tags, ", ")

			fmt.Printf("%-12s %-20s %-8s %-15s %-50s %s\n",
				id, timeStr, age, snap.Hostname, paths, tags)
		}
	}

	logger.Info("terminal prompt:", zap.String("output", strings.Repeat("=", 140)))
	logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("Total snapshots: %d", len(snapshots))))
}

// ShowSnapshotsGrouped displays snapshots grouped by a specified field.
// This display logic was previously in cmd/list/backups.go.
//
// Parameters:
//   - rc: Runtime context for logging
//   - snapshots: List of snapshots to display
//   - groupBy: Field to group by ("host"/"hostname", "tag", "date")
//   - detailed: If true, show detailed format for each group
func ShowSnapshotsGrouped(rc *eos_io.RuntimeContext, snapshots []backup.Snapshot, groupBy string, detailed bool) {
	if rc == nil || snapshots == nil {
		return
	}

	logger := otelzap.Ctx(rc.Ctx)

	// Group snapshots
	groups := make(map[string][]backup.Snapshot)

	for _, snap := range snapshots {
		var key string
		switch groupBy {
		case "host", "hostname":
			key = snap.Hostname
		case "tag":
			if len(snap.Tags) > 0 {
				key = snap.Tags[0]
			} else {
				key = "(no tags)"
			}
		case "date":
			key = snap.Time.Format("2006-01-02")
		default:
			key = "all"
		}

		groups[key] = append(groups[key], snap)
	}

	// Display each group
	for groupName, groupSnapshots := range groups {
		logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("\n%s: %s (%d snapshots)",
			strings.ToUpper(groupBy), groupName, len(groupSnapshots))))
		logger.Info("terminal prompt:", zap.String("output", strings.Repeat("=", 140)))

		ShowSnapshots(rc, groupSnapshots, detailed)
	}
}
