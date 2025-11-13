// pkg/backup/display/filter.go
//
// Snapshot filtering business logic.
// Migrated from cmd/list/backups.go to consolidate backup display operations.

package display

import (
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/backup"
)

// FilterSnapshots applies filters to snapshot list and returns filtered results.
// This is business logic that was previously in cmd/list/backups.go.
//
// Filters applied:
//   - filterTags: Include only snapshots with at least one matching tag
//   - filterHost: Include only snapshots from specific hostname
//   - filterPath: Include only snapshots containing specified path
//   - lastN: Limit to last N snapshots (0 = no limit)
//
// Returns empty slice if snapshots is nil.
func FilterSnapshots(snapshots []backup.Snapshot, filterTags []string, filterHost, filterPath string, lastN int) []backup.Snapshot {
	if snapshots == nil {
		return []backup.Snapshot{}
	}

	filtered := []backup.Snapshot{}

	for _, snap := range snapshots {
		// Tag filter
		if len(filterTags) > 0 {
			hasTag := false
			for _, tag := range filterTags {
				for _, snapTag := range snap.Tags {
					if tag == snapTag {
						hasTag = true
						break
					}
				}
				if hasTag {
					break
				}
			}
			if !hasTag {
				continue
			}
		}

		// Host filter
		if filterHost != "" && snap.Hostname != filterHost {
			continue
		}

		// Path filter
		if filterPath != "" {
			hasPath := false
			for _, path := range snap.Paths {
				if strings.Contains(path, filterPath) {
					hasPath = true
					break
				}
			}
			if !hasPath {
				continue
			}
		}

		filtered = append(filtered, snap)
	}

	// Apply last N limit
	if lastN > 0 && len(filtered) > lastN {
		filtered = filtered[len(filtered)-lastN:]
	}

	return filtered
}
