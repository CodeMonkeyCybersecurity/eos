// Package output provides disk usage table formatting
package output

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/storage/monitor"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/utils"
)

// DiskUsageTable outputs disk usage information in a formatted table.
// It follows the Assess → Intervene → Evaluate pattern.
func DiskUsageTable(usage []monitor.DiskUsage, showInodes bool) error {
	// ASSESS - Prepare table writer
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	// INTERVENE - Write main disk usage table
	// Header
	_, _ = fmt.Fprintf(w, "FILESYSTEM\tDEVICE\tSIZE\tUSED\tAVAIL\tUSE%%\tMOUNTED ON\n")

	for _, u := range usage {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%.1f%%\t%s\n",
			u.Filesystem,
			u.Device,
			utils.FormatBytes(u.TotalSize),
			utils.FormatBytes(u.UsedSize),
			utils.FormatBytes(u.AvailableSize),
			u.UsedPercent,
			u.Path)
	}

	if err := w.Flush(); err != nil {
		fmt.Printf("Warning: Failed to flush output: %v\n", err)
	}

	// EVALUATE - Add inode table if requested
	if showInodes {
		fmt.Println("\nINODE USAGE:")
		w = tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		_, _ = fmt.Fprintf(w, "FILESYSTEM\tINODES\tIUSED\tIFREE\tIUSE%%\n")

		for _, u := range usage {
			_, _ = fmt.Fprintf(w, "%s\t%d\t%d\t%d\t%.1f%%\n",
				u.Filesystem,
				u.InodesTotal,
				u.InodesUsed,
				u.InodesFree,
				u.InodesUsedPercent)
		}

		if err := w.Flush(); err != nil {
		fmt.Printf("Warning: Failed to flush output: %v\n", err)
	}
	}

	return nil
}
