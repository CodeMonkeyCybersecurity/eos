package flags

import (
	"fmt"

	"github.com/spf13/cobra"
)

var DryRun = true // Default is dry-run mode (safe)
var addedDryRunFlags = false

func IsDryRun() bool {
	return DryRun
}

func IsLiveRun() bool {
	return !DryRun
}

func PrintDryRunNotice() {
	if DryRun {
		fmt.Println("🧪 Dry run is active. No changes will be made.")
	}
}

func SetDryRunMode(v bool) {
	DryRun = !v // Invert because `--live-run` means DryRun = false
	if DryRun {
		fmt.Println("🔒 Eos is running in dry-run mode.")
	} else {
		fmt.Println("⚠️  Live-run enabled. Changes will be applied.")
	}
}

// Register dry-run flags exactly once
func AddDryRunFlags(cmd *cobra.Command) {
	if addedDryRunFlags {
		return
	}
	addedDryRunFlags = true

	cmd.PersistentFlags().Bool("live-run", false, "Apply changes (default is dry-run)")
	cmd.PersistentFlags().BoolP("live", "L", false, "Alias for --live-run")
}

func ParseDryRunAliases(cmd *cobra.Command) {
	// Access the flags from the root command
	liveRun, _ := cmd.Root().PersistentFlags().GetBool("live-run")
	liveShort, _ := cmd.Root().PersistentFlags().GetBool("live")
	fmt.Printf("Debug: root live-run=%v, live=%v\n", liveRun, liveShort)

	if liveRun || liveShort {
		SetDryRunMode(true)
	}
}
