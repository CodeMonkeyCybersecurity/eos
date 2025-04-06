package flags

import (
	"fmt"

	"github.com/spf13/cobra"
)

var DryRun = true // Default is dry-run mode (safe)

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

// Call this inside main.go to define all aliases
func AddDryRunFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().Bool("live-run", false, "Apply changes (default is dry-run)")
	cmd.PersistentFlags().Bool("apply", false, "Alias for --live-run")
	cmd.PersistentFlags().Bool("force", false, "Alias for --live-run")
	cmd.PersistentFlags().Bool("do-it", false, "Alias for --live-run")
	cmd.PersistentFlags().BoolP("live", "L", false, "Alias for --live-run")
}

// Call this inside each command’s RunE() to parse flags
func ParseDryRunAliases(cmd *cobra.Command) {
	liveRun, _ := cmd.Flags().GetBool("live-run")
	apply, _ := cmd.Flags().GetBool("apply")
	force, _ := cmd.Flags().GetBool("force")
	doit, _ := cmd.Flags().GetBool("do-it")
	liveShort, _ := cmd.Flags().GetBool("live")

	if liveRun || apply || force || doit || liveShort {
		SetDryRunMode(false)
	}
}
