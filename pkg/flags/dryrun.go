// pkg/flags/dryrun.go

package flags

import "fmt"

var DryRun = true // Default to dry-run mode

func IsDryRun() bool {
	return DryRun
}

func PrintDryRunNotice() {
	if DryRun {
		fmt.Println("🧪 Dry run is active. No changes will be made.")
	}
}

func IsLiveRun() bool {
	return !DryRun
}

func SetDryRunMode(v bool) {
	DryRun = v
	if DryRun {
		fmt.Println("🔒 Eos is running in dry-run mode.")
	} else {
		fmt.Println("⚠️  Live-run enabled. Changes will be applied.")
	}
}
