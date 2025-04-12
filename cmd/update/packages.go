/* cmd/update/packages.go */
package update

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/spf13/cobra"
)

var Cron bool

var UpdatePackagesCmd = &cobra.Command{
	Use:     "packages",
	Aliases: []string{"pkgs"},
	Short:   "Update system packages based on detected OS",
	Long:    "Detects the host OS and executes the appropriate update and cleanup commands. Supports scheduling via --cron.",
	RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {
		return platform.RunPackageUpdate(Cron)
	}),
}

func init() {
	UpdateCmd.AddCommand(UpdatePackagesCmd)
	UpdatePackagesCmd.Flags().BoolVar(&Cron, "cron", false, "Schedule this update to run daily at a random time")
}
