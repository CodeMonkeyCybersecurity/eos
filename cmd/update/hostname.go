// cmd/update/hostname.go
package update

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/domain/sysinfo"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
)

var UpdateHostnameCmd = &cobra.Command{
	Use:   "hostname",
	Short: "Update the system hostname",
	Long:  `Update the system hostname by modifying /etc/hostname and /etc/hosts.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		return sysinfo.UpdateHostname(rc)
	}),
}

// init registers subcommands for the update command
func init() {
	UpdateCmd.AddCommand(UpdateHostnameCmd)
}
