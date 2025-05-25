/* cmd/inspect/ldap.go */
package read

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/ldap"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var InspectLDAPCmd = &cobra.Command{
	Use:     "ldap",
	Aliases: []string{"directory"},
	Short:   "Auto-discover and inspect LDAP",
	Long:    "Attempts to auto-discover an LDAP server and show config, users, and groups.",
	RunE: eos.Wrap(func(ctx *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		zap.L().Info("Launching interactive LDAP query tool")

		return ldap.InteractiveLDAPQuery()
	}),
}

func init() {

	// Core LDAP command
	ReadCmd.AddCommand(InspectLDAPCmd)
	ldap.InitFlags(InspectLDAPCmd)
}
