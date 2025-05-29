/* cmd/inspect/ldap.go */
package read

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/ldap"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

var InspectLDAPCmd = &cobra.Command{
	Use:     "ldap",
	Aliases: []string{"directory"},
	Short:   "Auto-discover and inspect LDAP",
	Long:    "Attempts to auto-discover an LDAP server and show config, users, and groups.",
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		otelzap.Ctx(rc.Ctx).Info("Launching interactive LDAP query tool")

		return ldap.InteractiveLDAPQuery(rc)
	}),
}

func init() {

	// Core LDAP command
	ReadCmd.AddCommand(InspectLDAPCmd)
	ldap.InitFlags(InspectLDAPCmd)
}
