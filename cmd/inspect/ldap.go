/* cmd/inspect/ldap.go */
package inspect

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/ldap"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/spf13/cobra"
)

var InspectLDAPCmd = &cobra.Command{
	Use:     "ldap",
	Aliases: []string{"directory"},
	Short:   "Auto-discover and inspect LDAP",
	Long:    "Attempts to auto-discover an LDAP server and show config, users, and groups.",
	RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {
		log.Info("Launching interactive LDAP query tool")

		return ldap.InteractiveLDAPQuery(log)
	}),
}

func init() {
	log = logger.L()

	// Core LDAP command
	InspectCmd.AddCommand(InspectLDAPCmd)
	ldap.InitFlags(InspectLDAPCmd)
}
