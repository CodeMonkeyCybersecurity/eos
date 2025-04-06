// cmd/inspect/ldap.go
package inspect

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/ldap"
	"github.com/spf13/cobra"
)

var InspectLDAPUsersCmd = &cobra.Command{
	Use:     "ldap-users",
	Aliases: []string{"users"},
	Short:   "List all LDAP users",
	Long:    "Retrieves a list of LDAP users (uid entries) from the directory.",
	RunE: func(cmd *cobra.Command, args []string) error {
		return ldap.PrintUsers()
	},
}

var InspectLDAPGroupsCmd = &cobra.Command{
	Use:     "ldap-groups",
	Aliases: []string{"groups"},
	Short:   "List all LDAP groups",
	Long:    "Retrieves a list of LDAP groups and their members from the directory.",
	RunE: func(cmd *cobra.Command, args []string) error {
		return ldap.PrintGroups()
	},
}

var InspectLDAPUserCmd = &cobra.Command{
	Use:   "ldap-user [uid]",
	Short: "Get a single LDAP user",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return ldap.PrintUser(args[0])
	},
}

func init() {
	InspectCmd.AddCommand(InspectLDAPUsersCmd)
	InspectCmd.AddCommand(InspectLDAPGroupsCmd)
	InspectCmd.AddCommand(InspectLDAPUserCmd)
}
