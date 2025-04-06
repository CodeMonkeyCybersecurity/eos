// cmd/inspect/ldap.go
package inspect

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/ldap"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var InspectLDAPUsersCmd = &cobra.Command{
	Use:     "ldap-users",
	Aliases: []string{"users"},
	Short:   "List all LDAP users",
	Long:    "Retrieves a list of LDAP users (uid entries) from the directory.",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, source, err := ldap.LoadLDAPConfig()
		if err != nil {
			log.Error("Failed to load LDAP config", zap.Error(err))
			return err
		}
		log.Info("LDAP config loaded", zap.String("source", source), zap.String("fqdn", cfg.FQDN))

		return ldap.PrintUsers()
	},
}

var InspectLDAPGroupsCmd = &cobra.Command{
	Use:     "ldap-groups",
	Aliases: []string{"groups"},
	Short:   "List all LDAP groups",
	Long:    "Retrieves a list of LDAP groups and their members from the directory.",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, source, err := ldap.LoadLDAPConfig()
		if err != nil {
			log.Error("Failed to load LDAP config", zap.Error(err))
			return err
		}
		log.Info("LDAP config loaded", zap.String("source", source), zap.String("fqdn", cfg.FQDN))

		return ldap.PrintGroups()
	},
}

var InspectLDAPUserCmd = &cobra.Command{
	Use:   "ldap-user [uid]",
	Short: "Get a single LDAP user",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		log.Info("Looking up LDAP user", zap.String("uid", args[0]))
		return ldap.PrintUser(args[0])
	},
}

var InspectLDAPGroupCmd = &cobra.Command{
	Use:   "ldap-group [cn]",
	Short: "Get a single LDAP group",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		log.Info("Looking up LDAP group", zap.String("cn", args[0]))
		return ldap.PrintGroup(args[0])
	},
}

func init() {
	log = logger.L()

	InspectCmd.AddCommand(InspectLDAPUsersCmd)
	InspectCmd.AddCommand(InspectLDAPGroupsCmd)
	InspectCmd.AddCommand(InspectLDAPUserCmd)
	InspectCmd.AddCommand(InspectLDAPGroupCmd)
}
