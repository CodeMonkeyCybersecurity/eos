// cmd/inspect/ldap.go
package inspect

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/ldap"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var InspectLDAPCmd = &cobra.Command{
	Use:     "ldap",
	Aliases: []string{"directory"},
	Short:   "Auto-discover and inspect LDAP",
	Long:    "Attempts to auto-discover an LDAP server and show config, users, and groups.",
	RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {
		cfg, source, err := ldap.LoadLDAPConfig()
		if err != nil {
			log.Error("Failed to load LDAP config", zap.Error(err))
			return err
		}
		log.Info("LDAP config loaded", zap.String("source", source), zap.String("fqdn", cfg.FQDN))

		if err := ldap.PrintUsers(); err != nil {
			return err
		}
		if err := ldap.PrintGroups(); err != nil {
			return err
		}
		return nil
	}),
}

var InspectLDAPUsersCmd = &cobra.Command{
	Use:   "users",
	Short: "List all LDAP users",
	RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {
		cfg, source, err := ldap.LoadLDAPConfig()
		if err != nil {
			log.Error("Failed to load LDAP config", zap.Error(err))
			return err
		}
		log.Info("LDAP config loaded", zap.String("source", source), zap.String("fqdn", cfg.FQDN))
		return ldap.PrintUsers()
	}),
}

var InspectLDAPGroupsCmd = &cobra.Command{
	Use:   "groups",
	Short: "List all LDAP groups",
	RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {
		cfg, source, err := ldap.LoadLDAPConfig()
		if err != nil {
			log.Error("Failed to load LDAP config", zap.Error(err))
			return err
		}
		log.Info("LDAP config loaded", zap.String("source", source), zap.String("fqdn", cfg.FQDN))
		return ldap.PrintGroups()
	}),
}

var InspectLDAPUserCmd = &cobra.Command{
	Use:   "user [uid]",
	Short: "Get a single LDAP user by UID",
	Args:  cobra.ExactArgs(1),
	RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {
		log.Info("Looking up LDAP user", zap.String("uid", args[0]))
		return ldap.PrintUser(args[0])
	}),
}

var InspectLDAPGroupCmd = &cobra.Command{
	Use:   "group [cn]",
	Short: "Get a single LDAP group by CN",
	Args:  cobra.ExactArgs(1),
	RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {
		log.Info("Looking up LDAP group", zap.String("cn", args[0]))
		return ldap.PrintGroup(args[0])
	}),
}

func init() {
	log = logger.L()

	// Core LDAP command
	InspectCmd.AddCommand(InspectLDAPCmd)

	// Subcommands
	InspectLDAPCmd.AddCommand(InspectLDAPUsersCmd)
	InspectLDAPCmd.AddCommand(InspectLDAPGroupsCmd)
	InspectLDAPCmd.AddCommand(InspectLDAPUserCmd)
	InspectLDAPCmd.AddCommand(InspectLDAPGroupCmd)
}
