// cmd/update/users.go
package update

import (
	"fmt"
	// "time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	// "github.com/CodeMonkeyCybersecurity/eos/pkg/hera"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/users"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// updateUsersCmd handles updating user information
var UpdateUsersCmd = &cobra.Command{
	Use:   "users",
	Short: "Update user information and settings",
	Long: `Update user information and settings including passwords and SSH access.

Examples:
  eos update users password [username]  # Change user password
  eos update users ssh-access [username]  # Grant SSH access to user`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		shared.SafeHelp(cmd)
		return nil
	}),
}

var updateUserPasswordCmd = &cobra.Command{
	Use:   "password [username]",
	Short: "Change user password (replaces changeUserPassword.sh)",
	Long: `Change the password for an existing user account.
This replaces the changeUserPassword.sh script functionality.

Examples:
  eos update users password john     # Change password for user 'john'
  eos update users password          # Interactive mode - prompt for username`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		return users.RunUpdateUserPassword(rc, cmd, args)
	}),
}

var updateUserSSHAccessCmd = &cobra.Command{
	Use:   "ssh-access [username]",
	Short: "Grant SSH access to a user",
	Long: `Grant SSH access to a user by adding them to the SSH AllowUsers configuration.
This functionality is part of the usersWithRemoteSsh.sh script migration.

Examples:
  eos update users ssh-access alice  # Grant SSH access to user 'alice'
  eos update users ssh-access        # Interactive mode - prompt for username`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		return users.RunUpdateUserSSHAccess(rc, cmd, args)
	}),
}

var SyncUsersCmd = &cobra.Command{
	Use:   "users",
	Short: "Create user-specific groups from Keycloak registration events",
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		otelzap.Ctx(rc.Ctx)

		realm, _ := interaction.PromptIfMissing(rc.Ctx, cmd, "realm", "Enter Keycloak realm", false)
		// sinceStr, _ := cmd.Flags().GetString("since")

		kcURL, _ := interaction.PromptIfMissing(rc.Ctx, cmd, "url", "Enter Keycloak base URL", false)

		clientID, _ := interaction.PromptIfMissing(rc.Ctx, cmd, "client-id", "Enter Keycloak client ID", false)

		clientSecret, _ := interaction.PromptIfMissing(rc.Ctx, cmd, "client-secret", "Enter Keycloak client secret", true)

		otelzap.Ctx(rc.Ctx).Debug("Initializing Keycloak client",
			zap.String("url", kcURL),
			zap.String("realm", realm),
			zap.String("clientID", clientID),
		)

		// sinceDur, err := time.ParseDuration(sinceStr)
		// if err != nil {
		// 	otelzap.Ctx(rc.Ctx).Error("Invalid --since duration", zap.Error(err))
		// 	return err
		// }

		// DEPRECATED: This command still uses Keycloak for backward compatibility
		// but users should migrate to Authentik
		otelzap.Ctx(rc.Ctx).Warn("Keycloak support is deprecated - please migrate to Authentik")
		otelzap.Ctx(rc.Ctx).Info("Use 'eos update authentik-users' for new Authentik-based user management")
		
		// For Authentik, we use the clientSecret as token since it's a different auth model
		// TODO: Fix hera package import
		// client, err := hera.NewAuthentikClient(kcURL, clientSecret)
		_ = clientSecret // Mark as used
		// var client interface{}
		// err = fmt.Errorf("hera package not available")
		return fmt.Errorf("hera package not available - cannot sync users")

		/* TODO: Re-enable when hera package is available
		if err != nil {
			otelzap.Ctx(rc.Ctx).Error("Failed to initialize Authentik client",
				zap.String("url", kcURL),
				zap.Error(err),
			)
			err := fmt.Errorf("authentik login failed (check URL and token)")
			otelzap.Ctx(rc.Ctx).Error("Failed to initialize Authentik client", zap.Error(err))
			return err
		}

		cutoff := time.Now().Add(-sinceDur)
		otelzap.Ctx(rc.Ctx).Info("Fetching registration events", zap.Time("since", cutoff))

		events, err := client.GetRegistrationEvents(cutoff)
		if err != nil {
			otelzap.Ctx(rc.Ctx).Error("Failed to fetch registration events", zap.Error(err))
			return err
		}

		otelzap.Ctx(rc.Ctx).Info("Processing registration events", zap.Int("count", len(events)))
		for _, ev := range events {
			// For Authentik events, username comes from Context instead of Details
			username, ok := ev.Context["username"].(string)
			if !ok {
				// Fallback: try to get username from User field
				if userMap, userOk := ev.User["username"]; userOk {
					username, _ = userMap.(string)
				}
			}
			if username == "" {
				otelzap.Ctx(rc.Ctx).Warn("Skipping event without username", zap.String("action", ev.Action))
				continue
			}
			groupName := fmt.Sprintf("tenant-%s", username)

			exists, err := client.GroupExists(groupName)
			if err != nil {
				otelzap.Ctx(rc.Ctx).Warn("Failed to check group existence", zap.String("group", groupName), zap.Error(err))
				continue
			}

			if !exists {
				otelzap.Ctx(rc.Ctx).Info("Creating new group", zap.String("group", groupName))
				if err := client.CreateGroup(groupName); err != nil {
					otelzap.Ctx(rc.Ctx).Warn("Failed to create group", zap.String("group", groupName), zap.Error(err))
					continue
				}
			} else {
				otelzap.Ctx(rc.Ctx).Debug("Group already exists", zap.String("group", groupName))
			}

			otelzap.Ctx(rc.Ctx).Info("Assigning user to group", zap.String("user", username), zap.String("group", groupName))
			if err := client.AddUserToGroup(username, groupName); err != nil {
				otelzap.Ctx(rc.Ctx).Warn("Failed to assign user to group", zap.String("user", username), zap.String("group", groupName), zap.Error(err))
				continue
			}
		}

		otelzap.Ctx(rc.Ctx).Info("User group synchronization complete")
		return nil
		*/
	}),
}

func init() {
	UpdateCmd.AddCommand(UpdateUsersCmd)
	UpdateUsersCmd.AddCommand(updateUserPasswordCmd)
	UpdateUsersCmd.AddCommand(updateUserSSHAccessCmd)

	UpdateCmd.AddCommand(SyncUsersCmd)
	SyncUsersCmd.Flags().String("realm", "", "Keycloak realm")
	SyncUsersCmd.Flags().String("since", "10m", "How far back to scan for registration events (e.g., 5m, 1h)")
	SyncUsersCmd.Flags().String("url", "https://hera.domain.com", "Keycloak base URL")
	SyncUsersCmd.Flags().String("client-id", "keycloak-api-bot", "Keycloak client ID")
	SyncUsersCmd.Flags().String("client-secret", "", "Keycloak client secret")
}
