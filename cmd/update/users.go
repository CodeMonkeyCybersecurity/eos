// cmd/update/users.go
package update

import (
	"fmt"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hera"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
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
		return runUpdateUserPassword(rc, cmd, args)
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
		return runUpdateUserSSHAccess(rc, cmd, args)
	}),
}

var SyncUsersCmd = &cobra.Command{
	Use:   "users",
	Short: "Create user-specific groups from Keycloak registration events",
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		otelzap.Ctx(rc.Ctx)

		realm, _ := interaction.PromptIfMissing(rc.Ctx, cmd, "realm", "Enter Keycloak realm", false)
		sinceStr, _ := cmd.Flags().GetString("since")

		kcURL, _ := interaction.PromptIfMissing(rc.Ctx, cmd, "url", "Enter Keycloak base URL", false)

		clientID, _ := interaction.PromptIfMissing(rc.Ctx, cmd, "client-id", "Enter Keycloak client ID", false)

		clientSecret, _ := interaction.PromptIfMissing(rc.Ctx, cmd, "client-secret", "Enter Keycloak client secret", true)

		otelzap.Ctx(rc.Ctx).Debug("Initializing Keycloak client",
			zap.String("url", kcURL),
			zap.String("realm", realm),
			zap.String("clientID", clientID),
		)

		sinceDur, err := time.ParseDuration(sinceStr)
		if err != nil {
			otelzap.Ctx(rc.Ctx).Error("Invalid --since duration", zap.Error(err))
			return err
		}

		client, err := hera.NewClient(kcURL, clientID, clientSecret, realm)
		if err != nil {
			otelzap.Ctx(rc.Ctx).Error("Failed to initialize Keycloak client",
				zap.String("url", kcURL),
				zap.String("clientID", clientID),
				zap.String("realm", realm),
				zap.Error(err),
			)
			err := fmt.Errorf("keycloak login failed (check client ID/secret/realm)")
			otelzap.Ctx(rc.Ctx).Error("Failed to initialize Keycloak client", zap.Error(err))
			return err
		}

		cutoff := time.Now().Add(-sinceDur)
		otelzap.Ctx(rc.Ctx).Info("Fetching registration events", zap.Time("since", cutoff))

		events, err := client.GetRegistrationEvents(realm, cutoff)
		if err != nil {
			otelzap.Ctx(rc.Ctx).Error("Failed to fetch registration events", zap.Error(err))
			return err
		}

		otelzap.Ctx(rc.Ctx).Info("Processing registration events", zap.Int("count", len(events)))
		for _, ev := range events {
			username := ev.Details["username"]
			groupName := fmt.Sprintf("tenant-%s", username)

			exists, err := client.GroupExists(realm, groupName)
			if err != nil {
				otelzap.Ctx(rc.Ctx).Warn("Failed to check group existence", zap.String("group", groupName), zap.Error(err))
				continue
			}

			if !exists {
				otelzap.Ctx(rc.Ctx).Info("Creating new group", zap.String("group", groupName))
				if err := client.CreateGroup(realm, groupName); err != nil {
					otelzap.Ctx(rc.Ctx).Warn("Failed to create group", zap.String("group", groupName), zap.Error(err))
					continue
				}
			} else {
				otelzap.Ctx(rc.Ctx).Debug("Group already exists", zap.String("group", groupName))
			}

			userID, err := client.GetUserID(realm, username)
			if err != nil {
				otelzap.Ctx(rc.Ctx).Warn("Failed to fetch user ID", zap.String("user", username), zap.Error(err))
				continue
			}

			otelzap.Ctx(rc.Ctx).Info("Assigning user to group", zap.String("user", username), zap.String("group", groupName))
			if err := client.AssignUserToGroup(realm, userID, groupName); err != nil {
				otelzap.Ctx(rc.Ctx).Warn("Failed to assign user to group", zap.String("user", username), zap.String("group", groupName), zap.Error(err))
				continue
			}
		}

		otelzap.Ctx(rc.Ctx).Info("User group synchronization complete")
		return nil
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
