package sync

import (
	"fmt"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hera"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var SyncUsersCmd = &cobra.Command{
	Use:   "users",
	Short: "Create user-specific groups from Keycloak registration events",
	RunE: eos.Wrap(func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error {
		zap.L().Named("delphi.sync.users")

		realm, _ := interaction.PromptIfMissing(cmd, "realm", "Enter Keycloak realm", false)
		sinceStr, _ := cmd.Flags().GetString("since")

		kcURL, _ := interaction.PromptIfMissing(cmd, "url", "Enter Keycloak base URL", false)

		clientID, _ := interaction.PromptIfMissing(cmd, "client-id", "Enter Keycloak client ID", false)

		clientSecret, _ := interaction.PromptIfMissing(cmd, "client-secret", "Enter Keycloak client secret", true)

		zap.L().Debug("Initializing Keycloak client",
			zap.String("url", kcURL),
			zap.String("realm", realm),
			zap.String("clientID", clientID),
		)

		sinceDur, err := time.ParseDuration(sinceStr)
		if err != nil {
			zap.L().Error("Invalid --since duration", zap.Error(err))
			return err
		}

		client, err := hera.NewClient(kcURL, clientID, clientSecret, realm)
		if err != nil {
			zap.L().Error("Failed to initialize Keycloak client",
				zap.String("url", kcURL),
				zap.String("clientID", clientID),
				zap.String("realm", realm),
				zap.Error(err),
			)
			err := fmt.Errorf("keycloak login failed (check client ID/secret/realm)")
			zap.L().Error("Failed to initialize Keycloak client", zap.Error(err))
			return err
		}

		cutoff := time.Now().Add(-sinceDur)
		zap.L().Info("Fetching registration events", zap.Time("since", cutoff))

		events, err := client.GetRegistrationEvents(realm, cutoff)
		if err != nil {
			zap.L().Error("Failed to fetch registration events", zap.Error(err))
			return err
		}

		zap.L().Info("Processing registration events", zap.Int("count", len(events)))
		for _, ev := range events {
			username := ev.Details["username"]
			groupName := fmt.Sprintf("tenant-%s", username)

			exists, err := client.GroupExists(realm, groupName)
			if err != nil {
				zap.L().Warn("Failed to check group existence", zap.String("group", groupName), zap.Error(err))
				continue
			}

			if !exists {
				zap.L().Info("Creating new group", zap.String("group", groupName))
				if err := client.CreateGroup(realm, groupName); err != nil {
					zap.L().Warn("Failed to create group", zap.String("group", groupName), zap.Error(err))
					continue
				}
			} else {
				zap.L().Debug("Group already exists", zap.String("group", groupName))
			}

			userID, err := client.GetUserID(realm, username)
			if err != nil {
				zap.L().Warn("Failed to fetch user ID", zap.String("user", username), zap.Error(err))
				continue
			}

			zap.L().Info("Assigning user to group", zap.String("user", username), zap.String("group", groupName))
			if err := client.AssignUserToGroup(realm, userID, groupName); err != nil {
				zap.L().Warn("Failed to assign user to group", zap.String("user", username), zap.String("group", groupName), zap.Error(err))
				continue
			}
		}

		zap.L().Info("User group synchronization complete")
		return nil
	}),
}

func init() {
	SyncCmd.AddCommand(SyncUsersCmd)
	SyncUsersCmd.Flags().String("realm", "", "Keycloak realm")
	SyncUsersCmd.Flags().String("since", "10m", "How far back to scan for registration events (e.g., 5m, 1h)")
	SyncUsersCmd.Flags().String("url", "https://hera.domain.com", "Keycloak base URL")
	SyncUsersCmd.Flags().String("client-id", "keycloak-api-bot", "Keycloak client ID")
	SyncUsersCmd.Flags().String("client-secret", "", "Keycloak client secret")
}
