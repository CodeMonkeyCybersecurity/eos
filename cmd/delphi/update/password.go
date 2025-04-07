// cmd/delphi/update/password.go
package update

import (
	"errors"
	"fmt"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/delphi"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/xdg"
)

var (
	username      string
	password      string
	storePassword bool
)

var PasswordCmd = &cobra.Command{
	Use:   "password",
	Short: "Update a Wazuh user's password",
	Long: `Update the password of a Wazuh (Delphi) user using their username.
Supports interactive confirmation and XDG-safe password storage if requested.`,
	RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {
		log := logger.GetLogger()

		if username == "" {
			return errors.New("username is required (use --username)")
		}

		cfg, err := delphi.LoadDelphiConfig()
		if err != nil {
			log.Fatal("Failed to load Delphi config", zap.Error(err))
		}

		// Prompt for current password
		currentPassword, err := interaction.PromptPassword("Current password")
		if err != nil {
			return fmt.Errorf("failed to read current password: %w", err)
		}

		log.Info("Authenticating with current password...")

		if _, err := delphi.AuthenticateUser(cfg, username, currentPassword); err != nil {
			return fmt.Errorf("authentication failed: %w", err)
		}

		userID, err := delphi.GetUserIDByUsername(cfg, username)
		if err != nil {
			return fmt.Errorf("unable to resolve user ID for username %s: %w", username, err)
		}

		if strings.EqualFold(username, "wazuh-wui") {
			confirm, err := interaction.Confirm("You are updating the wazuh-wui user. This will impact the Wazuh dashboard. Proceed?")
			if err != nil || !confirm {
				return errors.New("aborted by user")
			}
		}

		// Prompt for password (if not provided via flag)
		if password == "" {
			pw1, err := interaction.PromptPassword("New password")
			if err != nil {
				return err
			}
			pw2, err := interaction.PromptPassword("Confirm password")
			if err != nil {
				return err
			}
			if pw1 != pw2 {
				return errors.New("passwords do not match")
			}
			password = pw1
		}

		if err := delphi.UpdateUserPassword(cfg, userID, password); err != nil {
			return fmt.Errorf("failed to update password: %w", err)
		}

		log.Info("Password updated successfully", zap.String("username", username))

		if storePassword {
			path, err := xdg.SaveCredential("delphi", username, password)
			if err != nil {
				log.Warn("Password update succeeded but storing password failed", zap.Error(err))
			} else {
				log.Info("Password stored securely", zap.String("path", path))
			}
		}

		return nil
	}),
}

func init() {
	PasswordCmd.Flags().StringVar(&username, "username", "", "Wazuh username to update (required)")
	PasswordCmd.Flags().StringVar(&password, "password", "", "New password to set (optional; will prompt if omitted)")
	PasswordCmd.Flags().BoolVar(&storePassword, "store", false, "Store new password securely via XDG")
	PasswordCmd.MarkFlagRequired("username")

	UpdateCmd.AddCommand(PasswordCmd)
}
