// cmd/wazuh/update/password.go
package update

import (
	"errors"
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/wazuh"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/xdg"
)

// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
var (
	username      string
	password      string
	storePassword bool
)

var PasswordCmd = &cobra.Command{
	Use:   "password",
	Short: "Update a Wazuh user's password",
	Long: `Update the password of a Wazuh (Wazuh) user using their username.
Supports interactive confirmation and XDG-safe password storage if requested.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {

		if username == "" {
			return errors.New("username is required (use --username)")
		}

		cfg, err := wazuh.ReadConfig(rc)
		if err != nil {
			otelzap.Ctx(rc.Ctx).Fatal("Failed to load Wazuh config", zap.Error(err))
		}

		// Prompt for current password
		currentPassword, err := crypto.PromptPassword(rc, "Current password")
		if err != nil {
			return fmt.Errorf("failed to read current password: %w", err)
		}

		otelzap.Ctx(rc.Ctx).Info("Authenticating with current password...")

		if _, err := wazuh.AuthenticateUser(rc, cfg, username, currentPassword); err != nil {
			return fmt.Errorf("authentication failed: %w", err)
		}

		userID, err := wazuh.GetUserIDByUsername(rc, cfg, username)
		if err != nil {
			return fmt.Errorf("unable to resolve user ID for username %s: %w", username, err)
		}

		if strings.EqualFold(username, "wazuh-wui") {
			confirm, err := interaction.Resolve(rc, "You are updating the wazuh-wui user. This will impact the Wazuh dashboard. Proceed?")
			if err != nil || !confirm {
				return errors.New("aborted by user")
			}
		}

		// Prompt for password (if not provided via flag)
		if password == "" {
			pw1, err := crypto.PromptPassword(rc, "New password")
			if err != nil {
				return err
			}
			pw2, err := crypto.PromptPassword(rc, "Confirm password")
			if err != nil {
				return err
			}
			if pw1 != pw2 {
				return errors.New("passwords do not match")
			}
			password = pw1
		}

		if err := wazuh.UpdateUserPassword(rc, cfg, userID, password); err != nil {
			return fmt.Errorf("failed to update password: %w", err)
		}

		otelzap.Ctx(rc.Ctx).Info("Password updated successfully", zap.String("username", username))

		if storePassword {
			path, err := xdg.SaveCredential("wazuh", username, password)
			if err != nil {
				otelzap.Ctx(rc.Ctx).Warn("Password update succeeded but storing password failed", zap.Error(err))
			} else {
				otelzap.Ctx(rc.Ctx).Info("Password stored securely", zap.String("path", path))
			}
		}

		return nil
	}),
}

func init() {
	PasswordCmd.Flags().StringVar(&username, "username", "", "Wazuh username to update (required)")
	PasswordCmd.Flags().StringVar(&password, "password", "", "New password to set (optional; will prompt if omitted)")
	PasswordCmd.Flags().BoolVar(&storePassword, "store", false, "Store new password securely via XDG")
	_ = PasswordCmd.MarkFlagRequired("username")

	UpdateCmd.AddCommand(PasswordCmd)
}
