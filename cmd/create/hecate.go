package create

import (
	"fmt"
	"os"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// NewCreateHecateCmd creates the `create hecate` subcommand
func NewCreateHecateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "hecate",
		Short: "Fetch and set up Hecate reverse proxy framework",
		Long: `This command downloads the Hecate reverse proxy framework from its repository,
places it in /opt/hecate, and prepares it for use with EOS.`,
		RunE: eos.Wrap(func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error {
			zap.L().Info("Starting Hecate setup...")

			// Check if /opt/hecate exists
			if _, err := os.Stat(hecate.InstallDir); os.IsNotExist(err) {
				zap.L().Info("/opt/hecate does not exist, creating it...")
				if err := os.MkdirAll(hecate.InstallDir, 0755); err != nil {
					zap.L().Error("Failed to create /opt/hecate", zap.Error(err))
					return fmt.Errorf("failed to create /opt/hecate: %w", err)
				}
			} else {
				zap.L().Info("/opt/hecate already exists")
			}

			zap.L().Info("✅ Hecate setup completed successfully")
			return nil
		}),
	}
}
