package create

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
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
			if _, err := os.Stat(shared.HecateInstallDir); os.IsNotExist(err) {
				zap.L().Info("/opt/hecate does not exist, creating it...")
				if err := os.MkdirAll(shared.HecateInstallDir, 0755); err != nil {
					zap.L().Error("Failed to create /opt/hecate", zap.Error(err))
					return fmt.Errorf("failed to create /opt/hecate: %w", err)
				}
			} else {
				zap.L().Info("/opt/hecate already exists")
			}

			// Check if Hecate repo already cloned
			gitDir := filepath.Join(shared.HecateInstallDir, ".git")
			if _, err := os.Stat(gitDir); err == nil {
				zap.L().Info("Hecate repository already cloned, skipping clone step")
				return nil
			}

			// Run: git clone <repo> /opt/hecate
			zap.L().Info("Cloning Hecate repository...",
				zap.String("repo", shared.HecateRepoURL),
				zap.String("destination", shared.HecateInstallDir),
			)
			cmdClone := exec.Command("git", "clone", shared.HecateRepoURL, shared.HecateInstallDir)
			cmdClone.Stdout = os.Stdout
			cmdClone.Stderr = os.Stderr

			if err := cmdClone.Run(); err != nil {
				zap.L().Error("Failed to clone Hecate repository", zap.Error(err))
				return fmt.Errorf("failed to clone hecate repository: %w", err)
			}

			zap.L().Info("✅ Hecate setup completed successfully")
			return nil
		}),
	}
}
