// cmd/fix/mattermost.go

package fix

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/mattermost/fix"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

var (
	mattermostFixDryRun     bool
	mattermostFixComposeDir string
	mattermostFixVolumesDir string
)

var mattermostFixCmd = &cobra.Command{
	Use:   "mattermost",
	Short: "[DEPRECATED] Fix Mattermost container permission issues - use 'eos update mattermost --fix'",
	Long: `⚠️  DEPRECATION WARNING:
This command is deprecated and will be removed in Eos v2.0.0 (approximately 6 months from now).

Use 'eos update mattermost --fix' instead for configuration drift correction.

Migration guide:
  eos fix mattermost            →  eos update mattermost --fix
  eos fix mattermost --dry-run  →  eos update mattermost --drift

The new 'eos update mattermost --fix' provides the same functionality with better
semantics: it compares current state against canonical state and corrects drift.

Legacy functionality (still works):
- Volume permission issues (chown 2000:2000)
- Container restart after permission fix
- Verification of successful startup

The fix process:
1. Stop the Mattermost container
2. Check current volume permissions
3. Fix permissions (chown 2000:2000)
4. Verify permissions changed
5. Start Mattermost container
6. Watch logs to verify successful startup

EXAMPLES (DEPRECATED - use 'eos update mattermost --fix' instead):
  # Fix Mattermost permissions
  sudo eos fix mattermost

  # Dry-run to see what would be fixed
  sudo eos fix mattermost --dry-run

  # Use custom directories
  sudo eos fix mattermost --compose-dir /opt/docker --volumes-dir /opt/mattermost`,

	RunE: eos_cli.Wrap(runMattermostFix),
}

func init() {
	mattermostFixCmd.Flags().BoolVar(&mattermostFixDryRun, "dry-run", false, "Show what would be fixed without making changes")
	mattermostFixCmd.Flags().StringVar(&mattermostFixComposeDir, "compose-dir", "/opt/docker", "Docker compose directory")
	mattermostFixCmd.Flags().StringVar(&mattermostFixVolumesDir, "volumes-dir", "/opt/mattermost", "Mattermost volumes directory")
}

func runMattermostFix(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Print deprecation warning
	logger.Warn("⚠️  DEPRECATION WARNING: 'eos fix mattermost' is deprecated")
	logger.Warn("   Use 'eos update mattermost --fix' instead")
	logger.Warn("   This command will be removed in Eos v2.0.0 (approximately 6 months from now)")
	logger.Info("")

	config := &fix.Config{
		DryRun:        mattermostFixDryRun,
		ComposeDir:    mattermostFixComposeDir,
		VolumesDir:    mattermostFixVolumesDir,
		ContainerName: "mattermost",
		ServiceName:   "mattermost",
		TargetUID:     2000,
		TargetGID:     2000,
		// Fix all Mattermost volumes that need correct ownership
		VolumesToFix: []string{
			"app",                           // Base app directory
			"app/mattermost/config",         // Config directory (config.json)
			"app/mattermost/data",           // Data directory
			"app/mattermost/logs",           // Logs directory
			"app/mattermost/plugins",        // Plugins directory
			"app/mattermost/client/plugins", // Client plugins
			"app/mattermost/bleve-indexes",  // Search indexes
		},
		WatchLogSeconds: 10,
	}

	if err := fix.FixMattermostPermissions(rc, config); err != nil {
		return fmt.Errorf("failed to fix Mattermost permissions: %w", err)
	}

	return nil
}
