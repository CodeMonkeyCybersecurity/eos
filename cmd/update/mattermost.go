// cmd/update/mattermost.go
package update

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/mattermost/fix"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	mattermostFix        bool
	mattermostDryRun     bool
	mattermostComposeDir string
	mattermostVolumesDir string
)

// MattermostCmd updates Mattermost configuration
var MattermostCmd = &cobra.Command{
	Use:   "mattermost",
	Short: "Update Mattermost configuration",
	Long: `Update Mattermost's configuration and fix common issues.

Configuration Drift Correction:
  --fix       Detect and correct container permission drift
  --dry-run   Preview changes without applying

  The --fix flag corrects common Mattermost container permission issues:
  - Volume ownership (sets to uid/gid 2000:2000)
  - Container restart after permission correction
  - Verification of successful startup

  Like combing through the configuration to correct any settings that drifted.

Examples:
  # Detect and fix all permission drift
  eos update mattermost --fix

  # Show what would be fixed (dry-run)
  eos update mattermost --fix --dry-run

  # Custom directories
  eos update mattermost --fix --compose-dir /opt/docker --volumes-dir /opt/mattermost

Code Monkey Cybersecurity - "Cybersecurity. With humans."`,

	RunE: eos_cli.Wrap(runMattermostUpdate),
}

func init() {
	MattermostCmd.Flags().BoolVar(&mattermostFix, "fix", false,
		"Fix configuration drift (container permissions) - use --dry-run to preview")
	MattermostCmd.Flags().BoolVar(&mattermostDryRun, "dry-run", false,
		"Preview changes without applying them")
	MattermostCmd.Flags().StringVar(&mattermostComposeDir, "compose-dir", "/opt/docker",
		"Docker compose directory")
	MattermostCmd.Flags().StringVar(&mattermostVolumesDir, "volumes-dir", "/opt/mattermost",
		"Mattermost volumes directory")
}

func runMattermostUpdate(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Only support --fix for now (future: add other update operations)
	if !mattermostFix {
		return eos_err.NewUserError(
			"Must specify --fix.\n\n" +
				"Fix configuration drift:\n" +
				"  eos update mattermost --fix           # Fix permission drift\n" +
				"  eos update mattermost --fix --dry-run # Preview without applying\n\n" +
				"Examples:\n" +
				"  eos update mattermost --fix\n" +
				"  eos update mattermost --fix --dry-run\n" +
				"  eos update mattermost --fix --compose-dir /opt/docker --volumes-dir /opt/mattermost")
	}

	logger.Info("Running Mattermost configuration drift correction",
		zap.Bool("dry_run", mattermostDryRun))

	// Create fix configuration
	config := &fix.Config{
		DryRun:        mattermostDryRun,
		ComposeDir:    mattermostComposeDir,
		VolumesDir:    mattermostVolumesDir,
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

	// Delegate to pkg/mattermost/fix - ALL business logic lives there
	return fix.FixMattermostPermissions(rc, config)
}
