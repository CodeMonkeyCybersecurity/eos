package debug

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/mattermost/debug"
	"github.com/spf13/cobra"
)

var mattermostCmd = &cobra.Command{
	Use:   "mattermost",
	Short: "Debug Mattermost deployment and troubleshoot issues",
	Long: `Debug Mattermost provides comprehensive troubleshooting for Mattermost deployments.

Diagnostic checks performed:
1. Docker Compose configuration verification
2. Mattermost container logs analysis (errors, warnings, connection issues)
3. Postgres container status and logs
4. Volume permissions verification (app and db volumes)
5. Postgres accessibility and connectivity tests
6. Docker network configuration and connectivity
7. Common issue detection and recommendations

The command analyzes logs for common patterns:
- Database connection failures
- Permission denied errors
- Authentication failures
- Migration errors
- Memory issues
- Network connectivity problems

Flags:
  --compose-dir DIR       Docker compose directory (default: /opt/docker)
  --volumes-dir DIR       Mattermost volumes directory (default: /opt/mattermost)
  --log-lines N           Number of Mattermost log lines to display (default: 100)
  --postgres-log-lines N  Number of Postgres log lines to display (default: 50)

Example:
  eos debug mattermost
  eos debug mattermost --log-lines 200
  eos debug mattermost --compose-dir /opt/docker --volumes-dir /opt/mattermost`,
	RunE: eos_cli.WrapDebug("mattermost", runDebugMattermost),
}

func init() {
	debugCmd.AddCommand(mattermostCmd)

	// Add flags
	mattermostCmd.Flags().String("compose-dir", "/opt/docker", "Docker compose directory")
	mattermostCmd.Flags().String("volumes-dir", "/opt/mattermost", "Mattermost volumes directory")
	mattermostCmd.Flags().Int("log-lines", 100, "Number of Mattermost log lines to display")
	mattermostCmd.Flags().Int("postgres-log-lines", 50, "Number of Postgres log lines to display")
}

func runDebugMattermost(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	// Parse flags
	composeDir, _ := cmd.Flags().GetString("compose-dir")
	volumesDir, _ := cmd.Flags().GetString("volumes-dir")
	logLines, _ := cmd.Flags().GetInt("log-lines")
	postgresLogLines, _ := cmd.Flags().GetInt("postgres-log-lines")

	config := &debug.Config{
		DockerComposeDir:     composeDir,
		MattermostVolumesDir: volumesDir,
		LogTailLines:         logLines,
		PostgresLogLines:     postgresLogLines,
	}

	// Run debug diagnostics
	return debug.RunDiagnostics(rc, config)
}
