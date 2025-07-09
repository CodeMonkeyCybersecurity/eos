// cmd/read/system_path.go
package read

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var systemPathCmd = &cobra.Command{
	Use:     "system-path",
	Aliases: []string{"path-diag", "path-diagnostics"},
	Short:   "Diagnose system PATH configuration",
	Long: `Analyze and troubleshoot PATH environment variable configuration.
	
This command examines:
- Current PATH and login shell PATH
- Configuration files that modify PATH
- Duplicate PATH entries
- Snap daemon status
- Configuration file contents

The diagnostic process:
1. Captures current PATH from environment
2. Analyzes shell configuration files (.bashrc, .profile, etc.)
3. Identifies duplicate entries that may cause confusion
4. Checks snap daemon status for snap-related PATH issues
5. Examines system-wide PATH configuration files
6. Generates comprehensive report with recommendations

The tool detects common PATH problems such as:
- Duplicate directory entries
- Missing essential system directories
- Conflicting PATH modifications
- Snap daemon configuration issues
- Permission problems with PATH directories`,
	Example: `  # Analyze current PATH configuration
  eos read system-path
  
  # Also available as aliases:
  eos read path-diag
  eos read path-diagnostics
  
  # Example output includes:
  # - Current PATH breakdown
  # - Duplicate entry detection
  # - Shell configuration analysis
  # - Snap daemon status
  # - Recommendations for PATH cleanup`,
	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info("Starting PATH diagnostics")

		diag := system.NewPathDiagnostics(rc)
		info, err := diag.AnalyzePath()
		if err != nil {
			return fmt.Errorf("PATH analysis failed: %w", err)
		}

		report := diag.GenerateReport(info)
		fmt.Println(report)

		logger.Info("PATH diagnostics completed successfully",
			zap.Int("duplicate_entries", len(info.DuplicateEntries)),
			zap.String("snap_status", info.SnapStatus),
			zap.Int("path_sources", len(info.PathSources)))

		return nil
	}),
}

func init() {
	ReadCmd.AddCommand(systemPathCmd)
}

