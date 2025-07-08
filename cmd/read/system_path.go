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

Examples:
  eos read system-path                          # Analyze PATH configuration`,

	RunE: eos_cli.Wrap(runPathDiagnostics),
}

func init() {
	ReadCmd.AddCommand(systemPathCmd)
}

func runPathDiagnostics(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
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
}