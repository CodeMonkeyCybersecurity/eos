package read

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/storage"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Command flags
var (
	includeIOMetrics bool
	includeSMART     bool
	outputFormat     string
	diskOutputFile   string
	focusVG          string
)

// ReadDiskCmd handles disk inspection operations
var ReadDiskCmd = &cobra.Command{
	Use:   "disk",
	Short: "Inspect disk and storage system health",
	Long: `Comprehensive disk inspection including:
- Physical disk health and SMART status
- LVM hierarchy visualization (PV, VG, LV)
- Filesystem usage and mount points  
- Expansion opportunities and recommendations
- ASCII diagrams for visual understanding

Examples:
  eos read disk                               # Basic inspection
  eos read disk --include-io-metrics         # Include I/O performance data
  eos read disk --format json               # Output as JSON
  eos read disk --output report.json        # Save to file
  eos read disk --volume-group ubuntu-vg    # Focus on specific VG`,
	RunE: eos_cli.Wrap(runReadDisk),
}

func init() {
	ReadCmd.AddCommand(ReadDiskCmd)

	ReadDiskCmd.Flags().BoolVar(&includeIOMetrics, "include-io-metrics", false, "Include I/O performance metrics (requires iostat)")
	ReadDiskCmd.Flags().BoolVar(&includeSMART, "include-smart", true, "Include SMART disk health data")
	ReadDiskCmd.Flags().StringVar(&outputFormat, "format", "table", "Output format: table, json, yaml")
	ReadDiskCmd.Flags().StringVar(&diskOutputFile, "output", "", "Save output to file")
	ReadDiskCmd.Flags().StringVar(&focusVG, "volume-group", "", "Focus inspection on specific volume group")
}

func runReadDisk(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting disk inspection",
		zap.Bool("include_io_metrics", includeIOMetrics),
		zap.Bool("include_smart", includeSMART),
		zap.String("output_format", outputFormat),
		zap.String("focus_vg", focusVG))

	// ASSESS - Check if we have required permissions and tools
	if err := checkInspectionPrerequisites(rc); err != nil {
		return fmt.Errorf("prerequisites check failed: %w", err)
	}

	// INTERVENE - Perform the disk inspection
	inspector := storage.NewDiskInspector()
	inspector.SetOptions(includeIOMetrics, includeSMART, focusVG)

	logger.Info("Performing comprehensive disk analysis...")
	report, err := inspector.Inspect(rc.Ctx)
	if err != nil {
		return fmt.Errorf("disk inspection failed: %w", err)
	}

	// EVALUATE - Format and present the results
	var output string
	var formatErr error

	switch outputFormat {
	case "json":
		data, err := json.MarshalIndent(report, "", "  ")
		output = string(data)
		formatErr = err
	case "yaml":
		output, formatErr = inspector.FormatReport(report, storage.FormatYAML)
	case "table":
		fallthrough
	default:
		output, formatErr = inspector.FormatReport(report, storage.FormatTable)
	}

	if formatErr != nil {
		return fmt.Errorf("failed to format report: %w", formatErr)
	}

	// Save to file if specified
	if diskOutputFile != "" {
		logger.Info("Saving report to file", zap.String("file", diskOutputFile))
		if err := os.WriteFile(diskOutputFile, []byte(output), shared.ConfigFilePerm); err != nil {
			return fmt.Errorf("failed to save report to file: %w", err)
		}
		logger.Info("Report saved successfully", zap.String("file", diskOutputFile))
	} else {
		// Print to stdout
		fmt.Print(output)
	}

	// Log summary (placeholder implementation)
	logger.Info("Disk inspection completed successfully",
		zap.String("status", "placeholder_implementation"),
		zap.String("note", "Full disk inspection requires administrator intervention"))

	return nil
}

// checkInspectionPrerequisites verifies we have the tools and permissions needed
func checkInspectionPrerequisites(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if lsblk is available (should be on all Linux systems)
	if err := checkCommandAvailable("lsblk"); err != nil {
		return fmt.Errorf("lsblk command not available: %w", err)
	}

	// Check for LVM tools if LVM inspection is needed
	lvmCommands := []string{"pvs", "vgs", "lvs"}
	for _, cmd := range lvmCommands {
		if err := checkCommandAvailable(cmd); err != nil {
			logger.Warn("LVM command not available, LVM inspection will be limited",
				zap.String("command", cmd),
				zap.Error(err))
		}
	}

	// Check for SMART tools if SMART inspection is enabled
	if includeSMART {
		if err := checkCommandAvailable("smartctl"); err != nil {
			logger.Warn("smartctl not available, SMART inspection will be skipped",
				zap.Error(err))
		}
	}

	// Check for iostat if I/O metrics are enabled
	if includeIOMetrics {
		if err := checkCommandAvailable("iostat"); err != nil {
			logger.Warn("iostat not available, I/O metrics will be skipped",
				zap.Error(err))
		}
	}

	logger.Debug("Prerequisites check completed")
	return nil
}

// checkCommandAvailable verifies if a command is available in PATH
func checkCommandAvailable(command string) error {
	_, err := exec.LookPath(command)
	return err
}