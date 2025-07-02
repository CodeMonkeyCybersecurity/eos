package read

import (
	"fmt"
	"path/filepath"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	outputFile   string
	displayOnly  bool
	includeAll   bool
	includeProcs bool
	includeNet   bool
	includeHist  bool
)

// ReadSystemCmd represents the read system command
var ReadSystemCmd = &cobra.Command{
	Use:   "system",
	Short: "Collect comprehensive Ubuntu system information",
	Long: `Collect comprehensive Ubuntu system diagnostic information including:
- Running processes and users
- Installed packages (APT and Snap)
- Disk usage and storage information
- Network configuration
- System logs and history
- Crontab entries

This command is equivalent to the collectUbuntuInfo.sh script but provides
structured logging and optional file output.

Examples:
  eos read system                           # Display all information
  eos read system --output /tmp/sysinfo.txt # Save to file
  eos read system --display-only            # Only display, don't save
  eos read system --include-procs           # Include only process info
  eos read system --include-net             # Include only network info`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		return runReadSystem(rc, cmd, args)
	}),
}

func runReadSystem(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting Ubuntu system information collection")

	// Collect system information
	info, err := system.CollectSystemInfo(rc)
	if err != nil {
		logger.Error("Failed to collect system information", zap.Error(err))
		return err
	}

	// Filter information if specific flags are set
	if includeProcs || includeNet || includeHist {
		info = filterSystemInfo(info, includeProcs, includeNet, includeHist)
	}

	// Display information
	if err := system.DisplaySystemInfo(rc, info); err != nil {
		logger.Error("Failed to display system information", zap.Error(err))
		return err
	}

	// Save to file if requested and not display-only
	if !displayOnly {
		filename := outputFile
		if filename == "" {
			// Generate default filename
			timestamp := time.Now().Format("20060102-150405")
			filename = filepath.Join("/tmp", fmt.Sprintf("ubuntu_system_info_%s.txt", timestamp))
		}

		logger.Info("Saving system information to file", zap.String("filename", filename))
		if err := system.SaveSystemInfoToFile(rc, info, filename); err != nil {
			logger.Error("Failed to save system information", zap.Error(err))
			return err
		}

		logger.Info("System information saved successfully", zap.String("filename", filename))
	}

	logger.Info("System information collection completed")
	return nil
}

// filterSystemInfo creates a filtered copy of SystemInfo based on flags
func filterSystemInfo(info *system.SystemInfo, procs, net, hist bool) *system.SystemInfo {
	filtered := &system.SystemInfo{
		Timestamp: info.Timestamp,
	}

	if procs {
		filtered.Processes = info.Processes
		filtered.Users = info.Users
	}

	if net {
		filtered.NetworkInfo = info.NetworkInfo
	}

	if hist {
		filtered.BashHistory = info.BashHistory
		filtered.CrontabSystem = info.CrontabSystem
		filtered.CrontabUser = info.CrontabUser
		filtered.DmesgOutput = info.DmesgOutput
	}

	// If no specific filters, include everything
	if !procs && !net && !hist {
		return info
	}

	return filtered
}

func init() {
	ReadCmd.AddCommand(ReadSystemCmd)

	ReadSystemCmd.Flags().StringVar(&outputFile, "output", "", "Output file path (default: /tmp/ubuntu_system_info_<timestamp>.txt)")
	ReadSystemCmd.Flags().BoolVar(&displayOnly, "display-only", false, "Only display information, don't save to file")
	ReadSystemCmd.Flags().BoolVar(&includeAll, "all", false, "Include all system information (default)")
	ReadSystemCmd.Flags().BoolVar(&includeProcs, "include-procs", false, "Include only process and user information")
	ReadSystemCmd.Flags().BoolVar(&includeNet, "include-net", false, "Include only network information")
	ReadSystemCmd.Flags().BoolVar(&includeHist, "include-hist", false, "Include only history and log information")
}