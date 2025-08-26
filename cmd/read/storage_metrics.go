package read

import (
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/storage/monitor"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var readStorageMetricsCmd = &cobra.Command{
	Use:   "storage-metrics",
	Short: "Read storage performance metrics",
	Long: `Display storage performance metrics including I/O rates, latency, 
and throughput for all storage devices.

This command provides real-time insights into storage device performance,
helping identify bottlenecks and monitor system health.

Features:
  - Displays read/write throughput in MB/s
  - Shows IOPS (Input/Output Operations Per Second)
  - Reports average read/write latency in milliseconds
  - Supports filtering by specific device
  - Continuous monitoring mode with configurable interval

Metrics displayed:
  - Read/Write MB/s: Data transfer rates
  - Read/Write IOPS: Operation rates
  - Read/Write Latency: Average response times

Examples:
  # Display current metrics for all devices
  eos read storage-metrics
  
  # Monitor specific device
  eos read storage-metrics --device sda
  
  # Watch metrics continuously (5-second interval)
  eos read storage-metrics --watch
  
  # Watch with custom interval
  eos read storage-metrics --watch --interval 10s`,
	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		device, _ := cmd.Flags().GetString("device")
		watch, _ := cmd.Flags().GetBool("watch")
		interval, _ := cmd.Flags().GetDuration("interval")

		logger.Info("Reading storage metrics",
			zap.String("device", device),
			zap.Bool("watch", watch))

		if watch {
			return watchMetrics(rc, device, interval)
		}

		// One-time collection
		metrics, err := monitor.CollectIOMetrics(rc)
		if err != nil {
			return fmt.Errorf("failed to collect I/O metrics: %w", err)
		}

		// Filter by device if specified
		if device != "" {
			filtered := make([]monitor.IOMetrics, 0)
			for _, m := range metrics {
				if m.Device == device {
					filtered = append(filtered, m)
				}
			}
			metrics = filtered
		}

		return displayMetrics(metrics)
	}),
}

func init() {
	readStorageMetricsCmd.Flags().String("device", "", "Specific device to monitor")
	readStorageMetricsCmd.Flags().Bool("watch", false, "Continuously monitor metrics")
	readStorageMetricsCmd.Flags().Duration("interval", 5*time.Second, "Update interval for watch mode")
}

// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
func displayMetrics(metrics []monitor.IOMetrics) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	fmt.Fprintf(w, "DEVICE\tREAD MB/s\tWRITE MB/s\tREAD IOPS\tWRITE IOPS\tREAD LAT(ms)\tWRITE LAT(ms)\n")

	for _, m := range metrics {
		fmt.Fprintf(w, "%s\t%.2f\t%.2f\t%.0f\t%.0f\t%.2f\t%.2f\n",
			m.Device,
			m.ReadBytesPerSec/monitor.MB,
			m.WriteBytesPerSec/monitor.MB,
			m.ReadOpsPerSec,
			m.WriteOpsPerSec,
			m.AvgReadLatency,
			m.AvgWriteLatency)
	}

	return w.Flush()
}

// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
func watchMetrics(rc *eos_io.RuntimeContext, device string, interval time.Duration) error {
	logger := otelzap.Ctx(rc.Ctx)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Clear screen
	logger.Info("terminal prompt: \033[2J\033[H")

	for {
		select {
		case <-rc.Ctx.Done():
			return nil
		case <-ticker.C:
			// Clear screen and move cursor to top
			logger.Info("terminal prompt: \033[2J\033[H")

			metrics, err := monitor.CollectIOMetrics(rc)
			if err != nil {
				logger.Info(fmt.Sprintf("terminal prompt: Error: %v", err))
				continue
			}

			// Filter if needed
			if device != "" {
				filtered := make([]monitor.IOMetrics, 0)
				for _, m := range metrics {
					if m.Device == device {
						filtered = append(filtered, m)
					}
				}
				metrics = filtered
			}

			logger.Info(fmt.Sprintf("terminal prompt: Storage Metrics - %s\n", time.Now().Format("15:04:05")))
			if err := displayMetrics(metrics); err != nil {
				logger.Info(fmt.Sprintf("terminal prompt: Warning: Failed to display metrics: %v", err))
			}
		}
	}
}
