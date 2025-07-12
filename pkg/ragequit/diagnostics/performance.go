package diagnostics

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/ragequit/system"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// PerformanceSnapshot takes a performance snapshot
// Migrated from cmd/ragequit/ragequit.go performanceSnapshot
func PerformanceSnapshot(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Prepare for performance snapshot
	logger.Info("Assessing performance snapshot requirements")

	homeDir := system.GetHomeDir()
	outputFile := filepath.Join(homeDir, "ragequit-performance.txt")

	var output strings.Builder
	output.WriteString("=== Performance Snapshot ===\n")
	output.WriteString(fmt.Sprintf("Timestamp: %s\n", time.Now().Format(time.RFC3339)))

	// INTERVENE - Collect performance data
	logger.Debug("Collecting performance metrics")

	// CPU info
	if cpuInfo := system.ReadFile("/proc/cpuinfo"); cpuInfo != "" {
		output.WriteString("\n--- CPU Information ---\n")
		lines := strings.Split(cpuInfo, "\n")
		for _, line := range lines {
			if strings.Contains(strings.ToLower(line), "mhz") {
				output.WriteString(line + "\n")
			}
		}
	}

	// Memory stats
	if vmStat := system.RunCommandWithTimeout("vmstat", []string{"1", "3"}, 10*time.Second); vmStat != "" {
		output.WriteString("\n--- Memory/CPU Stats ---\n")
		output.WriteString(vmStat)
		output.WriteString("\n")
	}

	// I/O stats
	if system.CommandExists("iostat") {
		if ioStat := system.RunCommandWithTimeout("iostat", []string{"-x", "1", "2"}, 5*time.Second); ioStat != "" {
			output.WriteString("\n--- I/O Stats ---\n")
			output.WriteString(ioStat)
			output.WriteString("\n")
		}
	}

	// Network stats
	if netStat := system.RunCommandWithTimeout("netstat", []string{"-s"}, 5*time.Second); netStat != "" {
		output.WriteString("\n--- Network Stats ---\n")
		output.WriteString(netStat)
		output.WriteString("\n")
	}

	// Load average
	if loadAvg := system.ReadFile("/proc/loadavg"); loadAvg != "" {
		output.WriteString("\n--- System Load ---\n")
		output.WriteString(loadAvg)
		output.WriteString("\n")
	}

	// EVALUATE - Write results
	if err := os.WriteFile(outputFile, []byte(output.String()), 0644); err != nil {
		return fmt.Errorf("failed to write performance snapshot: %w", err)
	}

	logger.Info("Performance snapshot completed",
		zap.String("output_file", outputFile))

	return nil
}
