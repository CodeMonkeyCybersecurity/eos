package diagnostics

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/ragequit"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/ragequit/system"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CheckResources performs comprehensive resource checks
// Migrated from cmd/ragequit/ragequit.go checkResources
func CheckResources(rc *eos_io.RuntimeContext) (*ragequit.ResourceInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Prepare for resource checking
	logger.Info("Assessing system resources")

	homeDir := system.GetHomeDir()
	outputFile := filepath.Join(homeDir, "ragequit-resources.txt")

	resourceInfo := &ragequit.ResourceInfo{
		DiskUsage: make(map[string]ragequit.DiskInfo),
	}

	var output strings.Builder
	output.WriteString("=== Resource Diagnostics ===\n")
	output.WriteString(fmt.Sprintf("Timestamp: %s\n\n", time.Now().Format(time.RFC3339)))

	// INTERVENE - Collect resource data
	logger.Debug("Collecting resource information")

	// Disk usage
	output.WriteString("=== Disk Usage ===\n")
	if dfOutput := system.RunCommandWithTimeout("df", []string{"-h"}, 5*time.Second); dfOutput != "" {
		output.WriteString(dfOutput)
		output.WriteString("\n")
	}

	// Check specific mount points
	mountPoints := []string{"/", "/var", "/tmp", "/home"}
	for _, mp := range mountPoints {
		if system.DirExists(mp) {
			var stat syscall.Statfs_t
			if err := syscall.Statfs(mp, &stat); err == nil {
				total := stat.Blocks * uint64(stat.Bsize)
				available := stat.Bavail * uint64(stat.Bsize)
				used := total - available
				percent := float64(used) / float64(total) * 100

				resourceInfo.DiskUsage[mp] = ragequit.DiskInfo{
					Total:     total,
					Used:      used,
					Available: available,
					Percent:   percent,
				}

				output.WriteString(fmt.Sprintf("%s: %.1f%% used (%d/%d bytes)\n",
					mp, percent, used, total))
			}
		}
	}

	// Memory usage
	output.WriteString("\n=== Memory Usage ===\n")
	if freeOutput := system.RunCommandWithTimeout("free", []string{"-h"}, 5*time.Second); freeOutput != "" {
		output.WriteString(freeOutput)

		// Parse memory info from /proc/meminfo
		if memInfo := system.ReadFile("/proc/meminfo"); memInfo != "" {
			lines := strings.Split(memInfo, "\n")
			for _, line := range lines {
				if strings.HasPrefix(line, "MemTotal:") {
					parts := strings.Fields(line)
					if len(parts) >= 2 {
						if val, err := strconv.ParseUint(parts[1], 10, 64); err == nil {
							resourceInfo.MemoryUsage.Total = val * 1024
						}
					}
				} else if strings.HasPrefix(line, "MemAvailable:") {
					parts := strings.Fields(line)
					if len(parts) >= 2 {
						if val, err := strconv.ParseUint(parts[1], 10, 64); err == nil {
							resourceInfo.MemoryUsage.Available = val * 1024
						}
					}
				}
			}
			resourceInfo.MemoryUsage.Used = resourceInfo.MemoryUsage.Total - resourceInfo.MemoryUsage.Available
		}
	}

	// CPU usage
	output.WriteString("\n=== CPU Usage ===\n")
	if topOutput := system.RunCommandWithTimeout("top", []string{"-bn1", "-i"}, 5*time.Second); topOutput != "" {
		lines := strings.Split(topOutput, "\n")
		if len(lines) > 10 {
			output.WriteString(strings.Join(lines[:10], "\n"))
		}
	}

	// Load average
	if loadAvg := system.ReadFile("/proc/loadavg"); loadAvg != "" {
		parts := strings.Fields(loadAvg)
		if len(parts) >= 3 {
			for i := 0; i < 3 && i < len(parts); i++ {
				if val, err := strconv.ParseFloat(parts[i], 64); err == nil {
					resourceInfo.LoadAverage[i] = val
				}
			}
			output.WriteString(fmt.Sprintf("\nLoad Average: %.2f %.2f %.2f\n",
				resourceInfo.LoadAverage[0],
				resourceInfo.LoadAverage[1],
				resourceInfo.LoadAverage[2]))
		}
	}

	// Process count
	output.WriteString("\n=== Process Information ===\n")
	if psOutput := system.RunCommandWithTimeout("ps", []string{"aux", "--sort=-%cpu"}, 5*time.Second); psOutput != "" {
		lines := strings.Split(psOutput, "\n")
		if len(lines) > 20 {
			output.WriteString(strings.Join(lines[:20], "\n"))
		}
	}

	// EVALUATE - Write results
	if err := os.WriteFile(outputFile, []byte(output.String()), 0644); err != nil {
		return nil, fmt.Errorf("failed to write resource diagnostics: %w", err)
	}

	logger.Info("Resource diagnostics completed",
		zap.String("output_file", outputFile),
		zap.Float64s("load_avg", resourceInfo.LoadAverage[:]))

	return resourceInfo, nil
}
