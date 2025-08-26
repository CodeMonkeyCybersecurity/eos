package monitor

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CollectIOMetrics collects I/O performance metrics for all block devices
func CollectIOMetrics(rc *eos_io.RuntimeContext) ([]IOMetrics, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing system for I/O metrics collection")

	// Check if we can read /proc/diskstats
	if _, err := os.Stat("/proc/diskstats"); err != nil {
		return nil, fmt.Errorf("cannot access /proc/diskstats: %w", err)
	}

	// INTERVENE
	logger.Info("Collecting I/O metrics")

	// First snapshot
	snapshot1, err := readDiskStats()
	if err != nil {
		return nil, fmt.Errorf("failed to read initial disk stats: %w", err)
	}

	// Wait for sample interval
	time.Sleep(1 * time.Second)

	// Second snapshot
	snapshot2, err := readDiskStats()
	if err != nil {
		return nil, fmt.Errorf("failed to read second disk stats: %w", err)
	}

	// Calculate metrics
	metrics := make([]IOMetrics, 0)

	for device, stats2 := range snapshot2 {
		stats1, exists := snapshot1[device]
		if !exists {
			continue
		}

		// Skip devices with no activity
		if stats2.ReadOps == stats1.ReadOps && stats2.WriteOps == stats1.WriteOps {
			continue
		}

		metric := IOMetrics{
			Device:     device,
			ReadOps:    stats2.ReadOps - stats1.ReadOps,
			WriteOps:   stats2.WriteOps - stats1.WriteOps,
			ReadBytes:  (stats2.ReadSectors - stats1.ReadSectors) * 512,
			WriteBytes: (stats2.WriteSectors - stats1.WriteSectors) * 512,
			ReadTime:   stats2.ReadTime - stats1.ReadTime,
			WriteTime:  stats2.WriteTime - stats1.WriteTime,
			IOTime:     stats2.IOTime - stats1.IOTime,
			Timestamp:  time.Now(),
		}

		// Calculate rates
		metric.ReadOpsPerSec = float64(metric.ReadOps)
		metric.WriteOpsPerSec = float64(metric.WriteOps)
		metric.ReadBytesPerSec = float64(metric.ReadBytes)
		metric.WriteBytesPerSec = float64(metric.WriteBytes)

		// Calculate latencies
		if metric.ReadOps > 0 {
			metric.AvgReadLatency = float64(metric.ReadTime) / float64(metric.ReadOps)
		}
		if metric.WriteOps > 0 {
			metric.AvgWriteLatency = float64(metric.WriteTime) / float64(metric.WriteOps)
		}

		metrics = append(metrics, metric)

		logger.Debug("I/O metrics collected",
			zap.String("device", device),
			zap.Float64("readMBps", metric.ReadBytesPerSec/MB),
			zap.Float64("writeMBps", metric.WriteBytesPerSec/MB))
	}

	// EVALUATE
	logger.Info("I/O metrics collection completed",
		zap.Int("deviceCount", len(metrics)))

	return metrics, nil
}

// MonitorIOPerformance monitors I/O performance and generates alerts
func MonitorIOPerformance(rc *eos_io.RuntimeContext, config *MonitorConfig) ([]Alert, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing I/O performance monitoring requirements",
		zap.Float64("latencyWarning", config.IOLatencyWarning))

	if !config.EnableIOMetrics {
		logger.Debug("I/O metrics monitoring disabled")
		return []Alert{}, nil
	}

	// INTERVENE
	logger.Info("Monitoring I/O performance")

	metrics, err := CollectIOMetrics(rc)
	if err != nil {
		return nil, fmt.Errorf("failed to collect I/O metrics: %w", err)
	}

	alerts := make([]Alert, 0)

	for _, metric := range metrics {
		// Check latency thresholds
		avgLatency := (metric.AvgReadLatency + metric.AvgWriteLatency) / 2

		if avgLatency > config.IOLatencyWarning {
			alert := Alert{
				ID:        generateAlertID(metric.Device, AlertTypeIOPerformance),
				Type:      AlertTypeIOPerformance,
				Severity:  AlertSeverityWarning,
				Device:    metric.Device,
				Message:   fmt.Sprintf("High I/O latency on %s: %.1fms", metric.Device, avgLatency),
				Value:     avgLatency,
				Threshold: config.IOLatencyWarning,
				Timestamp: time.Now(),
			}
			alerts = append(alerts, alert)

			logger.Warn("High I/O latency detected",
				zap.String("device", metric.Device),
				zap.Float64("latency", avgLatency))
		}

		// Check for I/O saturation
		if metric.IOTime > 900 { // >90% of time spent on I/O
			alert := Alert{
				ID:        generateAlertID(metric.Device, AlertTypeIOPerformance),
				Type:      AlertTypeIOPerformance,
				Severity:  AlertSeverityCritical,
				Device:    metric.Device,
				Message:   fmt.Sprintf("I/O saturation on %s: %d%% busy", metric.Device, metric.IOTime/10),
				Value:     float64(metric.IOTime) / 10,
				Threshold: 90.0,
				Timestamp: time.Now(),
			}
			alerts = append(alerts, alert)
		}
	}

	// EVALUATE
	logger.Info("I/O performance monitoring completed",
		zap.Int("alertsGenerated", len(alerts)))

	return alerts, nil
}

// GetIOStats gets current I/O statistics using iostat
func GetIOStats(rc *eos_io.RuntimeContext, device string) (*IOMetrics, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing device for I/O statistics",
		zap.String("device", device))

	// Check if iostat is available
	if _, err := exec.LookPath("iostat"); err != nil {
		// Fallback to /proc/diskstats
		return getIOStatsFromProc(rc, device)
	}

	// INTERVENE
	logger.Info("Collecting I/O statistics using iostat")

	// Run iostat
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "iostat",
		Args:    []string{"-dx", device, "1", "2"},
		Capture: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to run iostat: %w", err)
	}

	// Parse iostat output
	metric := parseIOStatOutput(output, device)
	if metric == nil {
		return nil, fmt.Errorf("failed to parse iostat output")
	}

	// EVALUATE
	logger.Info("I/O statistics collected",
		zap.String("device", device),
		zap.Float64("utilization", metric.Utilization))

	return metric, nil
}

// Helper functions

type diskStats struct {
	ReadOps      uint64
	ReadSectors  uint64
	ReadTime     uint64
	WriteOps     uint64
	WriteSectors uint64
	WriteTime    uint64
	IOTime       uint64
}

func readDiskStats() (map[string]diskStats, error) {
	file, err := os.Open("/proc/diskstats")
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := file.Close(); err != nil {
			fmt.Printf("Warning: Failed to close disk stats file: %v\n", err)
		}
	}()

	stats := make(map[string]diskStats)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 14 {
			continue
		}

		device := fields[2]

		// Skip partitions
		if strings.Contains(device, "p") || isNumeric(device[len(device)-1:]) {
			continue
		}

		var s diskStats
		fmt.Sscanf(fields[3], "%d", &s.ReadOps)
		fmt.Sscanf(fields[5], "%d", &s.ReadSectors)
		fmt.Sscanf(fields[6], "%d", &s.ReadTime)
		fmt.Sscanf(fields[7], "%d", &s.WriteOps)
		fmt.Sscanf(fields[9], "%d", &s.WriteSectors)
		fmt.Sscanf(fields[10], "%d", &s.WriteTime)
		fmt.Sscanf(fields[12], "%d", &s.IOTime)

		stats[device] = s
	}

	return stats, scanner.Err()
}

func getIOStatsFromProc(rc *eos_io.RuntimeContext, device string) (*IOMetrics, error) {
	stats, err := readDiskStats()
	if err != nil {
		return nil, err
	}

	stat, exists := stats[device]
	if !exists {
		return nil, fmt.Errorf("device %s not found in /proc/diskstats", device)
	}

	return &IOMetrics{
		Device:     device,
		ReadOps:    stat.ReadOps,
		WriteOps:   stat.WriteOps,
		ReadBytes:  stat.ReadSectors * 512,
		WriteBytes: stat.WriteSectors * 512,
		ReadTime:   stat.ReadTime,
		WriteTime:  stat.WriteTime,
		IOTime:     stat.IOTime,
		Timestamp:  time.Now(),
	}, nil
}

func parseIOStatOutput(output, device string) *IOMetrics {
	lines := strings.Split(output, "\n")

	// Find the device line in the second sample
	inSecondSample := false
	for _, line := range lines {
		if strings.Contains(line, "Device") && inSecondSample {
			continue
		}
		if strings.Contains(line, "Device") {
			inSecondSample = true
			continue
		}

		if !inSecondSample {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 14 || fields[0] != device {
			continue
		}

		metric := &IOMetrics{
			Device:    device,
			Timestamp: time.Now(),
		}

		// Parse fields
		fmt.Sscanf(fields[3], "%f", &metric.ReadOpsPerSec)
		fmt.Sscanf(fields[4], "%f", &metric.WriteOpsPerSec)

		var readKBps, writeKBps float64
		fmt.Sscanf(fields[5], "%f", &readKBps)
		fmt.Sscanf(fields[6], "%f", &writeKBps)
		metric.ReadBytesPerSec = readKBps * 1024
		metric.WriteBytesPerSec = writeKBps * 1024

		fmt.Sscanf(fields[9], "%f", &metric.AvgReadLatency)
		fmt.Sscanf(fields[10], "%f", &metric.AvgWriteLatency)
		fmt.Sscanf(fields[13], "%f", &metric.Utilization)

		return metric
	}

	return nil
}

func isNumeric(s string) bool {
	if len(s) == 0 {
		return false
	}
	return s[0] >= '0' && s[0] <= '9'
}
