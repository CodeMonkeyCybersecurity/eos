package storage_monitor

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// DetectContention detects I/O contention on storage devices
func DetectContention(rc *eos_io.RuntimeContext) ([]ContentionMetrics, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing system for I/O contention detection")

	// Check if we have necessary tools
	hasIostat := true
	if _, err := exec.LookPath("iostat"); err != nil {
		hasIostat = false
		logger.Debug("iostat not available, using /proc/stat")
	}

	// INTERVENE
	logger.Info("Detecting I/O contention")

	var metrics []ContentionMetrics

	if hasIostat {
		metrics, _ = detectContentionWithIostat(rc)
	}

	// Always supplement with /proc/stat data
	procMetrics, err := detectContentionFromProc(rc)
	if err != nil && len(metrics) == 0 {
		return nil, fmt.Errorf("failed to detect contention: %w", err)
	}

	// Merge or use proc metrics
	if len(metrics) == 0 {
		metrics = procMetrics
	} else {
		// Enhance iostat metrics with proc data
		for i := range metrics {
			for _, pm := range procMetrics {
				if metrics[i].Device == pm.Device {
					metrics[i].IOWaitPercent = pm.IOWaitPercent
					break
				}
			}
		}
	}

	// Calculate contention scores
	for i := range metrics {
		metrics[i].ContentionScore = calculateContentionScore(&metrics[i])
		metrics[i].Timestamp = time.Now()

		logger.Debug("Contention metrics",
			zap.String("device", metrics[i].Device),
			zap.Float64("score", metrics[i].ContentionScore),
			zap.Float64("utilization", metrics[i].Utilization))
	}

	// EVALUATE
	logger.Info("Contention detection completed",
		zap.Int("devicesChecked", len(metrics)))

	return metrics, nil
}

// MonitorContention monitors for resource contention and generates alerts
func MonitorContention(rc *eos_io.RuntimeContext, config *MonitorConfig) ([]Alert, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing contention monitoring requirements",
		zap.Bool("enabled", config.EnableContention))

	if !config.EnableContention {
		return []Alert{}, nil
	}

	// INTERVENE
	logger.Info("Monitoring resource contention")

	metrics, err := DetectContention(rc)
	if err != nil {
		return nil, fmt.Errorf("failed to detect contention: %w", err)
	}

	alerts := make([]Alert, 0)

	for _, metric := range metrics {
		if metric.ContentionScore > config.ContentionWarning {
			severity := AlertSeverityWarning
			if metric.ContentionScore > 80 {
				severity = AlertSeverityCritical
			}

			alert := Alert{
				ID:        generateAlertID(metric.Device, AlertTypeContention),
				Type:      AlertTypeContention,
				Severity:  severity,
				Device:    metric.Device,
				Message:   fmt.Sprintf("I/O contention detected on %s: score %.1f/100", metric.Device, metric.ContentionScore),
				Value:     metric.ContentionScore,
				Threshold: config.ContentionWarning,
				Timestamp: time.Now(),
			}
			alerts = append(alerts, alert)

			logger.Warn("I/O contention detected",
				zap.String("device", metric.Device),
				zap.Float64("score", metric.ContentionScore),
				zap.Float64("iowait", metric.IOWaitPercent))
		}
	}

	// EVALUATE
	logger.Info("Contention monitoring completed",
		zap.Int("alertsGenerated", len(alerts)))

	return alerts, nil
}

// AnalyzeContentionPatterns analyzes historical contention patterns
func AnalyzeContentionPatterns(rc *eos_io.RuntimeContext, device string, duration time.Duration) (*ContentionAnalysis, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing contention patterns",
		zap.String("device", device),
		zap.Duration("duration", duration))

	// INTERVENE
	logger.Info("Analyzing contention patterns")

	// Collect samples over time
	samples := make([]ContentionMetrics, 0)
	sampleInterval := 10 * time.Second
	numSamples := int(duration / sampleInterval)

	for i := 0; i < numSamples; i++ {
		metrics, err := DetectContention(rc)
		if err != nil {
			logger.Warn("Failed to collect contention sample",
				zap.Error(err))
			continue
		}

		for _, m := range metrics {
			if m.Device == device {
				samples = append(samples, m)
				break
			}
		}

		if i < numSamples-1 {
			time.Sleep(sampleInterval)
		}
	}

	if len(samples) == 0 {
		return nil, fmt.Errorf("no contention data collected for device %s", device)
	}

	// Analyze patterns
	analysis := &ContentionAnalysis{
		Device:      device,
		Duration:    duration,
		SampleCount: len(samples),
	}

	// Calculate statistics
	var totalScore, totalIOWait, totalUtil float64
	peakScore := 0.0

	for _, s := range samples {
		totalScore += s.ContentionScore
		totalIOWait += s.IOWaitPercent
		totalUtil += s.Utilization

		if s.ContentionScore > peakScore {
			peakScore = s.ContentionScore
			analysis.PeakTime = s.Timestamp
		}
	}

	analysis.AverageScore = totalScore / float64(len(samples))
	analysis.PeakScore = peakScore
	analysis.AverageIOWait = totalIOWait / float64(len(samples))
	analysis.AverageUtilization = totalUtil / float64(len(samples))

	// Identify patterns
	analysis.Patterns = identifyContentionPatterns(samples)

	// EVALUATE
	logger.Info("Contention pattern analysis completed",
		zap.String("device", device),
		zap.Float64("avgScore", analysis.AverageScore),
		zap.Float64("peakScore", analysis.PeakScore))

	return analysis, nil
}

// Types for contention analysis

type ContentionAnalysis struct {
	Device             string
	Duration           time.Duration
	SampleCount        int
	AverageScore       float64
	PeakScore          float64
	PeakTime           time.Time
	AverageIOWait      float64
	AverageUtilization float64
	Patterns           []string
}

// Helper functions

func detectContentionWithIostat(rc *eos_io.RuntimeContext) ([]ContentionMetrics, error) {
	// Run iostat with extended statistics
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "iostat",
		Args:    []string{"-dx", "1", "2"},
		Capture: true,
	})
	if err != nil {
		return nil, err
	}

	return parseIostatForContention(output), nil
}

func detectContentionFromProc(rc *eos_io.RuntimeContext) ([]ContentionMetrics, error) {
	// Read CPU stats for I/O wait
	cpuStat, err := readCPUStat()
	if err != nil {
		return nil, err
	}

	// Read disk stats
	diskStats, err := readDiskStats()
	if err != nil {
		return nil, err
	}

	metrics := make([]ContentionMetrics, 0)

	for device, stats := range diskStats {
		metric := ContentionMetrics{
			Device:        device,
			IOWaitPercent: cpuStat.IOWait,
		}

		// Estimate queue depth based on I/O time
		if stats.IOTime > 0 {
			metric.QueueDepth = float64(stats.ReadOps+stats.WriteOps) / float64(stats.IOTime) * 1000
		}

		// Estimate utilization
		metric.Utilization = float64(stats.IOTime) / 10.0 // Convert to percentage

		metrics = append(metrics, metric)
	}

	return metrics, nil
}

func parseIostatForContention(output string) []ContentionMetrics {
	metrics := make([]ContentionMetrics, 0)
	lines := strings.Split(output, "\n")

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
		if len(fields) < 14 {
			continue
		}

		metric := ContentionMetrics{
			Device: fields[0],
		}

		// Parse relevant fields
		fmt.Sscanf(fields[8], "%f", &metric.QueueDepth)   // avgqu-sz
		fmt.Sscanf(fields[11], "%f", &metric.ServiceTime) // svctm
		fmt.Sscanf(fields[13], "%f", &metric.Utilization) // %util

		metrics = append(metrics, metric)
	}

	return metrics
}

type cpuStats struct {
	User   float64
	System float64
	IOWait float64
	Idle   float64
}

func readCPUStat() (*cpuStats, error) {
	file, err := os.Open("/proc/stat")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "cpu ") {
			fields := strings.Fields(line)
			if len(fields) < 5 {
				continue
			}

			stats := &cpuStats{}

			user, _ := strconv.ParseFloat(fields[1], 64)
			system, _ := strconv.ParseFloat(fields[3], 64)
			idle, _ := strconv.ParseFloat(fields[4], 64)
			iowait, _ := strconv.ParseFloat(fields[5], 64)

			total := user + system + idle + iowait
			if total > 0 {
				stats.User = user / total * 100
				stats.System = system / total * 100
				stats.Idle = idle / total * 100
				stats.IOWait = iowait / total * 100
			}

			return stats, nil
		}
	}

	return nil, fmt.Errorf("cpu stats not found in /proc/stat")
}

func calculateContentionScore(m *ContentionMetrics) float64 {
	// Weighted scoring based on multiple factors
	score := 0.0

	// Utilization weight: 40%
	score += m.Utilization * 0.4

	// I/O wait weight: 30%
	score += m.IOWaitPercent * 0.3

	// Queue depth weight: 20%
	if m.QueueDepth > 0 {
		// Normalize queue depth (>10 is concerning)
		queueScore := m.QueueDepth / 10.0 * 100
		if queueScore > 100 {
			queueScore = 100
		}
		score += queueScore * 0.2
	}

	// Service time weight: 10%
	if m.ServiceTime > 0 {
		// Normalize service time (>20ms is concerning)
		svcScore := m.ServiceTime / 20.0 * 100
		if svcScore > 100 {
			svcScore = 100
		}
		score += svcScore * 0.1
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score
}

func identifyContentionPatterns(samples []ContentionMetrics) []string {
	patterns := make([]string, 0)

	if len(samples) < 3 {
		return patterns
	}

	// Check for sustained high contention
	highContentionCount := 0
	for _, s := range samples {
		if s.ContentionScore > 70 {
			highContentionCount++
		}
	}

	if float64(highContentionCount)/float64(len(samples)) > 0.5 {
		patterns = append(patterns, "sustained_high_contention")
	}

	// Check for spikes
	for i := 1; i < len(samples)-1; i++ {
		if samples[i].ContentionScore > samples[i-1].ContentionScore*2 &&
			samples[i].ContentionScore > samples[i+1].ContentionScore*2 {
			patterns = append(patterns, "contention_spikes")
			break
		}
	}

	// Check for increasing trend
	firstHalf := samples[:len(samples)/2]
	secondHalf := samples[len(samples)/2:]

	var firstAvg, secondAvg float64
	for _, s := range firstHalf {
		firstAvg += s.ContentionScore
	}
	firstAvg /= float64(len(firstHalf))

	for _, s := range secondHalf {
		secondAvg += s.ContentionScore
	}
	secondAvg /= float64(len(secondHalf))

	if secondAvg > firstAvg*1.2 {
		patterns = append(patterns, "increasing_contention")
	}

	return patterns
}
