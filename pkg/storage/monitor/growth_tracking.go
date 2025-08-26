package monitor

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// TrackGrowth tracks storage growth over time
func TrackGrowth(rc *eos_io.RuntimeContext, paths []string, historyFile string) ([]GrowthMetrics, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing storage growth tracking",
		zap.Strings("paths", paths),
		zap.String("historyFile", historyFile))

	// Load historical data
	history, err := loadHistory(historyFile)
	if err != nil {
		logger.Debug("No historical data found, starting fresh",
			zap.Error(err))
		history = make(map[string][]DiskUsage)
	}

	// INTERVENE
	logger.Info("Tracking storage growth")

	// Get current usage
	currentUsage, err := CheckDiskUsage(rc, paths)
	if err != nil {
		return nil, fmt.Errorf("failed to check disk usage: %w", err)
	}

	growthMetrics := make([]GrowthMetrics, 0, len(currentUsage))
	now := time.Now()

	for _, usage := range currentUsage {
		// Add to history
		history[usage.Path] = append(history[usage.Path], usage)

		// Calculate growth metrics
		pathHistory := history[usage.Path]
		if len(pathHistory) < 2 {
			// Not enough data for growth calculation
			growthMetrics = append(growthMetrics, GrowthMetrics{
				Path:        usage.Path,
				CurrentSize: usage.UsedSize,
				TimeWindow:  0,
			})
			continue
		}

		// Compare with oldest data point within window (default 24 hours)
		timeWindow := 24 * time.Hour
		var oldestInWindow *DiskUsage

		for i := len(pathHistory) - 2; i >= 0; i-- {
			// Assuming entries are chronological
			if now.Sub(pathHistory[i].Timestamp) <= timeWindow {
				oldestInWindow = &pathHistory[i]
			} else {
				break
			}
		}

		if oldestInWindow == nil {
			oldestInWindow = &pathHistory[len(pathHistory)-2]
		}

		// Calculate metrics
		growth := GrowthMetrics{
			Path:         usage.Path,
			CurrentSize:  usage.UsedSize,
			PreviousSize: oldestInWindow.UsedSize,
			GrowthBytes:  usage.UsedSize - oldestInWindow.UsedSize,
			TimeWindow:   now.Sub(oldestInWindow.Timestamp),
		}

		if oldestInWindow.UsedSize > 0 {
			growth.GrowthPercent = float64(growth.GrowthBytes) * 100.0 / float64(oldestInWindow.UsedSize)
		}

		// Calculate growth rate (bytes per hour)
		if growth.TimeWindow > 0 {
			growth.GrowthRate = float64(growth.GrowthBytes) / growth.TimeWindow.Hours()

			// Project when disk will be full
			if growth.GrowthRate > 0 {
				remainingSpace := usage.TotalSize - usage.UsedSize
				hoursUntilFull := float64(remainingSpace) / growth.GrowthRate
				growth.ProjectedFull = now.Add(time.Duration(hoursUntilFull) * time.Hour)
				growth.DaysUntilFull = hoursUntilFull / 24
			}
		}

		growthMetrics = append(growthMetrics, growth)

		logger.Debug("Growth metrics calculated",
			zap.String("path", usage.Path),
			zap.Float64("growthPercent", growth.GrowthPercent),
			zap.Float64("daysUntilFull", growth.DaysUntilFull))
	}

	// Save updated history
	if err := saveHistory(historyFile, history); err != nil {
		logger.Warn("Failed to save history",
			zap.Error(err))
	}

	// Prune old history entries
	pruneHistory(history, 7*24*time.Hour)

	// EVALUATE
	logger.Info("Growth tracking completed",
		zap.Int("pathsTracked", len(growthMetrics)))

	return growthMetrics, nil
}

// AnalyzeGrowthTrends analyzes growth trends and makes predictions
func AnalyzeGrowthTrends(rc *eos_io.RuntimeContext, historyFile string, path string) (*GrowthAnalysis, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing growth trends",
		zap.String("path", path))

	// Load historical data
	history, err := loadHistory(historyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load history: %w", err)
	}

	pathHistory, exists := history[path]
	if !exists || len(pathHistory) < 3 {
		return nil, fmt.Errorf("insufficient historical data for path %s", path)
	}

	// INTERVENE
	logger.Info("Analyzing growth trends")

	analysis := &GrowthAnalysis{
		Path:       path,
		StartTime:  pathHistory[0].Timestamp,
		EndTime:    pathHistory[len(pathHistory)-1].Timestamp,
		DataPoints: len(pathHistory),
	}

	// Calculate various growth rates

	// Daily growth rate
	dailyGrowth := calculateAverageGrowthRate(pathHistory, 24*time.Hour)
	analysis.DailyGrowthRate = dailyGrowth

	// Weekly growth rate
	weeklyGrowth := calculateAverageGrowthRate(pathHistory, 7*24*time.Hour)
	analysis.WeeklyGrowthRate = weeklyGrowth

	// Peak growth rate
	peakGrowth := findPeakGrowthRate(pathHistory, time.Hour)
	analysis.PeakGrowthRate = peakGrowth

	// Growth acceleration
	if len(pathHistory) >= 4 {
		firstHalf := pathHistory[:len(pathHistory)/2]
		secondHalf := pathHistory[len(pathHistory)/2:]

		firstRate := calculateAverageGrowthRate(firstHalf, 24*time.Hour)
		secondRate := calculateAverageGrowthRate(secondHalf, 24*time.Hour)

		if firstRate > 0 {
			analysis.GrowthAcceleration = (secondRate - firstRate) / firstRate * 100
		}
	}

	// Predict future usage
	current := pathHistory[len(pathHistory)-1]
	analysis.CurrentUsage = current.UsedSize
	analysis.TotalCapacity = current.TotalSize

	if dailyGrowth > 0 {
		remainingSpace := current.TotalSize - current.UsedSize
		daysUntilFull := float64(remainingSpace) / dailyGrowth
		analysis.PredictedFullDate = time.Now().Add(time.Duration(daysUntilFull*24) * time.Hour)
		analysis.DaysUntilFull = daysUntilFull

		// Calculate confidence based on consistency
		analysis.PredictionConfidence = calculatePredictionConfidence(pathHistory)
	}

	// EVALUATE
	logger.Info("Growth trend analysis completed",
		zap.String("path", path),
		zap.Float64("dailyGrowthGB", dailyGrowth/GB),
		zap.Float64("daysUntilFull", analysis.DaysUntilFull))

	return analysis, nil
}

// MonitorGrowthRate monitors growth rate and generates alerts
func MonitorGrowthRate(rc *eos_io.RuntimeContext, config *MonitorConfig, historyFile string) ([]Alert, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing growth rate monitoring",
		zap.Bool("enabled", config.EnableGrowthTracking))

	if !config.EnableGrowthTracking {
		return []Alert{}, nil
	}

	// INTERVENE
	logger.Info("Monitoring storage growth rates")

	// Track growth for monitored paths
	growthMetrics, err := TrackGrowth(rc, config.MonitorPaths, historyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to track growth: %w", err)
	}

	alerts := make([]Alert, 0)

	for _, metric := range growthMetrics {
		// Check growth rate threshold (GB per day)
		growthGBPerDay := metric.GrowthRate * 24 / GB

		if growthGBPerDay > config.GrowthRateWarning {
			alert := Alert{
				ID:        generateAlertID(metric.Path, AlertTypeGrowthRate),
				Type:      AlertTypeGrowthRate,
				Severity:  AlertSeverityWarning,
				Path:      metric.Path,
				Message:   fmt.Sprintf("High growth rate on %s: %.1f GB/day", metric.Path, growthGBPerDay),
				Value:     growthGBPerDay,
				Threshold: config.GrowthRateWarning,
				Timestamp: time.Now(),
			}
			alerts = append(alerts, alert)

			logger.Warn("High growth rate detected",
				zap.String("path", metric.Path),
				zap.Float64("gbPerDay", growthGBPerDay))
		}

		// Alert if disk will be full soon
		if metric.DaysUntilFull > 0 && metric.DaysUntilFull < 7 {
			severity := AlertSeverityWarning
			if metric.DaysUntilFull < 3 {
				severity = AlertSeverityCritical
			}

			alert := Alert{
				ID:       generateAlertID(metric.Path, AlertTypeGrowthRate),
				Type:     AlertTypeGrowthRate,
				Severity: severity,
				Path:     metric.Path,
				Message: fmt.Sprintf("Disk %s will be full in %.1f days at current growth rate",
					metric.Path, metric.DaysUntilFull),
				Value:     metric.DaysUntilFull,
				Threshold: 7.0,
				Timestamp: time.Now(),
			}
			alerts = append(alerts, alert)
		}
	}

	// EVALUATE
	logger.Info("Growth rate monitoring completed",
		zap.Int("alertsGenerated", len(alerts)))

	return alerts, nil
}

// Types for growth analysis

type GrowthAnalysis struct {
	Path                 string
	StartTime            time.Time
	EndTime              time.Time
	DataPoints           int
	CurrentUsage         int64
	TotalCapacity        int64
	DailyGrowthRate      float64
	WeeklyGrowthRate     float64
	PeakGrowthRate       float64
	GrowthAcceleration   float64
	PredictedFullDate    time.Time
	DaysUntilFull        float64
	PredictionConfidence float64
}

// Helper functions

func loadHistory(historyFile string) (map[string][]DiskUsage, error) {
	data, err := os.ReadFile(historyFile)
	if err != nil {
		return nil, err
	}

	var history map[string][]DiskUsage
	if err := json.Unmarshal(data, &history); err != nil {
		return nil, err
	}

	return history, nil
}

func saveHistory(historyFile string, history map[string][]DiskUsage) error {
	// Create directory if needed
	dir := filepath.Dir(historyFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(history, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(historyFile, data, 0644)
}

func pruneHistory(history map[string][]DiskUsage, maxAge time.Duration) {
	cutoff := time.Now().Add(-maxAge)

	for path, entries := range history {
		pruned := make([]DiskUsage, 0)
		for _, entry := range entries {
			if entry.Timestamp.After(cutoff) {
				pruned = append(pruned, entry)
			}
		}
		history[path] = pruned
	}
}

func calculateAverageGrowthRate(history []DiskUsage, window time.Duration) float64 {
	if len(history) < 2 {
		return 0
	}

	totalGrowth := int64(0)
	totalTime := time.Duration(0)
	windowStart := time.Now().Add(-window)

	for i := 1; i < len(history); i++ {
		if history[i].Timestamp.Before(windowStart) {
			continue
		}

		growth := history[i].UsedSize - history[i-1].UsedSize
		duration := history[i].Timestamp.Sub(history[i-1].Timestamp)

		totalGrowth += growth
		totalTime += duration
	}

	if totalTime == 0 {
		return 0
	}

	// Return bytes per hour
	return float64(totalGrowth) / totalTime.Hours()
}

func findPeakGrowthRate(history []DiskUsage, window time.Duration) float64 {
	if len(history) < 2 {
		return 0
	}

	peakRate := 0.0

	for i := 1; i < len(history); i++ {
		growth := history[i].UsedSize - history[i-1].UsedSize
		duration := history[i].Timestamp.Sub(history[i-1].Timestamp)

		if duration > 0 && duration <= window {
			rate := float64(growth) / duration.Hours()
			if rate > peakRate {
				peakRate = rate
			}
		}
	}

	return peakRate
}

func calculatePredictionConfidence(history []DiskUsage) float64 {
	if len(history) < 4 {
		return 0.0
	}

	// Calculate variance in growth rates
	rates := make([]float64, 0, len(history)-1)
	for i := 1; i < len(history); i++ {
		growth := history[i].UsedSize - history[i-1].UsedSize
		duration := history[i].Timestamp.Sub(history[i-1].Timestamp)
		if duration > 0 {
			rate := float64(growth) / duration.Hours()
			rates = append(rates, rate)
		}
	}

	if len(rates) < 2 {
		return 0.0
	}

	// Calculate mean
	sum := 0.0
	for _, rate := range rates {
		sum += rate
	}
	mean := sum / float64(len(rates))

	// Calculate variance
	variance := 0.0
	for _, rate := range rates {
		variance += (rate - mean) * (rate - mean)
	}
	variance /= float64(len(rates))

	// Convert to confidence score (0-100)
	// Lower variance = higher confidence
	stdDev := math.Sqrt(variance)
	coefficientOfVariation := stdDev / mean

	confidence := 100.0 * (1.0 - coefficientOfVariation)
	if confidence < 0 {
		confidence = 0
	}
	if confidence > 100 {
		confidence = 100
	}

	return confidence
}
