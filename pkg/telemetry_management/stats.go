package telemetry_management

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// TelemetryStats holds statistics about telemetry data
// Migrated from cmd/self/telemetry.go TelemetryStats
type TelemetryStats struct {
	TotalCommands      int
	SuccessfulCommands int
	FailedCommands     int
	SuccessRate        float64
	FileSize           string
	OldestEntry        string
	NewestEntry        string
	TopCommands        []CommandCount
}

// CommandCount represents command usage statistics
// Migrated from cmd/self/telemetry.go CommandCount
type CommandCount struct {
	Name  string
	Count int
}

// GetTelemetryStats analyzes the telemetry file and returns statistics
// Migrated from cmd/self/telemetry.go getTelemetryStats
func GetTelemetryStats(rc *eos_io.RuntimeContext, filePath string) (*TelemetryStats, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS - Prepare telemetry statistics analysis
	logger.Info("Assessing telemetry statistics analysis",
		zap.String("file_path", filePath))
	
	file, err := os.Open(filePath)
	if err != nil {
		logger.Error("Failed to open telemetry file",
			zap.String("file_path", filePath),
			zap.Error(err))
		return nil, fmt.Errorf("failed to open telemetry file: %w", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			logger.Warn("Failed to close telemetry file", zap.Error(err))
		}
	}()

	// Get file info
	fileInfo, err := file.Stat()
	if err != nil {
		logger.Error("Failed to get file info", zap.Error(err))
		return nil, fmt.Errorf("failed to get file info: %w", err)
	}

	// INTERVENE - Process telemetry data
	logger.Debug("Processing telemetry data")
	
	stats := &TelemetryStats{
		FileSize: FormatFileSize(fileInfo.Size()),
	}

	commandCounts := make(map[string]int)
	scanner := bufio.NewScanner(file)
	lineCount := 0

	var oldestTime, newestTime time.Time

	for scanner.Scan() {
		lineCount++
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		// Parse JSON line
		var span map[string]any
		if err := json.Unmarshal([]byte(line), &span); err != nil {
			logger.Debug("Skipping malformed telemetry line",
				zap.Int("line_number", lineCount),
				zap.Error(err))
			continue // Skip malformed lines
		}

		// Extract command name
		if name, ok := span["name"].(string); ok {
			commandCounts[name]++
			stats.TotalCommands++
		}

		// Extract success status
		if attrs, ok := span["attributes"].(map[string]any); ok {
			if success, ok := attrs["success"].(bool); ok && success {
				stats.SuccessfulCommands++
			} else {
				stats.FailedCommands++
			}
		}

		// Extract timestamp
		if startTime, ok := span["startTime"].(string); ok {
			if t, err := time.Parse(time.RFC3339Nano, startTime); err == nil {
				if oldestTime.IsZero() || t.Before(oldestTime) {
					oldestTime = t
				}
				if newestTime.IsZero() || t.After(newestTime) {
					newestTime = t
				}
			}
		}
	}

	// Calculate success rate
	if stats.TotalCommands > 0 {
		stats.SuccessRate = float64(stats.SuccessfulCommands) / float64(stats.TotalCommands) * 100
	}

	// Format timestamps
	if !oldestTime.IsZero() {
		stats.OldestEntry = oldestTime.Format("2006-01-02 15:04:05")
	}
	if !newestTime.IsZero() {
		stats.NewestEntry = newestTime.Format("2006-01-02 15:04:05")
	}

	// Sort top commands
	for cmd, count := range commandCounts {
		stats.TopCommands = append(stats.TopCommands, CommandCount{Name: cmd, Count: count})
	}

	// Simple bubble sort for top commands (small data set)
	for i := 0; i < len(stats.TopCommands)-1; i++ {
		for j := 0; j < len(stats.TopCommands)-i-1; j++ {
			if stats.TopCommands[j].Count < stats.TopCommands[j+1].Count {
				stats.TopCommands[j], stats.TopCommands[j+1] = stats.TopCommands[j+1], stats.TopCommands[j]
			}
		}
	}

	// EVALUATE - Log successful analysis
	logger.Info("Telemetry statistics analysis completed successfully",
		zap.Int("total_commands", stats.TotalCommands),
		zap.Int("lines_processed", lineCount),
		zap.Int("unique_commands", len(commandCounts)))

	return stats, scanner.Err()
}

// ShowTelemetryStatus displays current telemetry status and statistics
// Migrated from cmd/self/telemetry.go showTelemetryStatus
func ShowTelemetryStatus(rc *eos_io.RuntimeContext, stateFile string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS - Check telemetry status
	logger.Info("Assessing telemetry status",
		zap.String("state_file", stateFile))
	
	// Check if telemetry is enabled
	enabled := false
	if _, err := os.Stat(stateFile); err == nil {
		enabled = true
	}

	telemetryPath := GetTelemetryFilePath()

	// INTERVENE - Display telemetry status
	logger.Info("📊 Telemetry Status",
		zap.Bool("enabled", enabled),
		zap.String("config_file", stateFile),
		zap.String("data_file", telemetryPath))

	if !enabled {
		logger.Info("❌ Telemetry is disabled",
			zap.String("enable_command", "eos self telemetry on"))
		return nil
	}

	// Get file statistics
	stats, err := GetTelemetryStats(rc, telemetryPath)
	if err != nil {
		logger.Warn("Could not read telemetry statistics", zap.Error(err))
		return nil
	}

	logger.Info("📈 Telemetry Statistics",
		zap.Int("total_commands", stats.TotalCommands),
		zap.Int("successful_commands", stats.SuccessfulCommands),
		zap.Int("failed_commands", stats.FailedCommands),
		zap.Float64("success_rate_percent", stats.SuccessRate),
		zap.String("file_size", stats.FileSize),
		zap.String("oldest_entry", stats.OldestEntry),
		zap.String("newest_entry", stats.NewestEntry))

	if len(stats.TopCommands) > 0 {
		logger.Info("🔝 Most Used Commands")
		for i, cmd := range stats.TopCommands {
			if i >= 5 { // Show top 5
				break
			}
			logger.Info("",
				zap.Int("rank", i+1),
				zap.String("command", cmd.Name),
				zap.Int("count", cmd.Count))
		}
	}

	ShowTelemetryInfo(rc)
	
	// EVALUATE - Log successful status display
	logger.Info("Telemetry status displayed successfully")
	
	return nil
}

// FormatFileSize converts bytes to human-readable format
// Migrated from cmd/self/telemetry.go formatFileSize
func FormatFileSize(bytes int64) string {
	// ASSESS - Determine appropriate unit for file size
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	
	// INTERVENE - Calculate and format file size
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	
	// EVALUATE - Return formatted file size
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}