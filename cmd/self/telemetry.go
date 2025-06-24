// cmd/self/telemetry.go

package self

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var TelemetryCmd = &cobra.Command{
	Use:   "telemetry [on|off|status]",
	Short: "Manage Eos CLI telemetry collection",
	Long: `Manage local telemetry collection for Eos CLI usage statistics.

Telemetry data is stored locally in JSONL format and can be analyzed 
to understand usage patterns. No data is sent to external servers.

Commands:
  on     - Enable telemetry collection
  off    - Disable telemetry collection  
  status - Show telemetry status and statistics`,
	Args: cobra.ExactArgs(1),
	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		stateFile := filepath.Join(os.Getenv("HOME"), ".eos", "telemetry_on")
		action := args[0]

		log := otelzap.Ctx(rc.Ctx)

		switch action {
		case "on":
			if err := os.MkdirAll(filepath.Dir(stateFile), 0700); err != nil {
				log.Error("Failed to create config directory", zap.Error(err))
				return fmt.Errorf("mkdir failed: %w", err)
			}
			if err := os.WriteFile(stateFile, []byte("on\n"), 0600); err != nil {
				log.Error("Failed to write telemetry toggle file", zap.Error(err))
				return fmt.Errorf("enable telemetry: %w", err)
			}
			log.Info(" Telemetry enabled")
			showTelemetryInfo(log)
		case "off":
			if err := os.Remove(stateFile); err != nil && !os.IsNotExist(err) {
				log.Error("Failed to remove telemetry toggle file", zap.Error(err))
				return fmt.Errorf("disable telemetry: %w", err)
			}
			log.Info("🚫 Telemetry disabled")
		case "status":
			return showTelemetryStatus(log, stateFile)
		default:
			log.Warn("Invalid telemetry argument", zap.String("arg", action))
			return fmt.Errorf("usage: telemetry [on|off|status]")
		}

		return nil
	}),
}

// getTelemetryFilePath returns the path to the telemetry file, following the same logic as the telemetry package
func getTelemetryFilePath() string {
	// Try system directory first (Ubuntu/production)
	systemPath := "/var/log/eos/telemetry.jsonl"
	if _, err := os.Stat(filepath.Dir(systemPath)); err == nil {
		return systemPath
	}

	// Fallback to user directory (development/macOS)
	return filepath.Join(os.Getenv("HOME"), ".eos", "telemetry", "telemetry.jsonl")
}

// showTelemetryInfo displays telemetry configuration details
func showTelemetryInfo(log otelzap.LoggerWithCtx) {
	telemetryPath := getTelemetryFilePath()
	log.Info(" Telemetry configuration",
		zap.String("file_path", telemetryPath),
		zap.String("format", "JSONL (JSON Lines)"),
		zap.String("privacy", "Local storage only - no external transmission"))

	log.Info("💡 Analysis commands",
		zap.String("command_frequency", "jq -r '.name' "+telemetryPath+" | sort | uniq -c | sort -nr"),
		zap.String("success_rate", "jq -r 'select(.attributes.success == true) | .name' "+telemetryPath+" | wc -l"),
		zap.String("avg_duration", "jq -r 'select(.attributes.duration_ms) | \"\\(.name) \\(.attributes.duration_ms)\"' "+telemetryPath))
}

// showTelemetryStatus displays current telemetry status and statistics
func showTelemetryStatus(log otelzap.LoggerWithCtx, stateFile string) error {
	// Check if telemetry is enabled
	enabled := false
	if _, err := os.Stat(stateFile); err == nil {
		enabled = true
	}

	telemetryPath := getTelemetryFilePath()

	log.Info(" Telemetry Status",
		zap.Bool("enabled", enabled),
		zap.String("config_file", stateFile),
		zap.String("data_file", telemetryPath))

	if !enabled {
		log.Info(" Telemetry is disabled",
			zap.String("enable_command", "eos self telemetry on"))
		return nil
	}

	// Get file statistics
	stats, err := getTelemetryStats(telemetryPath)
	if err != nil {
		log.Warn("Could not read telemetry statistics", zap.Error(err))
		return nil
	}

	log.Info("📈 Telemetry Statistics",
		zap.Int("total_commands", stats.TotalCommands),
		zap.Int("successful_commands", stats.SuccessfulCommands),
		zap.Int("failed_commands", stats.FailedCommands),
		zap.Float64("success_rate_percent", stats.SuccessRate),
		zap.String("file_size", stats.FileSize),
		zap.String("oldest_entry", stats.OldestEntry),
		zap.String("newest_entry", stats.NewestEntry))

	if len(stats.TopCommands) > 0 {
		log.Info("🔝 Most Used Commands")
		for i, cmd := range stats.TopCommands {
			if i >= 5 { // Show top 5
				break
			}
			log.Info("",
				zap.Int("rank", i+1),
				zap.String("command", cmd.Name),
				zap.Int("count", cmd.Count))
		}
	}

	showTelemetryInfo(log)
	return nil
}

// TelemetryStats holds statistics about telemetry data
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

type CommandCount struct {
	Name  string
	Count int
}

// getTelemetryStats analyzes the telemetry file and returns statistics
func getTelemetryStats(filePath string) (*TelemetryStats, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := file.Close(); err != nil {
			logger := otelzap.Ctx(context.Background())
			logger.Warn("Failed to close telemetry file", zap.Error(err))
		}
	}()

	// Get file info
	fileInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}

	stats := &TelemetryStats{
		FileSize: formatFileSize(fileInfo.Size()),
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

	return stats, scanner.Err()
}

// formatFileSize converts bytes to human-readable format
func formatFileSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func init() {
	SelfCmd.AddCommand(TelemetryCmd)
}
