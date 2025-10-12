// cmd/debug/watchdog_traces.go

package debug

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var watchdogTracesCmd = &cobra.Command{
	Use:   "watchdog-traces",
	Short: "Analyze resource watchdog traces from previous runs",
	Long: `Display and analyze traces captured by the resource watchdog during high resource usage events.

This command helps diagnose resource exhaustion issues by examining the detailed traces
captured when the system experienced high CPU, memory usage, or excessive process counts.`,
	RunE: eos_cli.Wrap(runWatchdogTraces),
}

var (
	sessionFlag  string
	detailFlag   bool
	criticalFlag bool
)

func init() {
	watchdogTracesCmd.Flags().StringVar(&sessionFlag, "session", "", "Specific session ID to analyze")
	watchdogTracesCmd.Flags().BoolVar(&detailFlag, "detail", false, "Show detailed trace information")
	watchdogTracesCmd.Flags().BoolVar(&criticalFlag, "critical-only", false, "Show only sessions with critical events")
}

func runWatchdogTraces(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Find trace directory
	traceDir := "/var/log/eos/watchdog"
	if home := os.Getenv("HOME"); home != "" && os.Getuid() != 0 {
		userDir := filepath.Join(home, ".eos", "watchdog")
		if _, err := os.Stat(userDir); err == nil {
			traceDir = userDir
		}
	}

	logger.Info("Searching for watchdog traces", zap.String("directory", traceDir))

	// Check if trace directory exists
	if _, err := os.Stat(traceDir); os.IsNotExist(err) {
		logger.Info("No watchdog traces found",
			zap.String("expected_location", traceDir),
			zap.String("note", "Resource watchdog creates traces when resource usage exceeds thresholds"))
		return nil
	}

	// If specific session requested, show it
	if sessionFlag != "" {
		return showSessionDetail(rc, traceDir, sessionFlag)
	}

	// List all sessions
	sessions, err := ioutil.ReadDir(traceDir)
	if err != nil {
		return fmt.Errorf("failed to read trace directory: %w", err)
	}

	// Filter and sort sessions
	var watchdogSessions []os.FileInfo
	for _, session := range sessions {
		if session.IsDir() && strings.HasPrefix(session.Name(), "eos-watchdog-") {
			// Skip if critical-only flag is set and session has no critical events
			if criticalFlag {
				criticalDir := filepath.Join(traceDir, session.Name(), "critical")
				if _, err := os.Stat(criticalDir); os.IsNotExist(err) {
					continue
				}
			}
			watchdogSessions = append(watchdogSessions, session)
		}
	}

	// Sort by modification time (newest first)
	sort.Slice(watchdogSessions, func(i, j int) bool {
		return watchdogSessions[i].ModTime().After(watchdogSessions[j].ModTime())
	})

	if len(watchdogSessions) == 0 {
		logger.Info("No watchdog sessions found")
		return nil
	}

	fmt.Printf("\n=== Resource Watchdog Trace Sessions ===\n")
	fmt.Printf("Found %d sessions in %s\n\n", len(watchdogSessions), traceDir)

	// Display summary of each session
	for i, session := range watchdogSessions {
		sessionPath := filepath.Join(traceDir, session.Name())

		fmt.Printf("%d. %s ", i+1, session.Name())

		// Show age
		age := time.Since(session.ModTime())
		if age < time.Hour {
			fmt.Printf("(%.0f minutes ago)\n", age.Minutes())
		} else if age < 24*time.Hour {
			fmt.Printf("(%.1f hours ago)\n", age.Hours())
		} else {
			fmt.Printf("(%.0f days ago)\n", age.Hours()/24)
		}

		// Check for critical events
		if _, err := os.Stat(filepath.Join(sessionPath, "critical")); err == nil {
			fmt.Printf("   CRITICAL EVENT DETECTED\n")
		}

		// Count warnings
		warningCount := countWarnings(sessionPath)
		if warningCount > 0 {
			fmt.Printf("   ⚡ %d warning events\n", warningCount)
		}

		// Read summary from main log
		if summary := getSessionSummary(sessionPath); summary != "" {
			fmt.Printf("    %s\n", summary)
		}

		// Show size of traces
		size := getDirectorySize(sessionPath)
		fmt.Printf("   💾 Trace size: %s\n", formatBytes(size))

		fmt.Println()
	}

	fmt.Printf("\n💡 Tips:\n")
	fmt.Printf("  • Use --session=<session-id> to view detailed analysis\n")
	fmt.Printf("  • Use --critical-only to filter critical events\n")
	fmt.Printf("  • Use --detail with --session for complete trace data\n")
	fmt.Printf("\nExample: eos debug watchdog-traces --session=%s --detail\n", watchdogSessions[0].Name())

	return nil
}

func showSessionDetail(rc *eos_io.RuntimeContext, traceDir, sessionID string) error {
	logger := otelzap.Ctx(rc.Ctx)
	sessionPath := filepath.Join(traceDir, sessionID)

	if _, err := os.Stat(sessionPath); os.IsNotExist(err) {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	logger.Info("Analyzing session", zap.String("session", sessionID))

	fmt.Printf("\n=== Watchdog Session Analysis: %s ===\n\n", sessionID)

	// Read main log
	mainLog := filepath.Join(sessionPath, "watchdog.log")
	if logData, err := ioutil.ReadFile(mainLog); err == nil {
		lines := strings.Split(string(logData), "\n")

		// Extract key events
		var startTime, endTime string
		var warnings, criticals []string

		for _, line := range lines {
			if strings.Contains(line, "Session Started") {
				startTime = extractTimestamp(line)
			} else if strings.Contains(line, "WARNING:") {
				warnings = append(warnings, line)
			} else if strings.Contains(line, "CRITICAL:") {
				criticals = append(criticals, line)
			}
			if line != "" {
				endTime = extractTimestamp(line)
			}
		}

		fmt.Printf("📅 Session Timeline:\n")
		fmt.Printf("   Started: %s\n", startTime)
		if endTime != "" && endTime != startTime {
			fmt.Printf("   Last Event: %s\n", endTime)
		}
		fmt.Printf("\n")

		// Show warnings
		if len(warnings) > 0 {
			fmt.Printf("⚡ Warnings (%d):\n", len(warnings))
			for i, w := range warnings {
				if i < 5 || detailFlag {
					fmt.Printf("   %s\n", strings.TrimSpace(w))
				}
			}
			if len(warnings) > 5 && !detailFlag {
				fmt.Printf("   ... and %d more (use --detail to see all)\n", len(warnings)-5)
			}
			fmt.Printf("\n")
		}

		// Show critical events
		if len(criticals) > 0 {
			fmt.Printf("Critical Events (%d):\n", len(criticals))
			for _, c := range criticals {
				fmt.Printf("   %s\n", strings.TrimSpace(c))
			}
			fmt.Printf("\n")
		}
	}

	// Show system info if available
	sysInfo := filepath.Join(sessionPath, "system", "info.txt")
	if data, err := ioutil.ReadFile(sysInfo); err == nil {
		fmt.Printf("🖥️  System Information:\n")
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if strings.Contains(line, "Hostname:") ||
				strings.Contains(line, "OS:") ||
				strings.Contains(line, "NumCPU:") ||
				strings.Contains(line, "Total:") && strings.Contains(line, "GB") {
				fmt.Printf("   %s\n", strings.TrimSpace(line))
			}
		}
		fmt.Printf("\n")
	}

	// Show critical diagnostics if available
	criticalDir := filepath.Join(sessionPath, "critical")
	if _, err := os.Stat(criticalDir); err == nil {
		fmt.Printf("🚨 Critical Diagnostics Available:\n")

		// List files in critical directory
		if files, err := ioutil.ReadDir(criticalDir); err == nil {
			for _, file := range files {
				fmt.Printf("   • %s (%s)\n", file.Name(), formatBytes(file.Size()))

				// Show preview of process details
				if file.Name() == "processes-detailed.txt" && detailFlag {
					if data, err := ioutil.ReadFile(filepath.Join(criticalDir, file.Name())); err == nil {
						lines := strings.Split(string(data), "\n")
						fmt.Printf("\n     Process Details Preview:\n")
						for i, line := range lines {
							if i < 20 || detailFlag {
								if strings.HasPrefix(line, "---") ||
									strings.Contains(line, "PID") ||
									strings.Contains(line, "CPU:") ||
									strings.Contains(line, "Memory:") {
									fmt.Printf("     %s\n", line)
								}
							}
						}
					}
				}
			}
		}
		fmt.Printf("\n")
	}

	// Provide analysis commands
	fmt.Printf("📊 Analysis Commands:\n")
	fmt.Printf("   • View CPU profile: go tool pprof %s\n", filepath.Join(criticalDir, "cpu.prof"))
	fmt.Printf("   • View memory profile: go tool pprof %s\n", filepath.Join(criticalDir, "mem.prof"))
	fmt.Printf("   • View process tree: cat %s\n", filepath.Join(criticalDir, "ps-tree.txt"))
	fmt.Printf("\n")

	return nil
}

// Helper functions

func countWarnings(sessionPath string) int {
	count := 0
	filepath.Walk(sessionPath, func(path string, info os.FileInfo, err error) error {
		if info.IsDir() && strings.HasPrefix(info.Name(), "warning-") {
			count++
		}
		return nil
	})
	return count
}

func getSessionSummary(sessionPath string) string {
	mainLog := filepath.Join(sessionPath, "watchdog.log")
	if data, err := ioutil.ReadFile(mainLog); err == nil {
		lines := strings.Split(string(data), "\n")
		// Find last significant event
		for i := len(lines) - 1; i >= 0; i-- {
			line := strings.TrimSpace(lines[i])
			if strings.Contains(line, "Resource") ||
				strings.Contains(line, "Process") ||
				strings.Contains(line, "CPU") ||
				strings.Contains(line, "Memory") {
				// Extract just the message part
				if idx := strings.Index(line, "]"); idx > 0 && idx < len(line)-1 {
					return strings.TrimSpace(line[idx+1:])
				}
				return line
			}
		}
	}
	return ""
}

func getDirectorySize(path string) int64 {
	var size int64
	filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			size += info.Size()
		}
		return nil
	})
	return size
}

func formatBytes(bytes int64) string {
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

func extractTimestamp(line string) string {
	// Extract timestamp from log line format: [HH:MM:SS.mmm] message
	if start := strings.Index(line, "["); start >= 0 {
		if end := strings.Index(line[start:], "]"); end > 0 {
			return line[start+1 : start+end]
		}
	}
	return ""
}
