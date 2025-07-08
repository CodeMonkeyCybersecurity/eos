// pkg/eos_utils/system_prompts.go

package pipeline

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/delphi_channels"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// DefaultSystemPromptsDir is the standard path for system prompts.
const DefaultSystemPromptsDir = "/srv/eos/system-prompts"

// EnsureSystemPromptsDirectory ensures the system prompts directory exists
// and has the specified ownership and permissions.
//
// Arguments:
//
//	dirPath: The full path to the directory (e.g., "/srv/eos/system-prompts").
//	ownerUser: The desired username for the directory owner (e.g., "stanley").
//	ownerGroup: The desired group name for the directory owner (e.g., "stanley").
//	dirPerms: The desired file mode for the directory (e.g., 0755).
//	logger: An otelzap.LoggerWithCtx for logging.
//
// Returns:
//
//	An error if the directory cannot be created, permissions cannot be set,
//	or ownership cannot be changed.
//
// EnsureSystemPromptsDirectory ensures the system prompts directory exists
// and has the specified ownership and permissions.
//
// Arguments:
//
//	dirPath: The full path to the directory (e.g., "/srv/eos/system-prompts").
//	ownerUser: The desired username for the directory owner (e.g., "stanley").
//	ownerGroup: The desired group name for the directory owner (e.g., "stanley").
//	dirPerms: The desired file mode for the directory (e.g., 0755).
//	logger: An otelzap.LoggerWithCtx for logging.
//
// Returns:
//
//	An error if the directory cannot be created, permissions cannot be set,
//	or ownership cannot be changed.
func EnsureSystemPromptsDirectory(
	dirPath string,
	ownerUser string,
	ownerGroup string,
	dirPerms os.FileMode,
	logger otelzap.LoggerWithCtx,
) error {
	logger.Info("Ensuring system prompts directory exists and has correct permissions",
		zap.String("path", dirPath),
		zap.String("owner_user", ownerUser),
		zap.String("owner_group", ownerGroup),
		zap.String("permissions", fmt.Sprintf("%o", dirPerms)),
	)

	// Step 1: Check if the directory exists. If not, create it.
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		logger.Info("System prompts directory does not exist, creating it", zap.String("path", dirPath))
		if err := os.MkdirAll(dirPath, dirPerms); err != nil {
			return fmt.Errorf("failed to create system prompts directory '%s': %w", dirPath, err)
		}
		logger.Info("System prompts directory created", zap.String("path", dirPath))
	} else if err != nil {
		// Other error than not existing (e.g., permissions to stat)
		return fmt.Errorf("failed to stat system prompts directory '%s': %w", dirPath, err)
	}

	// Step 2: Set the correct permissions for the directory.
	// This ensures the initial permissions are correct, or updates them if they're wrong.
	if err := os.Chmod(dirPath, dirPerms); err != nil {
		return fmt.Errorf("failed to set permissions for directory '%s': %w", dirPath, err)
	}
	logger.Debug("Directory permissions set",
		zap.String("path", dirPath),
		zap.String("permissions", fmt.Sprintf("%o", dirPerms)),
	)

	// Step 3: Get UID and GID for the specified ownerUser and ownerGroup.
	usr, err := user.Lookup(ownerUser)
	if err != nil {
		return fmt.Errorf("failed to lookup user '%s': %w", ownerUser, err)
	}
	uid, err := strconv.Atoi(usr.Uid)
	if err != nil {
		return fmt.Errorf("failed to parse UID for user '%s': %w", ownerUser, err)
	}

	grp, err := user.LookupGroup(ownerGroup)
	if err != nil {
		return fmt.Errorf("failed to lookup group '%s': %w", ownerGroup, err)
	}
	gid, err := strconv.Atoi(grp.Gid)
	if err != nil {
		return fmt.Errorf("failed to parse GID for group '%s': %w", ownerGroup, err)
	}

	// Step 4: Set the ownership for the directory.
	if err := os.Chown(dirPath, uid, gid); err != nil {
		return fmt.Errorf("failed to change ownership of directory '%s' to %s:%s: %w", dirPath, ownerUser, ownerGroup, err)
	}
	logger.Info("Directory ownership set",
		zap.String("path", dirPath),
		zap.String("owner", ownerUser),
		zap.String("group", ownerGroup),
	)

	// Step 5: (Optional but recommended) Iterate over existing files and set ownership/permissions.
	// This ensures consistency for any files already placed there manually.
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		logger.Warn("Failed to read directory entries to set file permissions/ownership, continuing", zap.Error(err))
		// Not a fatal error for the directory setup itself, but worth logging.
	} else {
		for _, entry := range entries {
			filePath := filepath.Join(dirPath, entry.Name())
			// Set ownership for files (directories handled by MkdirAll and Chown on dirPath)
			if !entry.IsDir() {
				if err := os.Chown(filePath, uid, gid); err != nil {
					logger.Warn("Failed to change ownership of file, continuing",
						zap.String("file", filePath),
						zap.String("owner", ownerUser),
						zap.String("group", ownerGroup),
						zap.Error(err),
					)
				}
				// Set read permissions for .txt files for the owner and group, others read-only
				if filepath.Ext(filePath) == ".txt" {
					if err := os.Chmod(filePath, 0644); err != nil {
						logger.Warn("Failed to set permissions for file, continuing",
							zap.String("file", filePath),
							zap.String("permissions", "0644"),
							zap.Error(err),
						)
					}
				}
			}
		}
	}

	logger.Info("System prompts directory and its contents ensured successfully", zap.String("path", dirPath))
	return nil
}

// FileExists checks if a file exists
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// FormatFileSize formats file size in human readable format
func FormatFileSize(bytes int64) string {
	if bytes < 1024 {
		return fmt.Sprintf("%d B", bytes)
	}
	if bytes < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(bytes)/1024)
	}
	return fmt.Sprintf("%.1f MB", float64(bytes)/(1024*1024))
}

// formatRelativeTime formats time relative to now
func FormatRelativeTime(t time.Time) string {
	now := time.Now()
	diff := now.Sub(t)

	if diff < time.Hour {
		return fmt.Sprintf("%d minutes ago", int(diff.Minutes()))
	}
	if diff < 24*time.Hour {
		return fmt.Sprintf("%d hours ago", int(diff.Hours()))
	}
	if diff < 30*24*time.Hour {
		return fmt.Sprintf("%d days ago", int(diff.Hours()/24))
	}
	return t.Format("2006-01-02")
}

// formatSizeChange formats the size change between old and new file sizes
func formatSizeChange(oldSize, newSize int64) string {
	diff := newSize - oldSize
	if diff == 0 {
		return "no change"
	} else if diff > 0 {
		return fmt.Sprintf("+%s", FormatFileSize(diff))
	} else {
		return fmt.Sprintf("-%s", FormatFileSize(-diff))
	}
}

// runAnalysis analyzes worker configurations without making changes
func runAnalysis(standardizer *delphi_channels.ChannelStandardizer, outputJSON bool, logger otelzap.LoggerWithCtx) error {
	logger.Info("Analyzing current worker channel configurations")

	infos, err := standardizer.AnalyzeWorkers()
	if err != nil {
		logger.Error("Failed to analyze workers", zap.Error(err))
		return fmt.Errorf("analysis failed: %v", err)
	}

	if outputJSON {
		return outputWorkerAnalysisJSON(infos)
	} else {
		return outputWorkerAnalysisText(infos)
	}
}

// runStandardization performs channel standardization
func runStandardization(standardizer *delphi_channels.ChannelStandardizer, outputJSON, dryRun bool, logger otelzap.LoggerWithCtx) error {
	if dryRun {
		logger.Info("Running in dry-run mode - no changes will be made")
	} else {
		logger.Info("Standardizing notification channels")
	}

	result := standardizer.StandardizeAll()

	if outputJSON {
		return outputStandardizationJSON(result)
	} else {
		return outputStandardizationText(result, dryRun)
	}
}

// outputWorkerAnalysisJSON outputs worker analysis in JSON format
func outputWorkerAnalysisJSON(infos []delphi_channels.WorkerChannelInfo) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(map[string]interface{}{
		"analysis":          infos,
		"standard_channels": delphi_channels.StandardChannels,
	})
}

// outputWorkerAnalysisText outputs worker analysis in human-readable format
func outputWorkerAnalysisText(infos []delphi_channels.WorkerChannelInfo) error {
	fmt.Println("Delphi Notification Channel Analysis")
	fmt.Println(strings.Repeat("=", 50))

	correctCount := 0
	for _, info := range infos {
		fmt.Printf("\n%s\n", info.Filename)

		if info.IsCorrect {
			fmt.Println("    Configuration is correct")
			correctCount++
		} else {
			fmt.Println("   Configuration needs fixing")
		}

		if len(info.ListenChannels) > 0 {
			fmt.Printf("   Listen: %s\n", strings.Join(info.ListenChannels, ", "))
		}

		if len(info.NotifyChannels) > 0 {
			fmt.Printf("   Notify: %s\n", strings.Join(info.NotifyChannels, ", "))
		}

		if len(info.Issues) > 0 {
			fmt.Println("    Issues:")
			for _, issue := range info.Issues {
				fmt.Printf("      • %s\n", issue)
			}
		}
	}

	fmt.Println("\n" + strings.Repeat("=", 50))
	fmt.Printf("Summary: %d/%d workers correctly configured\n", correctCount, len(infos))

	if correctCount < len(infos) {
		fmt.Println("\nTo fix issues, run: eos update delphi-notification-channels")
	}

	fmt.Println("\nSTANDARD NOTIFICATION FLOW:")
	for channel, description := range delphi_channels.StandardChannels {
		fmt.Printf("   %-18s → %s\n", channel, description)
	}
	fmt.Println(strings.Repeat("=", 50))

	return nil
}

// outputStandardizationJSON outputs standardization results in JSON format
func outputStandardizationJSON(result *delphi_channels.StandardizationResult) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

// outputStandardizationText outputs standardization results in human-readable format
func outputStandardizationText(result *delphi_channels.StandardizationResult, dryRun bool) error {
	if dryRun {
		fmt.Println("Notification Channel Standardization (DRY RUN)")
	} else {
		fmt.Println("Notification Channel Standardization")
	}
	fmt.Println(strings.Repeat("=", 50))

	// Show changes
	if len(result.Changes) > 0 {
		if dryRun {
			fmt.Printf("\nCHANGES THAT WOULD BE MADE (%d):\n", len(result.Changes))
		} else {
			fmt.Printf("\nCHANGES MADE (%d):\n", len(result.Changes))
		}

		changesByFile := groupChangesByFile(result.Changes)
		for file, changes := range changesByFile {
			fmt.Printf("   %s:\n", file)
			for _, change := range changes {
				fmt.Printf("      %s: %s → %s\n",
					getChangeTypeEmoji(change.Type),
					change.OldValue,
					change.NewValue)
			}
		}
	}

	// Show files updated
	if len(result.FilesUpdated) > 0 {
		if dryRun {
			fmt.Printf("\nFILES THAT WOULD BE UPDATED (%d):\n", len(result.FilesUpdated))
		} else {
			fmt.Printf("\nFILES UPDATED (%d):\n", len(result.FilesUpdated))
		}
		for _, file := range result.FilesUpdated {
			fmt.Printf("   ✓ %s\n", file)
		}
	}

	// Show files skipped
	if len(result.FilesSkipped) > 0 {
		fmt.Printf("\nFILES SKIPPED (%d):\n", len(result.FilesSkipped))
		for _, file := range result.FilesSkipped {
			fmt.Printf("   • %s\n", file)
		}
	}

	// Show backups created
	if len(result.BackupsCreated) > 0 && !dryRun {
		fmt.Printf("\nBACKUPS CREATED (%d):\n", len(result.BackupsCreated))
		for _, backup := range result.BackupsCreated {
			fmt.Printf("   %s\n", backup)
		}
	}

	// Show errors
	if len(result.Errors) > 0 {
		fmt.Printf("\nERRORS (%d):\n", len(result.Errors))
		for _, err := range result.Errors {
			fmt.Printf("   • %s\n", err)
		}
	}

	// Summary
	fmt.Println("\n" + strings.Repeat("=", 50))

	if result.Success {
		if len(result.Changes) == 0 {
			fmt.Println("All workers already use correct notification channels!")
		} else if dryRun {
			fmt.Printf("Analysis complete: %d changes needed\n", len(result.Changes))
			fmt.Println("Run without --dry-run to apply changes")
		} else {
			fmt.Printf("Standardization complete: %d changes applied\n", len(result.Changes))
		}
	} else {
		fmt.Println("Standardization completed with errors")
		if !dryRun {
			os.Exit(1)
		}
	}

	if !dryRun && len(result.Changes) == 0 {
		fmt.Println("\nSTANDARD NOTIFICATION FLOW:")
		for channel, description := range delphi_channels.StandardChannels {
			fmt.Printf("   %-18s → %s\n", channel, description)
		}
	}

	fmt.Println(strings.Repeat("=", 50))
	return nil
}

// Helper functions
func groupChangesByFile(changes []delphi_channels.ChannelChange) map[string][]delphi_channels.ChannelChange {
	grouped := make(map[string][]delphi_channels.ChannelChange)
	for _, change := range changes {
		filename := change.File
		if strings.Contains(filename, "/") {
			// Extract just the filename from the path
			parts := strings.Split(filename, "/")
			filename = parts[len(parts)-1]
		}
		grouped[filename] = append(grouped[filename], change)
	}
	return grouped
}

func getChangeTypeEmoji(changeType string) string {
	switch changeType {
	case "listen_channel":
		return "📥"
	case "notify_channel":
		return "📤"
	case "pg_notify":
		return "🔔"
	case "listen_statement":
		return "👂"
	default:
		return ""
	}
}
