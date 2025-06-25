// pkg/eos_utils/system_prompts.go

package pipeline

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"time"

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
