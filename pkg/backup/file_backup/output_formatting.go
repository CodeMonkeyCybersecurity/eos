package file_backup

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/utils"
)

// Output formatting functions

func OutputFileBackupJSON(result *FileBackupOperation) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func OutputFileBackupText(result *FileBackupOperation) error {
	if result.DryRun {
		fmt.Printf("[DRY RUN] %s\n", result.Message)
	} else if result.Success {
		fmt.Printf("✓ %s\n", result.Message)
		if result.Duration > 0 {
			fmt.Printf("  Duration: %v\n", result.Duration)
		}
		if result.FileSize > 0 {
			fmt.Printf("  Size: %d bytes\n", result.FileSize)
		}
	} else {
		fmt.Printf("✗ %s\n", result.Message)
	}
	return nil
}

func OutputFileListJSON(result *BackupListResult) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func OutputFileListText(result *BackupListResult) error {
	if result.TotalBackups == 0 {
		fmt.Printf("No backups found in %s\n", result.BackupDir)
		return nil
	}

	fmt.Printf("Found %d backups in %s\n", result.TotalBackups, result.BackupDir)
	fmt.Printf("Total size: %d bytes\n\n", result.TotalSize)

	// Print header
	fmt.Printf("%-30s %-20s %-12s %s\n", "BACKUP NAME", "ORIGINAL FILE", "SIZE", "BACKUP TIME")
	fmt.Println(strings.Repeat("-", 80))

	// Print backups
	for _, backup := range result.Backups {
		originalFile := backup.OriginalFile
		if originalFile == "" {
			originalFile = "-"
		}

		backupTime := "-"
		if !backup.BackupTime.IsZero() {
			backupTime = backup.BackupTime.Format("01-02 15:04")
		}

		fmt.Printf("%-30s %-20s %-12d %s\n",
			utils.TruncateString(backup.Name, 30),
			utils.TruncateString(originalFile, 20),
			backup.Size,
			backupTime)
	}

	return nil
}

func OutputFileRestoreJSON(result *RestoreOperation) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func OutputFileRestoreText(result *RestoreOperation) error {
	if result.DryRun {
		fmt.Printf("[DRY RUN] %s\n", result.Message)
	} else if result.Success {
		fmt.Printf("✓ %s\n", result.Message)
		if result.Overwritten {
			fmt.Printf("  (File was overwritten)\n")
		}
		if result.Duration > 0 {
			fmt.Printf("  Duration: %v\n", result.Duration)
		}
	} else {
		fmt.Printf("✗ %s\n", result.Message)
	}
	return nil
}
