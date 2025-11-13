// pkg/clean/clean.go

package clean

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Forbidden characters for Windows filenames (including control characters)
var forbidden = regexp.MustCompile(`[<>:"/\\|?*\x00\n\r\t]`)

// Reserved Windows device names
var reserved = map[string]bool{
	"CON": true, "PRN": true, "AUX": true, "NUL": true,
	"COM1": true, "COM2": true, "COM3": true, "COM4": true, "COM5": true, "COM6": true, "COM7": true, "COM8": true, "COM9": true,
	"LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true, "LPT5": true, "LPT6": true, "LPT7": true, "LPT8": true, "LPT9": true,
}

// -----------------------------------------------------------------------------
// Sanitiser helpers
// -----------------------------------------------------------------------------

// invalidRE is unused but kept for potential future filename validation
var _ = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

// Sanitize a single file/directory name for Windows
func SanitizeName(name string) string {
	// Limit length to prevent DoS (Windows max filename is 255)
	if len(name) > 255 {
		name = name[:255]
	}

	// Remove forbidden characters (including null bytes and control characters)
	clean := forbidden.ReplaceAllString(name, "_")

	// Remove trailing spaces or dots
	clean = strings.TrimRight(clean, " .")

	// Prevent reserved device names
	base := strings.ToUpper(clean)
	if reserved[base] {
		clean = clean + "_file"
	}

	if clean == "" {
		clean = "_"
	}
	return clean
}

func WalkAndSanitize(root string) error {
	return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		dir := filepath.Dir(path)
		oldName := filepath.Base(path)
		newName := SanitizeName(oldName)

		// If the name changed, rename
		if newName != oldName {
			oldPath := path
			newPath := filepath.Join(dir, newName)
			fmt.Printf("Renaming: %s → %s\n", oldPath, newPath)
			if err := os.Rename(oldPath, newPath); err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "Rename failed: %v\n", err)
				return err
			}
		}
		return nil
	})
}

func Usage() {
	fmt.Println("Usage: eos clean /path/to/file_or_dir --for-microsoft")
	os.Exit(1)
}

// -----------------------------------------------------------------------------
// Internal helper
// -----------------------------------------------------------------------------

func RenameIfNeeded(oldPath string) error {
	dir := filepath.Dir(oldPath)
	oldName := filepath.Base(oldPath)
	newName := SanitizeName(oldName)
	if newName == oldName {
		return nil
	}
	newPath := filepath.Join(dir, newName)
	fmt.Printf("Renaming: %s → %s\n", oldPath, newPath)
	return os.Rename(oldPath, newPath)
}
