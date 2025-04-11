package backup

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	SRC_CONF       = "conf.d"
	SRC_CERTS      = "certs"
	SRC_COMPOSE    = "docker-compose.yml"
	BACKUP_CONF    = "conf.d.bak"
	BACKUP_CERTS   = "certs.bak"
	BACKUP_COMPOSE = "docker-compose.yml.bak"
)

// removeIfExists checks if a path exists and removes it if so.
// If it's a directory it uses os.RemoveAll, otherwise os.Remove.
func removeIfExists(path string) error {
	if _, err := os.Stat(path); err == nil {
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		if info.IsDir() {
			fmt.Printf("Removing existing directory '%s'...\n", path)
			return os.RemoveAll(path)
		} else {
			fmt.Printf("Removing existing file '%s'...\n", path)
			return os.Remove(path)
		}
	}
	return nil
}

// copyFile copies a file from src to dst, preserving the file mode.
func copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	srcInfo, err := srcFile.Stat()
	if err != nil {
		return err
	}

	// Create destination file with the same file mode.
	dstFile, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY, srcInfo.Mode())
	if err != nil {
		return err
	}
	defer dstFile.Close()

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return err
	}
	return nil
}

// copyDir recursively copies a directory from src to dst.
func copyDir(src, dst string) error {
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}

	// Create destination directory.
	if err := os.MkdirAll(dst, 0755); err != nil {
		return err
	}

	// Iterate over directory entries.
	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		if entry.IsDir() {
			// Recursively copy subdirectory.
			if err := copyDir(srcPath, dstPath); err != nil {
				return err
			}
		} else {
			// Copy individual file.
			if err := copyFile(srcPath, dstPath); err != nil {
				return err
			}
		}
	}

	return nil
}

func main() {
	// Backup the conf.d directory.
	srcInfo, err := os.Stat(SRC_CONF)
	if err != nil || !srcInfo.IsDir() {
		fmt.Printf("Error: Source directory '%s' does not exist.\n", SRC_CONF)
		os.Exit(1)
	}
	if err := removeIfExists(BACKUP_CONF); err != nil {
		fmt.Printf("Error removing backup directory '%s': %v\n", BACKUP_CONF, err)
		os.Exit(1)
	}
	if err := copyDir(SRC_CONF, BACKUP_CONF); err != nil {
		fmt.Printf("Error during backup of %s: %v\n", SRC_CONF, err)
		os.Exit(1)
	}
	fmt.Printf("Backup complete: '%s' has been backed up to '%s'.\n", SRC_CONF, BACKUP_CONF)

	// Backup the certs directory.
	srcInfo, err = os.Stat(SRC_CERTS)
	if err != nil || !srcInfo.IsDir() {
		fmt.Printf("Error: Source directory '%s' does not exist.\n", SRC_CERTS)
		os.Exit(1)
	}
	if err := removeIfExists(BACKUP_CERTS); err != nil {
		fmt.Printf("Error removing backup directory '%s': %v\n", BACKUP_CERTS, err)
		os.Exit(1)
	}
	if err := copyDir(SRC_CERTS, BACKUP_CERTS); err != nil {
		fmt.Printf("Error during backup of %s: %v\n", SRC_CERTS, err)
		os.Exit(1)
	}
	fmt.Printf("Backup complete: '%s' has been backed up to '%s'.\n", SRC_CERTS, BACKUP_CERTS)

	// Backup the docker-compose.yml file.
	srcInfo, err = os.Stat(SRC_COMPOSE)
	if err != nil || srcInfo.IsDir() {
		fmt.Printf("Error: Source file '%s' does not exist.\n", SRC_COMPOSE)
		os.Exit(1)
	}
	if err := removeIfExists(BACKUP_COMPOSE); err != nil {
		fmt.Printf("Error removing backup file '%s': %v\n", BACKUP_COMPOSE, err)
		os.Exit(1)
	}
	if err := copyFile(SRC_COMPOSE, BACKUP_COMPOSE); err != nil {
		fmt.Printf("Error during backup of %s: %v\n", SRC_COMPOSE, err)
		os.Exit(1)
	}
	fmt.Printf("Backup complete: '%s' has been backed up to '%s'.\n", SRC_COMPOSE, BACKUP_COMPOSE)
}
