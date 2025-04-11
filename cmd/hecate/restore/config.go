package restore

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Define backup and destination paths.
const (
	backupConf    = "conf.d.bak"
	backupCerts   = "certs.bak"
	backupCompose = "docker-compose.yml.bak"
	dstConf       = "conf.d"
	dstCerts      = "certs"
	dstCompose    = "docker-compose.yml"
)

// removeIfExists removes the file or directory at the given path if it exists.
func removeIfExists(path string) error {
	if _, err := os.Stat(path); err == nil {
		info, err := os.Stat(path)
		if err != nil {
			return err
		}

		if info.IsDir() {
			fmt.Printf("Removing directory '%s'...\n", path)
			return os.RemoveAll(path)
		} else {
			fmt.Printf("Removing file '%s'...\n", path)
			return os.Remove(path)
		}
	} else if os.IsNotExist(err) {
		return nil
	} else {
		return err
	}
}

// copyFile copies a file from src to dst, preserving file permissions.
func copyFile(src, dst string) error {
	srcInfo, err := os.Stat(src)
	if err != nil {
		return err
	}
	if !srcInfo.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", src)
	}

	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err = io.Copy(out, in); err != nil {
		return err
	}

	// Set destination file permissions same as the source.
	return out.Chmod(srcInfo.Mode())
}

// copyDir recursively copies a directory from src to dst.
func copyDir(src string, dst string) error {
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}

	srcInfo, err := os.Stat(src)
	if err != nil {
		return err
	}

	if err = os.MkdirAll(dst, srcInfo.Mode()); err != nil {
		return err
	}

	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		if entry.IsDir() {
			if err := copyDir(srcPath, dstPath); err != nil {
				return err
			}
		} else {
			if err := copyFile(srcPath, dstPath); err != nil {
				return err
			}
		}
	}
	return nil
}

func main() {
	// Restore conf.d directory.
	info, err := os.Stat(backupConf)
	if err != nil || !info.IsDir() {
		fmt.Printf("Error: Backup directory '%s' does not exist.\n", backupConf)
		os.Exit(1)
	}
	if err := removeIfExists(dstConf); err != nil {
		fmt.Printf("Error removing directory '%s': %v\n", dstConf, err)
		os.Exit(1)
	}
	if err := copyDir(backupConf, dstConf); err != nil {
		fmt.Printf("Error during restore of %s: %v\n", backupConf, err)
		os.Exit(1)
	}
	fmt.Printf("Restore complete: '%s' has been restored to '%s'.\n", backupConf, dstConf)

	// Restore certs directory.
	info, err = os.Stat(backupCerts)
	if err != nil || !info.IsDir() {
		fmt.Printf("Error: Backup directory '%s' does not exist.\n", backupCerts)
		os.Exit(1)
	}
	if err := removeIfExists(dstCerts); err != nil {
		fmt.Printf("Error removing directory '%s': %v\n", dstCerts, err)
		os.Exit(1)
	}
	if err := copyDir(backupCerts, dstCerts); err != nil {
		fmt.Printf("Error during restore of %s: %v\n", backupCerts, err)
		os.Exit(1)
	}
	fmt.Printf("Restore complete: '%s' has been restored to '%s'.\n", backupCerts, dstCerts)

	// Restore docker-compose.yml file.
	info, err = os.Stat(backupCompose)
	if err != nil || info.IsDir() {
		fmt.Printf("Error: Backup file '%s' does not exist.\n", backupCompose)
		os.Exit(1)
	}
	if err := removeIfExists(dstCompose); err != nil {
		fmt.Printf("Error removing file '%s': %v\n", dstCompose, err)
		os.Exit(1)
	}
	if err := copyFile(backupCompose, dstCompose); err != nil {
		fmt.Printf("Error during restore of %s: %v\n", backupCompose, err)
		os.Exit(1)
	}
	fmt.Printf("Restore complete: '%s' has been restored to '%s'.\n", backupCompose, dstCompose)
}
