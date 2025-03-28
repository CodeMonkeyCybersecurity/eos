// pkg/utils/utils.go

package utils

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"eos/pkg/config"
)

//
//---------------------------- CRYPTO, HASHING, SECRETS ---------------------------- //
//

// HashString computes and returns the SHA256 hash of the provided string.
func HashString(s string) string {
	hash := sha256.Sum256([]byte(s))
	hashStr := hex.EncodeToString(hash[:])
	return hashStr
}

// generatePassword creates a random alphanumeric password of the given length.
func GeneratePassword(length int) (string, error) {
	// Generate random bytes. Since hex encoding doubles the length, we need length/2 bytes.
	bytes := make([]byte, length/2)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	// Encode to hex and trim to required length.
	return hex.EncodeToString(bytes)[:length], nil
}

//
//---------------------------- LOGGING ---------------------------- //
//

// monitorVaultLogs tails the log file and prints new lines to STDOUT.
// It returns when it sees a line containing the specified marker or when the context is done.
func MonitorVaultLogs(ctx context.Context, logFilePath, marker string) error {
	file, err := os.Open(logFilePath)
	if err != nil {
		return fmt.Errorf("failed to open log file for monitoring: %w", err)
	}
	defer file.Close()

	// Seek to the end of the file so we only see new log lines.
	_, err = file.Seek(0, io.SeekEnd)
	if err != nil {
		return fmt.Errorf("failed to seek log file: %w", err)
	}

	scanner := bufio.NewScanner(file)
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout reached while waiting for Vault to start")
		default:
			if scanner.Scan() {
				line := scanner.Text()
				fmt.Println(line) // Print the log line to terminal
				if strings.Contains(line, marker) {
					return nil
				}
			} else {
				time.Sleep(500 * time.Millisecond) // No new line, wait and try again
			}
		}
	}
}

//
//---------------------------- HOSTNAME ---------------------------- //
//

// GetInternalHostname returns the machine's hostname.
// If os.Hostname() fails, it logs the error and returns "localhost".
func GetInternalHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "localhost"
	}
	return hostname
}

//
//---------------------------- ERROR HANDLING ---------------------------- //
//

// HandleError logs an error and optionally exits the program
func HandleError(err error, message string, exit bool) {
	if err != nil {
		if exit {
		}
	}
}

// WithErrorHandling wraps a function with error handling
func WithErrorHandling(fn func() error) {
	err := fn()
	if err != nil {
		HandleError(err, "An error occurred", true)
	}
}

//
//---------------------------- PERMISSIONS ---------------------------- //
//

// CheckSudo checks if the current user has sudo privileges
func CheckSudo() bool {
	cmd := exec.Command("sudo", "-n", "true")
	err := cmd.Run()
	return err != nil
}

//
//---------------------------- YAML ---------------------------- //
//

// Recursive function to process and print nested YAML structures
func ProcessMap(data map[string]interface{}, indent string) {
	for key, value := range data {
		switch v := value.(type) {
		case map[string]interface{}:
			fmt.Printf("%s%s:\n", indent, key)
			ProcessMap(v, indent+"  ")
		case []interface{}:
			fmt.Printf("%s%s:\n", indent, key)
			for _, item := range v {
				if itemMap, ok := item.(map[string]interface{}); ok {
					ProcessMap(itemMap, indent+"  ")
				} else {
					fmt.Printf("%s  - %v\n", indent, item)
				}
			}
		default:
			fmt.Printf("%s%s: %v\n", indent, key, v)
		}
	}
}

//
//---------------------------- FILE COMMANDS ---------------------------- //
//

// CopyFile copies a file from src to dst.
func CopyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open src file: %w", err)
	}
	defer srcFile.Close()

	srcInfo, err := srcFile.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat src file: %w", err)
	}

	dstFile, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, srcInfo.Mode())
	if err != nil {
		return fmt.Errorf("failed to create dst file: %w", err)
	}
	defer dstFile.Close()

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return fmt.Errorf("failed to copy contents: %w", err)
	}

	return nil
}

// CopyDir recursively copies a directory from src to dst.
func CopyDir(src, dst string) error {
	srcInfo, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("failed to stat src: %w", err)
	}
	if !srcInfo.IsDir() {
		return fmt.Errorf("source is not a directory: %s", src)
	}

	if err := os.MkdirAll(dst, srcInfo.Mode()); err != nil {
		return fmt.Errorf("failed to create dst dir: %w", err)
	}

	entries, err := os.ReadDir(src)
	if err != nil {
		return fmt.Errorf("failed to read dir: %w", err)
	}

	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		if entry.IsDir() {
			if err := CopyDir(srcPath, dstPath); err != nil {
				return err
			}
		} else {
			if err := CopyFile(srcPath, dstPath); err != nil {
				return err
			}
		}
	}

	return nil
}

// RemoveIfExists deletes the given path if it exists.
func RemoveIfExists(path string) error {
	if _, err := os.Stat(path); err == nil {
		return os.RemoveAll(path)
	} else if os.IsNotExist(err) {
		return nil // Nothing to do
	} else {
		return fmt.Errorf("failed to check path %s: %w", path, err)
	}
}

// DeployApp deploys the application by copying necessary config files and restarting services
func DeployApp(app string, force bool) error {

	if err := ValidateConfigPaths(app); err != nil {
		return fmt.Errorf("failed to validate config paths: %w", err)
	}

	// Test Nginx configuration
	cmdTest := exec.Command("nginx", "-t")
	if output, err := cmdTest.CombinedOutput(); err != nil {
		return fmt.Errorf("nginx config test failed: %s", string(output))
	}

	// Restart Nginx
	cmdRestart := exec.Command("systemctl", "restart", "nginx")
	if err := cmdRestart.Run(); err != nil {
		return fmt.Errorf("failed to restart nginx: %w", err)
	}

	return nil
}

//
//---------------------------- FACT CHECKING ---------------------------- //
//

// ✅ Moved here since it may be used in multiple commands
func IsValidApp(app string) bool {
	for _, validApp := range config.GetSupportedAppNames() {
		if app == validApp {
			return true
		}
	}
	return false
}

func OrganizeAssetsForDeployment(app string) error {
	assetsDir := "assets"
	otherDir := "other" // "other" is at the project root

	// Ensure the "other" directory exists.
	if err := os.MkdirAll(otherDir, 0755); err != nil {
		return fmt.Errorf("failed to create 'other' directory: %w", err)
	}

	// Define the generic allowed filenames (lowercase).
	allowedGenerics := map[string]bool{
		"http.conf":   true,
		"stream.conf": true,
		"nginx.conf":  true,
	}

	// Walk the assets directory.
	err := filepath.Walk(assetsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories.
		if info.IsDir() {
			return nil
		}

		// Compute the file's relative path from assetsDir.
		relPath, err := filepath.Rel(assetsDir, path)
		if err != nil {
			return err
		}

		// Get the base filename in lowercase.
		base := strings.ToLower(filepath.Base(path))

		// Check if the file is relevant.
		if allowedGenerics[base] || strings.Contains(base, strings.ToLower(app)) {
			return nil
		}

		// File is not relevant; log that it will be moved.
		dest := filepath.Join(otherDir, relPath)

		// Ensure the destination directory exists.
		if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
			return fmt.Errorf("failed to create destination directory %s: %w", filepath.Dir(dest), err)
		}

		// Move (rename) the file.
		if err := os.Rename(path, dest); err != nil {
			return fmt.Errorf("failed to move file %s to %s: %w", path, dest, err)
		}

		return nil
	})
	if err != nil {
	}
	return err
}

func ReplaceTokensInAllFiles(rootDir, baseDomain, backendIP string) error {
	return filepath.WalkDir(rootDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		// Read the file
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read file %s: %w", path, err)
		}
		content := string(data)
		// Replace tokens
		content = strings.ReplaceAll(content, "${BASE_DOMAIN}", baseDomain)
		content = strings.ReplaceAll(content, "${backendIP}", backendIP)
		content = strings.ReplaceAll(content, "${BACKEND_IP}", backendIP)
		// Write the file back with the same permissions
		info, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("failed to stat file %s: %w", path, err)
		}
		if err := os.WriteFile(path, []byte(content), info.Mode()); err != nil {
			return fmt.Errorf("failed to write file %s: %w", path, err)
		}
		return nil
	})
}

//
//---------------------------- DEPLOY HELPERS ---------------------------- //
//

// quote adds quotes around a string for cleaner logging
func Quote(s string) string {
	return fmt.Sprintf("%q", s)
}

// ValidateConfigPaths checks that the app’s Nginx source config files exist
func ValidateConfigPaths(app string) error {

	httpSrc := filepath.Join("assets/servers", app+".conf")

	if _, err := os.Stat(httpSrc); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("missing HTTP config: %s", httpSrc)
		}
		return fmt.Errorf("error checking config file: %w", err)
	}

	// Stream config is optional — no error if missing
	return nil
}

// PathExists returns true if the file or directory at the given path exists.
func PathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil || !os.IsNotExist(err)
}
