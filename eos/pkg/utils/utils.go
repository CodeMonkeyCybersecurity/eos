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

	"go.uber.org/zap"

	"eos/pkg/config"
	"eos/pkg/logger"
)

var log = logger.L()

//
//---------------------------- CRYPTO, HASHING, SECRETS ---------------------------- //
//

// HashString computes and returns the SHA256 hash of the provided string.
func HashString(s string) string {
	log.Debug("Computing SHA256 hash", zap.String("input", s))
	hash := sha256.Sum256([]byte(s))
	hashStr := hex.EncodeToString(hash[:])
	log.Debug("Computed SHA256 hash", zap.String("hash", hashStr))
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
		log.Error("Failed to open log file for monitoring", zap.String("logFilePath", logFilePath), zap.Error(err))
		return fmt.Errorf("failed to open log file for monitoring: %w", err)
	}
	defer file.Close()

	// Seek to the end of the file so we only see new log lines.
	_, err = file.Seek(0, io.SeekEnd)
	if err != nil {
		log.Error("Failed to seek log file", zap.String("logFilePath", logFilePath), zap.Error(err))
		return fmt.Errorf("failed to seek log file: %w", err)
	}

	scanner := bufio.NewScanner(file)
	for {
		select {
		case <-ctx.Done():
			log.Warn("Timeout reached while waiting for Vault to start")
			return fmt.Errorf("timeout reached while waiting for Vault to start")
		default:
			if scanner.Scan() {
				line := scanner.Text()
				fmt.Println(line) // Print the log line to terminal
				log.Debug("Vault Log Line", zap.String("logLine", line))
				if strings.Contains(line, marker) {
					log.Info("Vault marker found, exiting log monitor", zap.String("marker", marker))
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
	log.Info("Retrieving internal hostname")
	hostname, err := os.Hostname()
	if err != nil {
		log.Error("Unable to retrieve hostname, defaulting to localhost", zap.Error(err))
		return "localhost"
	}
	log.Info("Retrieved hostname", zap.String("hostname", hostname))
	return hostname
}

//
//---------------------------- ERROR HANDLING ---------------------------- //
//

// HandleError logs an error and optionally exits the program
func HandleError(err error, message string, exit bool) {
	if err != nil {
		log.Error(message, zap.Error(err))
		if exit {
			log.Fatal("Exiting program due to error", zap.String("message", message))
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
	log.Info("Checking if user has sudo privileges")
	cmd := exec.Command("sudo", "-n", "true") // Non-interactive sudo check
	err := cmd.Run()
	if err != nil {
		log.Warn("User does not have sudo privileges", zap.Error(err))
		return false
	}
	log.Info("User has sudo privileges")
	return true
}

//
//---------------------------- YAML ---------------------------- //
//

// Recursive function to process and print nested YAML structures
func ProcessMap(data map[string]interface{}, indent string) {
	log.Debug("Processing YAML map")
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
	log.Debug("Completed processing YAML map")
}

// Convenience logging wrappers that call logger.GetLogger()
func Info(msg string, fields ...zap.Field)  { logger.GetLogger().Info(msg, fields...) }
func Warn(msg string, fields ...zap.Field)  { logger.GetLogger().Warn(msg, fields...) }
func Error(msg string, fields ...zap.Field) { logger.GetLogger().Error(msg, fields...) }
func Debug(msg string, fields ...zap.Field) { logger.GetLogger().Debug(msg, fields...) }
func Fatal(msg string, fields ...zap.Field) { logger.GetLogger().Fatal(msg, fields...) }
func Panic(msg string, fields ...zap.Field) { logger.GetLogger().Panic(msg, fields...) }
func SyncLogger() error                     { return logger.Sync() }

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
	log.Info("🚀 Starting deployment", zap.String("app", app), zap.Bool("force", force))

	if err := ValidateConfigPaths(app); err != nil {
		return fmt.Errorf("failed to validate config paths: %w", err)
	}

	// Test Nginx configuration
	cmdTest := exec.Command("nginx", "-t")
	if output, err := cmdTest.CombinedOutput(); err != nil {
		log.Error("❌ Nginx config test failed", zap.String("output", string(output)), zap.Error(err))
		return fmt.Errorf("nginx config test failed: %s", string(output))
	}

	// Restart Nginx
	cmdRestart := exec.Command("systemctl", "restart", "nginx")
	if err := cmdRestart.Run(); err != nil {
		log.Error("❌ Failed to restart Nginx", zap.Error(err))
		return fmt.Errorf("failed to restart nginx: %w", err)
	}

	log.Info("✅ Deployment successful", zap.String("app", app))
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
	log.Info("OrganizeAssetsForDeployment: 'other' directory verified", zap.String("other_Dir", otherDir))

	// Define the generic allowed filenames (lowercase).
	allowedGenerics := map[string]bool{
		"http.conf":   true,
		"stream.conf": true,
		"nginx.conf":  true,
	}

	// Walk the assets directory.
	err := filepath.Walk(assetsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Error("Error accessing path", zap.String("path", path), zap.Error(err))
			return err
		}

		// Skip directories.
		if info.IsDir() {
			log.Debug("Skipping directory", zap.String("dir", path))
			return nil
		}

		// Compute the file's relative path from assetsDir.
		relPath, err := filepath.Rel(assetsDir, path)
		if err != nil {
			log.Error("Failed to compute relative path", zap.String("path", path), zap.Error(err))
			return err
		}
		log.Debug("Processing file", zap.String("relativePath", relPath))

		// Get the base filename in lowercase.
		base := strings.ToLower(filepath.Base(path))
		log.Debug("Base filename", zap.String("base", base))

		// Check if the file is relevant.
		if allowedGenerics[base] || strings.Contains(base, strings.ToLower(app)) {
			log.Debug("File is relevant; leaving it in assets", zap.String("file", path))
			return nil
		}

		// File is not relevant; log that it will be moved.
		dest := filepath.Join(otherDir, relPath)
		log.Debug("File not relevant; preparing to move", zap.String("file", path), zap.String("destination", dest))

		// Ensure the destination directory exists.
		if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
			log.Error("Failed to create destination directory", zap.String("destDir", filepath.Dir(dest)), zap.Error(err))
			return fmt.Errorf("failed to create destination directory %s: %w", filepath.Dir(dest), err)
		}

		// Move (rename) the file.
		if err := os.Rename(path, dest); err != nil {
			log.Error("Failed to move file to 'other'", zap.String("from", path), zap.String("to", dest), zap.Error(err))
			return fmt.Errorf("failed to move file %s to %s: %w", path, dest, err)
		}

		log.Info("Moved unused asset file to 'other'", zap.String("from", path), zap.String("to", dest))
		return nil
	})
	if err != nil {
		log.Error("Error during asset organization", zap.Error(err))
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
func quote(s string) string {
	return fmt.Sprintf("%q", s)
}

// ValidateConfigPaths checks that the app’s Nginx source config files exist
func ValidateConfigPaths(app string) error {

	httpSrc := filepath.Join("assets/servers", app+".conf")

	if _, err := os.Stat(httpSrc); err != nil {
		if os.IsNotExist(err) {
			log.Error("❌ Required config file not found", zap.String("file", httpSrc))
			return fmt.Errorf("missing HTTP config: %s", httpSrc)
		}
		return fmt.Errorf("error checking config file: %w", err)
	}

	// Stream config is optional — no error if missing
	return nil
}
