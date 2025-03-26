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
	"gopkg.in/yaml.v2"

	"eos/pkg/config"
	"eos/pkg/logger"
)

var log = logger.L() // Retrieve the globally initialized logger

//
//---------------------------- CONTAINER FUNCTIONS ---------------------------- //
//

// RemoveVolumes removes the specified Docker volumes.
func RemoveVolumes(volumes []string) error {
	for _, volume := range volumes {
		// Execute the docker volume rm command.
		if err := Execute("docker", "volume", "rm", volume); err != nil {
			log.Warn("failed to remove volume", zap.String("volume", volume), zap.Error(err))
		} else {
			log.Info("Volume removed successfully", zap.String("volume", volume))
		}
	}
	return nil
}

// StopContainers stops the specified Docker containers.
func StopContainers(containers []string) error {
	// Build the arguments for "docker stop" command.
	args := append([]string{"stop"}, containers...)
	if err := Execute("docker", args...); err != nil {
		return fmt.Errorf("failed to stop containers %v: %w", containers, err)
	}
	log.Info("Containers stopped successfully", zap.Any("containers", containers))
	return nil
}

// RemoveContainers removes the specified Docker containers.
func RemoveContainers(containers []string) error {
	args := append([]string{"rm"}, containers...)
	if err := Execute("docker", args...); err != nil {
		return fmt.Errorf("failed to remove containers %v: %w", containers, err)
	}
	log.Info("Containers removed successfully", zap.Any("containers", containers))
	return nil
}

// RemoveImages removes the specified Docker images.
// It logs a warning if an image cannot be removed, but continues with the others.
func RemoveImages(images []string) error {
	for _, image := range images {
		if err := Execute("docker", "rmi", image); err != nil {
			log.Warn("failed to remove image (it might be used elsewhere)",
				zap.String("image", image), zap.Error(err))
		} else {
			log.Info("Image removed successfully", zap.String("image", image))
		}
	}
	return nil
}

// It returns the full path to the backup file.
func BackupVolume(volumeName, backupDir string) (string, error) {
	timestamp := time.Now().Format("20060102_150405")
	backupFile := fmt.Sprintf("%s_%s.tar.gz", timestamp, volumeName)
	cmd := []string{
		"run", "--rm",
		"-v", fmt.Sprintf("%s:/volume", volumeName),
		"-v", fmt.Sprintf("%s:/backup", backupDir),
		"alpine",
		"tar", "czf", fmt.Sprintf("/backup/%s", backupFile),
		"-C", "/volume", ".",
	}
	if err := Execute("docker", cmd...); err != nil {
		return "", fmt.Errorf("failed to backup volume %s: %w", volumeName, err)
	}
	return filepath.Join(backupDir, backupFile), nil
}

// BackupVolumes backs up all provided volumes to the specified backupDir.
func BackupVolumes(volumes []string, backupDir string) (map[string]string, error) {
	backupResults := make(map[string]string)

	// Ensure the backup directory exists.
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return backupResults, fmt.Errorf("failed to create backup directory %s: %w", backupDir, err)
	}

	for _, vol := range volumes {
		log.Info("Backing up volume", zap.String("volume", vol))
		backupFile, err := BackupVolume(vol, backupDir)
		if err != nil {
			log.Error("Error backing up volume", zap.String("volume", vol), zap.Error(err))
		} else {
			log.Info("Volume backup completed", zap.String("volume", vol), zap.String("backupFile", backupFile))
			backupResults[vol] = backupFile
		}
	}
	return backupResults, nil
}

// LogCommandExecution logs a command and its arguments using structured logging.
func LogCommandExecution(cmdName string, args []string) {
	logger.GetLogger().Info("Command executed", zap.String("command", cmdName), zap.Strings("args", args))
}

// ComposeFile represents the minimal structure of your docker-compose file.
type ComposeFile struct {
	Services map[string]Service     `yaml:"services"`
	Volumes  map[string]interface{} `yaml:"volumes"`
}

// Service holds the details we care about for each service.
type Service struct {
	Image         string `yaml:"image"`
	ContainerName string `yaml:"container_name"`
}

// ParseComposeFile reads a docker-compose file and returns container names, images, and volumes.
func ParseComposeFile(composePath string) (containers []string, images []string, volumes []string, err error) {
	data, err := os.ReadFile(composePath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read compose file: %w", err)
	}

	var compose ComposeFile
	if err := yaml.Unmarshal(data, &compose); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to unmarshal compose file: %w", err)
	}

	// Extract container names and images from services.
	for key, svc := range compose.Services {
		// If ContainerName is not provided, you can decide to use the service key
		if svc.ContainerName != "" {
			containers = append(containers, svc.ContainerName)
		} else {
			containers = append(containers, key)
		}
		if svc.Image != "" {
			images = append(images, svc.Image)
		}
	}

	// Extract volume names.
	for volName := range compose.Volumes {
		volumes = append(volumes, volName)
	}

	log.Info("Parsed compose file successfully", zap.String("path", composePath),
		zap.Any("containers", containers), zap.Any("images", images), zap.Any("volumes", volumes))

	return containers, images, volumes, nil
}

// EnsureArachneNetwork checks if the Docker network "arachne-net" exists.
// If it does not exist, it creates it with the desired IPv4 and IPv6 subnets.
func EnsureArachneNetwork() error {
	networkName := "arachne-net"
	desiredIPv4 := "10.1.0.0/16"
	desiredIPv6 := "fd42:1a2b:3c4d:5e6f::/64"

	// Check if the network exists by running: docker network inspect arachne-net
	cmd := exec.Command("docker", "network", "inspect", networkName)
	if err := cmd.Run(); err == nil {
		// Network exists, so just return
		return nil
	}

	// If the network does not exist, create it with the specified subnets.
	createCmd := exec.Command("docker", "network", "create",
		"--driver", "bridge",
		"--subnet", desiredIPv4,
		"--ipv6",
		"--subnet", desiredIPv6,
		networkName,
	)
	output, err := createCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to create network %s: %v, output: %s", networkName, err, output)
	}

	return nil
}

// CheckDockerContainers runs "docker ps" and logs its output.
// It returns an error if the command fails.
func CheckDockerContainers() error {
	cmd := exec.Command("docker", "ps")
	output, err := cmd.CombinedOutput()
	// Print output to terminal
	fmt.Println(string(output))
	if err != nil {
		return fmt.Errorf("failed to run docker ps: %v, output: %s", err, output)
	}
	log.Info("Docker ps output", zap.String("output", string(output)))
	return nil
}

//
//---------------------------- COMMAND EXECUTION ---------------------------- //
//

// Execute runs a command with separate arguments.
func Execute(command string, args ...string) error {
	log.Debug("Executing command", zap.String("command", command), zap.Strings("args", args))
	cmd := exec.Command(command, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		log.Error("Command execution failed", zap.String("command", command), zap.Strings("args", args), zap.Error(err))
	} else {
		log.Info("Command executed successfully", zap.String("command", command))
	}
	return err
}

// ExecuteShell runs a shell command with pipes (`| grep`).
func ExecuteShell(command string) error {
	log.Debug("Executing shell command", zap.String("command", command))
	cmd := exec.Command("bash", "-c", command) // Runs in shell mode
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	err := cmd.Run()
	if err != nil {
		log.Error("Shell command execution failed", zap.String("command", command), zap.Error(err))
	} else {
		log.Info("Shell command executed successfully", zap.String("command", command))
	}
	return err
}

func ExecuteInDir(dir, command string, args ...string) error {
	log.Debug("Executing command in directory", zap.String("directory", dir), zap.String("command", command), zap.Strings("args", args))
	cmd := exec.Command(command, args...)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		log.Error("Command execution failed in directory", zap.String("directory", dir), zap.String("command", command), zap.Strings("args", args), zap.Error(err))
	} else {
		log.Info("Command executed successfully in directory", zap.String("directory", dir), zap.String("command", command))
	}
	return err
}

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
