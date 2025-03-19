// pkg/utils/utils.go
package utils

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"io"
	"io/ioutil"

	"gopkg.in/yaml.v2"
	"go.uber.org/zap"

	"eos/pkg/logger"
)

var log = logger.GetLogger() // Retrieve the globally initialized logger

//
//---------------------------- CONTAINER FUNCTIONS ---------------------------- //
//

// RemoveVolumes removes the specified Docker volumes.
// It accepts a projectName parameter to account for Docker Compose’s volume name prefix.
func RemoveVolumes(volumes []string, projectName string) error {
    for _, volume := range volumes {
        // Determine the actual volume name.
        // If the volume does not already start with the project name and an underscore, prepend it.
        actualVolume := volume
        if projectName != "" && !strings.HasPrefix(volume, projectName+"_") {
            actualVolume = projectName + "_" + volume
        }
        // Execute the docker volume rm command.
        if err := Execute("docker", "volume", "rm", actualVolume); err != nil {
            log.Warn("failed to remove volume", zap.String("volume", actualVolume), zap.Error(err))
        } else {
            log.Info("Volume removed successfully", zap.String("volume", actualVolume))
        }
    }
    return nil
}

// StopContainers stops the specified Docker containers.
func StopContainers(containers []string) error {
	// Build the arguments for "docker stop" command.
	args := append([]string{"stop"}, containers...)
	
	// Execute the command.
	if err := Execute("docker", args...); err != nil {
		return fmt.Errorf("failed to stop containers %v: %w", containers, err)
	}
	
	// Log the successful stopping of containers.
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

// BackupVolume backs up a single Docker volume by running a temporary Alpine container.
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
// It returns a map with volume names as keys and their backup file paths as values.
// If any backup fails, it logs the error but continues processing the remaining volumes.
func BackupVolumes(volumes []string, backupDir string) (map[string]string, error) {
	backupResults := make(map[string]string)

	// Ensure the backup directory exists.
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return backupResults, fmt.Errorf("failed to create backup directory %s: %w", backupDir, err)
	}

	// Loop through each volume and back it up.
	for _, vol := range volumes {
		log.Info("Backing up volume", zap.String("volume", vol))
		backupFile, err := BackupVolume(vol, backupDir)
		if err != nil {
			log.Error("Error backing up volume", zap.String("volume", vol), zap.Error(err))
			// Continue processing other volumes even if one fails.
		} else {
			log.Info("Volume backup completed", zap.String("volume", vol), zap.String("backupFile", backupFile))
			backupResults[vol] = backupFile
		}
	}
	return backupResults, nil
}

// ComposeFile represents the minimal structure of your docker-compose file.
type ComposeFile struct {
	Services map[string]Service `yaml:"services"`
	Volumes  map[string]interface{} `yaml:"volumes"`
}

// Service holds the details we care about for each service.
type Service struct {
	Image         string `yaml:"image"`
	ContainerName string `yaml:"container_name"`
}

// ParseComposeFile reads a docker-compose file and returns container names, images, and volumes.
func ParseComposeFile(composePath string) (containers []string, images []string, volumes []string, err error) {
	data, err := ioutil.ReadFile(composePath)
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
	desiredIPv4 := "172.28.0.0/22"
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
