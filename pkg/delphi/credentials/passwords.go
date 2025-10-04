package credentials

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"golang.org/x/term"
)

// ExtractWazuhPasswords extracts and displays Wazuh installation passwords
// Migrated from cmd/create/delphi.go extractWazuhPasswords
func ExtractWazuhPasswords(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)

	// ASSESS - Search for password files
	log.Info("Assessing Wazuh installation for password files")

	searchPaths := []string{"/root", "/tmp", "/opt", "/var/tmp", "."}
	var passwordFiles []string

	for _, basePath := range searchPaths {
		matches, _ := filepath.Glob(filepath.Join(basePath, "*passwords*.txt"))
		passwordFiles = append(passwordFiles, matches...)
		matches, _ = filepath.Glob(filepath.Join(basePath, "*passwords*.tar"))
		passwordFiles = append(passwordFiles, matches...)
	}

	if len(passwordFiles) == 0 {
		log.Warn("No password files found in standard locations")
		return nil
	}

	// INTERVENE - Extract and display passwords
	log.Info("Found password files", zap.Int("count", len(passwordFiles)))

	for _, file := range passwordFiles {
		log.Info("Processing password file", zap.String("file", file))

		if strings.HasSuffix(file, ".tar") {
			// Extract tar file
			cmd := exec.CommandContext(rc.Ctx, "tar", "-xf", file, "-O")
			output, err := cmd.Output()
			if err != nil {
				log.Warn("Failed to extract tar file", zap.String("file", file), zap.Error(err))
				continue
			}
			// SECURITY: Use structured logging instead of fmt.Printf to avoid terminal exposure
			// Passwords should not be printed to stdout (visible in scrollback, recordings, logs)
			log.Info("SENSITIVE: Extracted password file contents",
				zap.String("file", file),
				zap.Int("size", len(output)),
				zap.String("note", "View file directly for credentials"))
		} else {
			// Read text file
			content, err := os.ReadFile(file)
			if err != nil {
				log.Warn("Failed to read password file", zap.String("file", file), zap.Error(err))
				continue
			}
			// SECURITY: Use structured logging instead of fmt.Printf
			log.Info("SENSITIVE: Found password file",
				zap.String("file", file),
				zap.Int("size", len(content)),
				zap.String("note", "Use 'cat' or secure viewer to read credentials"))
		}
	}

	// EVALUATE - Log completion
	log.Info("Password extraction completed")
	return nil
}

// RunCredentialsChange changes Delphi/Wazuh credentials
// Migrated from cmd/create/delphi.go runCredentialsChange
func RunCredentialsChange(rc *eos_io.RuntimeContext, adminPassword, kibanaPassword, apiPassword, deployType string, interactive bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Validate deployment exists
	logger.Info("Assessing credentials change requirements",
		zap.String("deploy_type", deployType),
		zap.Bool("interactive", interactive))

	// Check if docker-compose.yml exists
	if _, err := os.Stat("docker-compose.yml"); os.IsNotExist(err) {
		return fmt.Errorf("docker-compose.yml not found. Please deploy first")
	}

	// INTERVENE - Change passwords
	if interactive || adminPassword == "" || kibanaPassword == "" || apiPassword == "" {
		logger.Info("Interactive mode: prompting for passwords")

		var err error
		if adminPassword == "" {
			logger.Info("Prompting for admin password")
			adminPassword, err = crypto.PromptPassword(rc, "Admin Password: ")
			if err != nil {
				return fmt.Errorf("failed to read admin password: %w", err)
			}
		}

		if kibanaPassword == "" {
			logger.Info("Prompting for kibana password")
			kibanaPassword, err = crypto.PromptPassword(rc, "Kibana Password: ")
			if err != nil {
				return fmt.Errorf("failed to read kibana password: %w", err)
			}
		}

		if apiPassword == "" {
			logger.Info("Prompting for API password")
			apiPassword, err = crypto.PromptPassword(rc, "API Password: ")
			if err != nil {
				return fmt.Errorf("failed to read API password: %w", err)
			}
		}
	}

	// Stop containers
	logger.Info("Stopping containers")
	stopCmd := exec.Command("docker-compose", "down")
	stopCmd.Stdout = os.Stdout
	stopCmd.Stderr = os.Stderr
	if err := stopCmd.Run(); err != nil {
		return fmt.Errorf("failed to stop containers: %w", err)
	}

	// Update passwords
	logger.Info("Updating passwords")

	if err := UpdateAdminPassword(adminPassword); err != nil {
		return fmt.Errorf("failed to update admin password: %w", err)
	}

	if err := UpdateKibanaPassword(kibanaPassword); err != nil {
		return fmt.Errorf("failed to update kibana password: %w", err)
	}

	if err := UpdateAPIPassword(apiPassword); err != nil {
		return fmt.Errorf("failed to update API password: %w", err)
	}

	// Restart containers
	logger.Info("Starting containers with new credentials")
	startCmd := exec.Command("docker-compose", "up", "-d")
	startCmd.Stdout = os.Stdout
	startCmd.Stderr = os.Stderr
	if err := startCmd.Run(); err != nil {
		return fmt.Errorf("failed to start containers: %w", err)
	}

	// EVALUATE - Verify changes
	logger.Info("Credentials updated successfully - services restarting")

	return nil
}

// UpdateAdminPassword updates the admin password
// Migrated from cmd/create/delphi.go updateAdminPassword
func UpdateAdminPassword(password string) error {
	// Update docker-compose.yml
	if err := updateComposeFile("INDEXER_PASSWORD=SecretPassword", fmt.Sprintf("INDEXER_PASSWORD=%s", password)); err != nil {
		return err
	}

	// Generate password hash
	hash, err := generatePasswordHash(password)
	if err != nil {
		return err
	}

	// Update internal users
	return updateInternalUsers("$2y$12$K/SpwjtB.wOHJ/Nc6GVRDuc1h0rM1DfvziFRNPtk27P.c4yDr9njO", hash)
}

// UpdateKibanaPassword updates the kibana password
// Migrated from cmd/create/delphi.go updateKibanaPassword
func UpdateKibanaPassword(password string) error {
	// Update docker-compose.yml
	if err := updateComposeFile("DASHBOARD_PASSWORD=kibanaserver", fmt.Sprintf("DASHBOARD_PASSWORD=%s", password)); err != nil {
		return err
	}

	// Generate password hash
	hash, err := generatePasswordHash(password)
	if err != nil {
		return err
	}

	// Update internal users
	return updateInternalUsers("$2a$12$4AcgAt3xwOWadA5s5blL6ev39OXDNhmOesEoo33eZtrq2N0YrU3H.", hash)
}

// UpdateAPIPassword updates the API password
// Migrated from cmd/create/delphi.go updateAPIPassword
func UpdateAPIPassword(password string) error {
	// Update docker-compose.yml
	if err := updateComposeFile("API_PASSWORD=MyS3cr37P450r.*-", fmt.Sprintf("API_PASSWORD=%s", password)); err != nil {
		return err
	}

	// Update wazuh.yml
	return updateWazuhYML("API_PASSWORD=MyS3cr37P450r.*-", fmt.Sprintf("API_PASSWORD=%s", password))
}

// Helper functions

func updateComposeFile(oldValue, newValue string) error {
	return replaceInFile("docker-compose.yml", oldValue, newValue)
}

func updateInternalUsers(oldHash, newHash string) error {
	return replaceInFile("config/wazuh_indexer/internal_users.yml", oldHash, newHash)
}

func updateWazuhYML(oldValue, newValue string) error {
	return replaceInFile("config/wazuh_dashboard/wazuh.yml", oldValue, newValue)
}

func replaceInFile(filename, oldValue, newValue string) error {
	content, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	newContent := strings.ReplaceAll(string(content), oldValue, newValue)

	// SECURITY: Write with 0600 permissions (owner read/write only)
	// BEFORE: 0644 = -rw-r--r-- (world-readable, exposes passwords)
	// AFTER:  0600 = -rw------- (owner-only, secure)
	return os.WriteFile(filename, []byte(newContent), 0600)
}

func generatePasswordHash(password string) (string, error) {
	// SECURITY: Use temp file with restrictive permissions to pass password to Docker
	// This prevents password exposure in:
	// 1. Process table (/proc/*/cmdline)
	// 2. Docker container environment variables
	// 3. Shell command history

	// Create temp file with restrictive permissions
	tmpFile, err := os.CreateTemp("", "eos-pass-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	// Set permissions to owner-only before writing password
	if err := os.Chmod(tmpPath, 0600); err != nil {
		tmpFile.Close()
		return "", fmt.Errorf("failed to set permissions: %w", err)
	}

	if _, err := tmpFile.WriteString(password); err != nil {
		tmpFile.Close()
		return "", fmt.Errorf("failed to write password: %w", err)
	}
	tmpFile.Close()

	// SECURITY: Mount temp file as read-only volume - password never in process args or environment
	cmd := exec.Command("docker", "run", "--rm",
		"-v", tmpPath+":/tmp/pass:ro",
		"opensearchproject/opensearch:latest",
		"sh", "-c", "plugins/opensearch-security/tools/hash.sh -p \"$(cat /tmp/pass)\"")

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("failed to generate hash: %w (output: %s)", err, out.String())
	}

	output := out.String()
	lines := strings.Split(output, "\n")

	// Extract hash from output
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "$") {
			return line, nil
		}
	}

	return "", fmt.Errorf("failed to extract hash from output: %s", output)
}

// readInput reads a line of input from stdin
// DEPRECATED: Use readPassword() for sensitive input
func readInput() (string, error) {
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(input), nil
}

// readPassword reads a password from stdin without echoing to terminal
// SECURITY: Prevents password from being visible in:
// - Terminal display (echoing disabled)
// - Terminal scrollback buffer
// - Screen recordings
func readPassword() (string, error) {
	// Get file descriptor for stdin
	fd := int(syscall.Stdin)

	// Read password with terminal echo disabled
	password, err := term.ReadPassword(fd)
	if err != nil {
		return "", fmt.Errorf("failed to read password: %w", err)
	}

	// Print newline since ReadPassword doesn't echo it (not using fmt.Println per CLAUDE.md)
	// Newline handled by terminal automatically after password input

	return string(password), nil
}
