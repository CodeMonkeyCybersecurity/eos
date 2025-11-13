package ssh

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/telemetry"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// SSHCredentials represents SSH connection parameters
type SSHCredentials struct {
	User    string
	Host    string
	Port    string
	KeyPath string
}

// ParseSSHPath extracts username, host, and optional port from SSH path
func ParseSSHPath(sshPath string) (*SSHCredentials, error) {
	// Remove any quotes
	sshPath = strings.Trim(sshPath, "'\"")

	// Default SSH port
	port := "22"

	// Check for port specification (user@host:port)
	if strings.Contains(sshPath, ":") && strings.Count(sshPath, ":") == 2 {
		parts := strings.Split(sshPath, ":")
		if len(parts) == 3 {
			sshPath = parts[0] + "@" + parts[1]
			port = parts[2]
		}
	}

	// Split user@host
	if !strings.Contains(sshPath, "@") {
		return nil, fmt.Errorf("invalid SSH path format, expected user@host")
	}

	parts := strings.Split(sshPath, "@")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid SSH path format, expected user@host")
	}

	user := strings.TrimSpace(parts[0])
	host := strings.TrimSpace(parts[1])

	if user == "" || host == "" {
		return nil, fmt.Errorf("empty user or host in SSH path")
	}

	return &SSHCredentials{
		User: user,
		Host: host,
		Port: port,
	}, nil
}

// CheckSSHCredentials validates SSH credentials by attempting a connection
func CheckSSHCredentials(rc *eos_io.RuntimeContext, creds *SSHCredentials) error {
	ctx, span := telemetry.Start(rc.Ctx, "ssh.CheckSSHCredentials")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Checking SSH credentials",
		zap.String("user", creds.User),
		zap.String("host", creds.Host),
		zap.String("port", creds.Port))

	// Build SSH command
	args := []string{
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=5",
		"-o", "StrictHostKeyChecking=no",
		"-p", creds.Port,
	}

	if creds.KeyPath != "" {
		args = append(args, "-i", creds.KeyPath)
	}

	target := fmt.Sprintf("%s@%s", creds.User, creds.Host)
	args = append(args, target, "exit")

	cmd := exec.CommandContext(ctx, "ssh", args...)

	logger.Debug("Executing SSH test command", zap.Strings("args", args))

	if err := cmd.Run(); err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			if exitError.ExitCode() != 0 {
				logger.Error("SSH connection failed", zap.Error(err), zap.Int("exit_code", exitError.ExitCode()))
				return fmt.Errorf("SSH connection failed to %s: %w", target, err)
			}
		}
		logger.Error("SSH command execution failed", zap.Error(err))
		return fmt.Errorf("SSH command failed: %w", err)
	}

	logger.Info("SSH credentials validated successfully")
	return nil
}

// CheckSSHKeyPermissions verifies and fixes SSH key file permissions
func CheckSSHKeyPermissions(rc *eos_io.RuntimeContext, keyPath string) error {
	ctx, span := telemetry.Start(rc.Ctx, "ssh.CheckSSHKeyPermissions")
	defer span.End()

	logger := otelzap.Ctx(ctx)

	// Check if file exists
	info, err := os.Stat(keyPath)
	if err != nil {
		logger.Error("SSH key file not found", zap.Error(err))
		return fmt.Errorf("SSH key file not found: %w", err)
	}

	// Get current permissions
	mode := info.Mode()
	perms := mode.Perm()

	logger.Info("Checking SSH key permissions",
		zap.String("key_path", keyPath),
		zap.String("current_perms", fmt.Sprintf("%o", perms)),
		zap.String("expected_perms", "600"))

	// Check if permissions are correct (600)
	expectedPerms := shared.SecretFilePerm
	if perms != expectedPerms {
		logger.Warn("SSH key permissions are incorrect, fixing",
			zap.String("current", fmt.Sprintf("%o", perms)),
			zap.String("expected", fmt.Sprintf("%o", expectedPerms)))

		if err := os.Chmod(keyPath, expectedPerms); err != nil {
			logger.Error("Failed to fix SSH key permissions", zap.Error(err))
			return fmt.Errorf("failed to fix SSH key permissions: %w", err)
		}

		logger.Info("SSH key permissions corrected")
	} else {
		logger.Info("SSH key permissions are correct")
	}

	return nil
}

// ListSSHKeys finds available SSH keys in the user's .ssh directory
func ListSSHKeys(rc *eos_io.RuntimeContext) ([]string, error) {
	ctx, span := telemetry.Start(rc.Ctx, "ssh.ListSSHKeys")
	defer span.End()

	homeDir, err := os.UserHomeDir()
	if err != nil {
		otelzap.Ctx(ctx).Error("Failed to get user home directory", zap.Error(err))
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}

	sshDir := filepath.Join(homeDir, ".ssh")

	// Find all .pub files and return their corresponding private keys
	pubFiles, err := filepath.Glob(filepath.Join(sshDir, "*.pub"))
	if err != nil {
		otelzap.Ctx(ctx).Error("Failed to list SSH public keys", zap.Error(err))
		return nil, fmt.Errorf("failed to list SSH keys: %w", err)
	}

	var privateKeys []string
	for _, pubFile := range pubFiles {
		// Remove .pub extension to get private key path
		privateKey := strings.TrimSuffix(pubFile, ".pub")

		// Check if private key exists
		if _, err := os.Stat(privateKey); err == nil {
			privateKeys = append(privateKeys, privateKey)
		}
	}

	otelzap.Ctx(ctx).Info("Found SSH keys", zap.Int("count", len(privateKeys)), zap.Strings("keys", privateKeys))

	return privateKeys, nil
}

// SelectSSHKey prompts user to select an SSH key from available keys
func SelectSSHKey(rc *eos_io.RuntimeContext) (string, error) {
	ctx, span := telemetry.Start(rc.Ctx, "ssh.SelectSSHKey")
	defer span.End()

	keys, err := ListSSHKeys(rc)
	if err != nil {
		return "", err
	}

	if len(keys) == 0 {
		otelzap.Ctx(ctx).Error("No SSH keys found")
		return "", eos_err.NewExpectedError(ctx, fmt.Errorf("no SSH keys found in ~/.ssh/, please generate or add an SSH key"))
	}

	if len(keys) == 1 {
		otelzap.Ctx(ctx).Info("Using only available SSH key", zap.String("key", keys[0]))
		return keys[0], nil
	}

	// Display available keys
	otelzap.Ctx(ctx).Info("Available SSH keys:")
	for i, key := range keys {
		otelzap.Ctx(ctx).Info(fmt.Sprintf("%d. %s", i+1, key))
	}

	// Prompt for selection
	choice, err := interaction.PromptUser(rc, "Select an SSH key by number: ")
	if err != nil {
		return "", fmt.Errorf("failed to get user input: %w", err)
	}

	// Parse choice
	choiceNum, err := strconv.Atoi(strings.TrimSpace(choice))
	if err != nil || choiceNum < 1 || choiceNum > len(keys) {
		otelzap.Ctx(ctx).Error("Invalid choice", zap.String("input", choice))
		return "", eos_err.NewExpectedError(ctx, fmt.Errorf("invalid choice, please enter a number between 1 and %d", len(keys)))
	}

	selectedKey := keys[choiceNum-1]
	otelzap.Ctx(ctx).Info("Selected SSH key", zap.String("key", selectedKey))

	return selectedKey, nil
}

// CheckSSHService verifies if SSH service is running on remote host
func CheckSSHService(rc *eos_io.RuntimeContext, creds *SSHCredentials) error {
	ctx, span := telemetry.Start(rc.Ctx, "ssh.CheckSSHService")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Checking SSH service status on remote host",
		zap.String("user", creds.User),
		zap.String("host", creds.Host),
		zap.String("port", creds.Port))

	// Build SSH command to check service status
	args := []string{
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=5",
		"-o", "StrictHostKeyChecking=no",
		"-p", creds.Port,
	}

	if creds.KeyPath != "" {
		args = append(args, "-i", creds.KeyPath)
	}

	target := fmt.Sprintf("%s@%s", creds.User, creds.Host)
	args = append(args, target, "systemctl is-active ssh || systemctl is-active sshd")

	cmd := exec.CommandContext(ctx, "ssh", args...)

	if err := cmd.Run(); err != nil {
		logger.Error("SSH service check failed", zap.Error(err))
		return fmt.Errorf("SSH service is not running on %s or permission denied: %w", creds.Host, err)
	}

	logger.Info("SSH service is running on remote host")
	return nil
}

// TroubleshootSSH performs comprehensive SSH connectivity troubleshooting
func TroubleshootSSH(rc *eos_io.RuntimeContext, sshPath string, keyPath string) error {
	ctx, span := telemetry.Start(rc.Ctx, "ssh.TroubleshootSSH")
	defer span.End()

	otelzap.Ctx(ctx).Info("Starting SSH troubleshooting", zap.String("ssh_path", sshPath))

	// Parse SSH path
	creds, err := ParseSSHPath(sshPath)
	if err != nil {
		otelzap.Ctx(ctx).Error("Failed to parse SSH path", zap.Error(err))
		return eos_err.NewExpectedError(ctx, fmt.Errorf("invalid SSH path format: %v", err))
	}

	// Select SSH key if not provided
	if keyPath == "" {
		keyPath, err = SelectSSHKey(rc)
		if err != nil {
			return err
		}
	}

	creds.KeyPath = keyPath

	// Check SSH key permissions
	otelzap.Ctx(ctx).Info("Step 1: Checking SSH key permissions")
	if err := CheckSSHKeyPermissions(rc, keyPath); err != nil {
		return err
	}

	// Check basic connectivity
	otelzap.Ctx(ctx).Info("Step 2: Testing network connectivity")
	if err := checkNetworkConnectivity(rc, creds); err != nil {
		return err
	}

	// Check SSH connection
	otelzap.Ctx(ctx).Info("Step 3: Testing SSH connection")
	if err := CheckSSHCredentials(rc, creds); err != nil {
		return err
	}

	// Check SSH service status
	otelzap.Ctx(ctx).Info("Step 4: Checking SSH service status")
	if err := CheckSSHService(rc, creds); err != nil {
		// This is non-fatal, log as warning
		otelzap.Ctx(ctx).Warn("SSH service check failed", zap.Error(err))
	}

	otelzap.Ctx(ctx).Info("SSH troubleshooting completed successfully")
	return nil
}

// checkNetworkConnectivity tests basic network connectivity to the host
func checkNetworkConnectivity(rc *eos_io.RuntimeContext, creds *SSHCredentials) error {
	ctx, span := telemetry.Start(rc.Ctx, "ssh.checkNetworkConnectivity")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Testing network connectivity",
		zap.String("host", creds.Host),
		zap.String("port", creds.Port))

	timeout := 5 * time.Second
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(creds.Host, creds.Port), timeout)
	if err != nil {
		logger.Error("Network connectivity failed", zap.Error(err))
		return fmt.Errorf("cannot connect to %s:%s - %w", creds.Host, creds.Port, err)
	}

	_ = conn.Close()
	logger.Info("Network connectivity successful")
	return nil
}

// DisableRootLogin disables SSH root login by modifying SSH configuration
func DisableRootLogin(rc *eos_io.RuntimeContext) error {
	ctx, span := telemetry.Start(rc.Ctx, "ssh.DisableRootLogin")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Starting SSH root login disable process")

	const sshConfigFile = "/etc/ssh/sshd_config"

	// Check if running as root
	if os.Geteuid() != 0 {
		logger.Error("Root privileges required")
		return eos_err.NewExpectedError(ctx, fmt.Errorf("this operation requires root privileges. Try using sudo"))
	}

	// Create backup of SSH config
	if err := backupSSHConfig(rc, sshConfigFile); err != nil {
		return err
	}

	// Modify SSH configuration
	if err := modifySSHConfig(rc, sshConfigFile); err != nil {
		return err
	}

	// Restart SSH service
	if err := restartSSHService(rc); err != nil {
		return err
	}

	logger.Info("SSH root login disabled successfully")
	return nil
}

// backupSSHConfig creates a backup of the SSH configuration file
func backupSSHConfig(rc *eos_io.RuntimeContext, configFile string) error {
	ctx, span := telemetry.Start(rc.Ctx, "ssh.backupSSHConfig")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	backupFile := configFile + ".bak"

	logger.Info("Creating backup of SSH configuration",
		zap.String("source", configFile),
		zap.String("backup", backupFile))

	// Read original config
	sourceFile, err := os.Open(configFile)
	if err != nil {
		logger.Error("Failed to open SSH config file", zap.Error(err))
		return fmt.Errorf("failed to open SSH config file: %w", err)
	}
	defer func() {
		if closeErr := sourceFile.Close(); closeErr != nil {
			logger.Warn("Failed to close source file", zap.Error(closeErr))
		}
	}()

	// Create backup file
	backupFileHandle, err := os.Create(backupFile)
	if err != nil {
		logger.Error("Failed to create backup file", zap.Error(err))
		return fmt.Errorf("failed to create backup file: %w", err)
	}
	defer func() {
		if closeErr := backupFileHandle.Close(); closeErr != nil {
			logger.Warn("Failed to close backup file", zap.Error(closeErr))
		}
	}()

	// Copy contents
	if _, err := io.Copy(backupFileHandle, sourceFile); err != nil {
		logger.Error("Failed to copy config to backup", zap.Error(err))
		return fmt.Errorf("failed to copy config to backup: %w", err)
	}

	logger.Info("SSH configuration backup created successfully")
	return nil
}

// modifySSHConfig modifies the SSH configuration to disable root login
func modifySSHConfig(rc *eos_io.RuntimeContext, configFile string) error {
	ctx, span := telemetry.Start(rc.Ctx, "ssh.modifySSHConfig")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Modifying SSH configuration to disable root login")

	// Read current config
	file, err := os.Open(configFile)
	if err != nil {
		logger.Error("Failed to read SSH config file", zap.Error(err))
		return fmt.Errorf("failed to read SSH config file: %w", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			logger.Warn("Failed to close config file", zap.Error(closeErr))
		}
	}()

	var modifiedLines []string
	found := false
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		stripped := strings.TrimSpace(line)

		// Check for PermitRootLogin setting (commented or uncommented)
		if strings.HasPrefix(stripped, "PermitRootLogin") || strings.HasPrefix(stripped, "#PermitRootLogin") {
			modifiedLines = append(modifiedLines, "PermitRootLogin no")
			found = true
			logger.Debug("Replaced PermitRootLogin line", zap.String("original", line))
		} else {
			modifiedLines = append(modifiedLines, line)
		}
	}

	if err := scanner.Err(); err != nil {
		logger.Error("Error reading SSH config file", zap.Error(err))
		return fmt.Errorf("error reading SSH config file: %w", err)
	}

	// If no PermitRootLogin line was found, add one
	if !found {
		modifiedLines = append(modifiedLines, "", "PermitRootLogin no")
		logger.Debug("Added new PermitRootLogin line")
	}

	// Write modified config
	outputFile, err := os.Create(configFile)
	if err != nil {
		logger.Error("Failed to open SSH config file for writing", zap.Error(err))
		return fmt.Errorf("failed to open SSH config file for writing: %w", err)
	}
	defer func() {
		if closeErr := outputFile.Close(); closeErr != nil {
			logger.Warn("Failed to close output file", zap.Error(closeErr))
		}
	}()

	writer := bufio.NewWriter(outputFile)
	for _, line := range modifiedLines {
		if _, err := writer.WriteString(line + "\n"); err != nil {
			logger.Error("Failed to write SSH config line", zap.Error(err))
			return fmt.Errorf("failed to write SSH config: %w", err)
		}
	}

	if err := writer.Flush(); err != nil {
		logger.Error("Failed to flush SSH config changes", zap.Error(err))
		return fmt.Errorf("failed to flush SSH config changes: %w", err)
	}

	logger.Info("SSH configuration updated successfully")
	return nil
}

// restartSSHService restarts the SSH service using multiple fallback methods
func restartSSHService(rc *eos_io.RuntimeContext) error {
	ctx, span := telemetry.Start(rc.Ctx, "ssh.restartSSHService")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Restarting SSH service")

	// Try multiple restart commands in order of preference
	commands := [][]string{
		{"systemctl", "restart", "sshd"},
		{"systemctl", "restart", "ssh"},
		{"service", "sshd", "restart"},
		{"service", "ssh", "restart"},
	}

	for _, cmdArgs := range commands {
		logger.Debug("Attempting SSH restart command", zap.Strings("command", cmdArgs))

		cmd := exec.CommandContext(ctx, cmdArgs[0], cmdArgs[1:]...)
		if err := cmd.Run(); err != nil {
			logger.Warn("SSH restart command failed",
				zap.Strings("command", cmdArgs),
				zap.Error(err))
			continue
		}

		logger.Info("SSH service restarted successfully", zap.Strings("command", cmdArgs))
		return nil
	}

	logger.Error("Failed to restart SSH service with all attempted methods")
	return eos_err.NewExpectedError(ctx, fmt.Errorf("could not restart SSH service automatically. Please restart it manually with 'sudo systemctl restart sshd' or 'sudo service ssh restart'"))
}

// CopySSHKeys copies SSH keys to multiple remote hosts
func CopySSHKeys(rc *eos_io.RuntimeContext, hosts []string, username string) error {
	ctx, span := telemetry.Start(rc.Ctx, "ssh.CopySSHKeys")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Starting SSH key distribution",
		zap.Strings("hosts", hosts),
		zap.String("username", username))

	if len(hosts) == 0 {
		logger.Error("No hosts specified for SSH key distribution")
		return eos_err.NewExpectedError(ctx, fmt.Errorf("no hosts specified for SSH key distribution"))
	}

	if username == "" {
		logger.Error("No username specified for SSH key distribution")
		return eos_err.NewExpectedError(ctx, fmt.Errorf("username is required for SSH key distribution"))
	}

	var successCount, failureCount int

	for _, host := range hosts {
		if err := copySSHKeyToHost(rc, host, username); err != nil {
			logger.Error("Failed to copy SSH key to host",
				zap.String("host", host),
				zap.Error(err))
			failureCount++
		} else {
			logger.Info("Successfully copied SSH key to host", zap.String("host", host))
			successCount++
		}
	}

	logger.Info("SSH key distribution completed",
		zap.Int("success_count", successCount),
		zap.Int("failure_count", failureCount))

	if failureCount > 0 {
		return eos_err.NewExpectedError(ctx, fmt.Errorf("failed to copy SSH key to %d out of %d hosts", failureCount, len(hosts)))
	}

	return nil
}

// copySSHKeyToHost copies SSH public key to a single host using ssh-copy-id
func copySSHKeyToHost(rc *eos_io.RuntimeContext, host, username string) error {
	ctx, span := telemetry.Start(rc.Ctx, "ssh.copySSHKeyToHost")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	target := fmt.Sprintf("%s@%s", username, host)

	logger.Info("Copying SSH key to host",
		zap.String("target", target))

	// Use ssh-copy-id to copy the SSH key
	cmd := exec.CommandContext(ctx, "ssh-copy-id", target)

	// Capture both stdout and stderr
	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Error("ssh-copy-id failed",
			zap.String("target", target),
			zap.ByteString("output", output),
			zap.Error(err))
		return fmt.Errorf("failed to copy SSH key to %s: %w", target, err)
	}

	logger.Debug("ssh-copy-id output",
		zap.String("target", target),
		zap.ByteString("output", output))

	return nil
}

// DistributeSSHKeysToTailscale distributes SSH keys to Tailscale network peers
func DistributeSSHKeysToTailscale(rc *eos_io.RuntimeContext, selectedHosts []string) error {
	ctx, span := telemetry.Start(rc.Ctx, "ssh.DistributeSSHKeysToTailscale")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Starting SSH key distribution to Tailscale peers",
		zap.Strings("selected_hosts", selectedHosts))

	// Check if Tailscale is running
	if err := checkTailscaleStatus(rc); err != nil {
		return err
	}

	// Get SSH public key
	publicKey, err := getSSHPublicKey(rc)
	if err != nil {
		return err
	}

	// Distribute key to selected hosts
	var successCount, failureCount int
	for _, host := range selectedHosts {
		if err := distributeKeyToTailscaleHost(rc, host, publicKey); err != nil {
			logger.Error("Failed to distribute SSH key to Tailscale host",
				zap.String("host", host),
				zap.Error(err))
			failureCount++
		} else {
			logger.Info("Successfully distributed SSH key to Tailscale host", zap.String("host", host))
			successCount++
		}
	}

	logger.Info("SSH key distribution to Tailscale peers completed",
		zap.Int("success_count", successCount),
		zap.Int("failure_count", failureCount))

	if failureCount > 0 {
		return eos_err.NewExpectedError(ctx, fmt.Errorf("failed to distribute SSH key to %d out of %d Tailscale hosts", failureCount, len(selectedHosts)))
	}

	return nil
}

// checkTailscaleStatus verifies that Tailscale is running and connected
func checkTailscaleStatus(rc *eos_io.RuntimeContext) error {
	ctx, span := telemetry.Start(rc.Ctx, "ssh.checkTailscaleStatus")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Checking Tailscale status")

	cmd := exec.CommandContext(ctx, "tailscale", "status")
	if err := cmd.Run(); err != nil {
		logger.Error("Tailscale is not running or not connected", zap.Error(err))
		return eos_err.NewExpectedError(ctx, fmt.Errorf("tailscale is not running or machine is not part of a Tailscale network. Install and configure Tailscale first"))
	}

	logger.Info("Tailscale is running and connected")
	return nil
}

// getSSHPublicKey reads the SSH public key from the default location
func getSSHPublicKey(rc *eos_io.RuntimeContext) (string, error) {
	ctx, span := telemetry.Start(rc.Ctx, "ssh.getSSHPublicKey")
	defer span.End()

	logger := otelzap.Ctx(ctx)

	homeDir, err := os.UserHomeDir()
	if err != nil {
		logger.Error("Failed to get user home directory", zap.Error(err))
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}

	keyPaths := []string{
		filepath.Join(homeDir, ".ssh", "id_rsa.pub"),
		filepath.Join(homeDir, ".ssh", "id_ed25519.pub"),
		filepath.Join(homeDir, ".ssh", "id_ecdsa.pub"),
	}

	for _, keyPath := range keyPaths {
		if _, err := os.Stat(keyPath); err == nil {
			keyData, err := os.ReadFile(keyPath)
			if err != nil {
				logger.Warn("Failed to read SSH public key", zap.String("path", keyPath), zap.Error(err))
				continue
			}

			logger.Info("Found SSH public key", zap.String("path", keyPath))
			return strings.TrimSpace(string(keyData)), nil
		}
	}

	logger.Error("No SSH public key found")
	return "", eos_err.NewExpectedError(ctx, fmt.Errorf("no SSH public key found in ~/.ssh/. Generate one with 'ssh-keygen -t rsa' or 'ssh-keygen -t ed25519'"))
}

// distributeKeyToTailscaleHost distributes SSH key to a specific Tailscale host
func distributeKeyToTailscaleHost(rc *eos_io.RuntimeContext, host, publicKey string) error {
	ctx, span := telemetry.Start(rc.Ctx, "ssh.distributeKeyToTailscaleHost")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Distributing SSH key to Tailscale host", zap.String("host", host))

	// SSH command to set up the key on the remote host
	sshCmd := fmt.Sprintf("mkdir -p ~/.ssh && echo '%s' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && chmod 700 ~/.ssh", publicKey)

	cmd := exec.CommandContext(ctx, "ssh", fmt.Sprintf("root@%s", host), sshCmd)

	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Error("Failed to distribute SSH key",
			zap.String("host", host),
			zap.ByteString("output", output),
			zap.Error(err))
		return fmt.Errorf("failed to distribute SSH key to %s: %w", host, err)
	}

	logger.Debug("SSH key distribution output",
		zap.String("host", host),
		zap.ByteString("output", output))

	return nil
}

// GetTailscalePeers retrieves list of Tailscale network peers
func GetTailscalePeers(rc *eos_io.RuntimeContext) ([]string, error) {
	ctx, span := telemetry.Start(rc.Ctx, "ssh.GetTailscalePeers")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Fetching Tailscale network peers")

	// Check if Tailscale is running
	if err := checkTailscaleStatus(rc); err != nil {
		return nil, err
	}

	// Get current hostname to exclude self
	currentHostname, err := os.Hostname()
	if err != nil {
		logger.Warn("Failed to get current hostname", zap.Error(err))
		currentHostname = ""
	}

	// Get Tailscale status in JSON format
	cmd := exec.CommandContext(ctx, "tailscale", "status", "--json")
	output, err := cmd.Output()
	if err != nil {
		logger.Error("Failed to get Tailscale status", zap.Error(err))
		return nil, fmt.Errorf("failed to get Tailscale status: %w", err)
	}

	// Parse JSON to extract peer information
	var tailscaleStatus struct {
		Peer map[string]struct {
			HostName string `json:"HostName"`
			TailAddr string `json:"TailAddr"`
		} `json:"Peer"`
	}

	if err := json.Unmarshal(output, &tailscaleStatus); err != nil {
		logger.Error("Failed to parse Tailscale status JSON", zap.Error(err))
		return nil, fmt.Errorf("failed to parse Tailscale status: %w", err)
	}

	var peers []string
	for _, peer := range tailscaleStatus.Peer {
		// Skip current machine
		if peer.HostName != currentHostname {
			peerInfo := fmt.Sprintf("%s (%s)", peer.HostName, peer.TailAddr)
			peers = append(peers, peerInfo)
		}
	}

	logger.Info("Found Tailscale peers",
		zap.Int("count", len(peers)),
		zap.Strings("peers", peers))

	if len(peers) == 0 {
		return nil, eos_err.NewExpectedError(ctx, fmt.Errorf("no other machines found in the Tailscale network"))
	}

	return peers, nil
}

// SSHDiagnosticResult represents the result of a single diagnostic check
type SSHDiagnosticResult struct {
	Name    string // Name of the check
	Status  string // "pass", "fail", "warn", "skip"
	Message string // Detailed message
	Details string // Additional details or output
}

// SSHDiagnosticReport contains all diagnostic results
type SSHDiagnosticReport struct {
	ClientResults []SSHDiagnosticResult
	ServerResults []SSHDiagnosticResult
	Timestamp     time.Time
	TargetHost    string // Empty for client-only diagnostics
}

// CheckClientSSHKeys checks if ED25519 SSH keys exist
func CheckClientSSHKeys(rc *eos_io.RuntimeContext) SSHDiagnosticResult {
	ctx, span := telemetry.Start(rc.Ctx, "ssh.CheckClientSSHKeys")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Debug("Checking client SSH keys")

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return SSHDiagnosticResult{
			Name:    "SSH Key Existence",
			Status:  "fail",
			Message: "Failed to get user home directory",
			Details: err.Error(),
		}
	}

	sshDir := filepath.Join(homeDir, ".ssh")
	keyPatterns := []string{
		filepath.Join(sshDir, "id_ed25519"),
		filepath.Join(sshDir, "id_rsa"),
		filepath.Join(sshDir, "id_ecdsa"),
	}

	var foundKeys []string
	var keyDetails strings.Builder

	for _, keyPath := range keyPatterns {
		if info, err := os.Stat(keyPath); err == nil {
			foundKeys = append(foundKeys, keyPath)
			pubKeyPath := keyPath + ".pub"
			keyDetails.WriteString(fmt.Sprintf("%s: %s (%o)\n", filepath.Base(keyPath), keyPath, info.Mode().Perm()))

			if pubInfo, pubErr := os.Stat(pubKeyPath); pubErr == nil {
				keyDetails.WriteString(fmt.Sprintf("%s.pub: %s (%o)\n", filepath.Base(keyPath), pubKeyPath, pubInfo.Mode().Perm()))
			}
		}
	}

	if len(foundKeys) == 0 {
		return SSHDiagnosticResult{
			Name:    "SSH Key Existence",
			Status:  "fail",
			Message: "No SSH keys found",
			Details: "Generate a key with: ssh-keygen -t ed25519 -C 'your_email@example.com'",
		}
	}

	return SSHDiagnosticResult{
		Name:    "SSH Key Existence",
		Status:  "pass",
		Message: fmt.Sprintf("Found %d SSH key(s)", len(foundKeys)),
		Details: keyDetails.String(),
	}
}

// GetSSHKeyFingerprint gets the fingerprint of an SSH public key
func GetSSHKeyFingerprint(rc *eos_io.RuntimeContext, pubKeyPath string) SSHDiagnosticResult {
	ctx, span := telemetry.Start(rc.Ctx, "ssh.GetSSHKeyFingerprint")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Debug("Getting SSH key fingerprint", zap.String("path", pubKeyPath))

	cmd := exec.CommandContext(ctx, "ssh-keygen", "-lf", pubKeyPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return SSHDiagnosticResult{
			Name:    "SSH Key Fingerprint",
			Status:  "fail",
			Message: "Failed to get fingerprint",
			Details: fmt.Sprintf("Error: %v\nOutput: %s", err, string(output)),
		}
	}

	return SSHDiagnosticResult{
		Name:    "SSH Key Fingerprint",
		Status:  "pass",
		Message: "Fingerprint retrieved",
		Details: strings.TrimSpace(string(output)),
	}
}

// CheckSSHAgent checks if SSH agent has keys loaded
func CheckSSHAgent(rc *eos_io.RuntimeContext) SSHDiagnosticResult {
	ctx, span := telemetry.Start(rc.Ctx, "ssh.CheckSSHAgent")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Debug("Checking SSH agent")

	cmd := exec.CommandContext(ctx, "ssh-add", "-l")
	output, err := cmd.CombinedOutput()

	if err != nil {
		// ssh-add -l returns 1 if agent has no identities, 2 if agent not running
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() == 1 {
				return SSHDiagnosticResult{
					Name:    "SSH Agent Status",
					Status:  "warn",
					Message: "SSH agent has no identities",
					Details: "Load your key with: ssh-add ~/.ssh/id_ed25519",
				}
			}
			if exitErr.ExitCode() == 2 {
				return SSHDiagnosticResult{
					Name:    "SSH Agent Status",
					Status:  "warn",
					Message: "SSH agent not running",
					Details: "Start agent with: eval $(ssh-agent)",
				}
			}
		}
		return SSHDiagnosticResult{
			Name:    "SSH Agent Status",
			Status:  "fail",
			Message: "Failed to check SSH agent",
			Details: fmt.Sprintf("Error: %v\nOutput: %s", err, string(output)),
		}
	}

	// Count number of keys
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	keyCount := len(lines)
	if keyCount == 1 && lines[0] == "" {
		keyCount = 0
	}

	return SSHDiagnosticResult{
		Name:    "SSH Agent Status",
		Status:  "pass",
		Message: fmt.Sprintf("SSH agent running with %d key(s)", keyCount),
		Details: strings.TrimSpace(string(output)),
	}
}

// GetSSHPublicKeyContent reads the public key content
func GetSSHPublicKeyContent(rc *eos_io.RuntimeContext, pubKeyPath string) SSHDiagnosticResult {
	ctx, span := telemetry.Start(rc.Ctx, "ssh.GetSSHPublicKeyContent")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Debug("Reading SSH public key content", zap.String("path", pubKeyPath))

	content, err := os.ReadFile(pubKeyPath)
	if err != nil {
		return SSHDiagnosticResult{
			Name:    "SSH Public Key Content",
			Status:  "fail",
			Message: "Failed to read public key",
			Details: err.Error(),
		}
	}

	return SSHDiagnosticResult{
		Name:    "SSH Public Key Content",
		Status:  "pass",
		Message: "Public key content available for copying to server",
		Details: strings.TrimSpace(string(content)),
	}
}

// CheckAllSSHKeys discovers all SSH keys in ~/.ssh directory
func CheckAllSSHKeys(rc *eos_io.RuntimeContext) SSHDiagnosticResult {
	ctx, span := telemetry.Start(rc.Ctx, "ssh.CheckAllSSHKeys")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Debug("Discovering all SSH keys")

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return SSHDiagnosticResult{
			Name:    "SSH Key Discovery",
			Status:  "fail",
			Message: "Failed to get user home directory",
			Details: err.Error(),
		}
	}

	sshDir := filepath.Join(homeDir, ".ssh")

	// Find all id_* files (both private keys and public keys)
	cmd := exec.CommandContext(ctx, "ls", "-la", sshDir+"/id_*")
	output, err := cmd.CombinedOutput()

	if err != nil {
		return SSHDiagnosticResult{
			Name:    "SSH Key Discovery",
			Status:  "warn",
			Message: "No SSH keys found",
			Details: "No id_* files found in ~/.ssh/",
		}
	}

	return SSHDiagnosticResult{
		Name:    "SSH Key Discovery",
		Status:  "pass",
		Message: "Found SSH keys in ~/.ssh/",
		Details: strings.TrimSpace(string(output)),
	}
}

// CheckSSHSymlinks checks for symlinks or aliases in SSH key files
func CheckSSHSymlinks(rc *eos_io.RuntimeContext) SSHDiagnosticResult {
	ctx, span := telemetry.Start(rc.Ctx, "ssh.CheckSSHSymlinks")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Debug("Checking for SSH key symlinks")

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return SSHDiagnosticResult{
			Name:    "SSH Key Symlinks",
			Status:  "fail",
			Message: "Failed to get user home directory",
			Details: err.Error(),
		}
	}

	sshDir := filepath.Join(homeDir, ".ssh")

	// Check for id_rsa* files specifically (what ssh-copy-id looks for by default)
	cmd := exec.CommandContext(ctx, "ls", "-laL", sshDir+"/id_rsa*")
	output, err := cmd.CombinedOutput()

	if err != nil {
		return SSHDiagnosticResult{
			Name:    "SSH Key Symlinks",
			Status:  "pass",
			Message: "No id_rsa* files or symlinks found",
			Details: "ssh-copy-id will not default to RSA keys",
		}
	}

	return SSHDiagnosticResult{
		Name:    "SSH Key Symlinks",
		Status:  "warn",
		Message: "Found id_rsa* files (ssh-copy-id defaults)",
		Details: strings.TrimSpace(string(output)),
	}
}

// CheckDefaultSSHKey checks if default id_rsa key exists (what ssh-copy-id uses)
func CheckDefaultSSHKey(rc *eos_io.RuntimeContext) SSHDiagnosticResult {
	ctx, span := telemetry.Start(rc.Ctx, "ssh.CheckDefaultSSHKey")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Debug("Checking for default id_rsa key")

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return SSHDiagnosticResult{
			Name:    "Default SSH Key (id_rsa)",
			Status:  "fail",
			Message: "Failed to get user home directory",
			Details: err.Error(),
		}
	}

	sshDir := filepath.Join(homeDir, ".ssh")
	rsaKeyPath := filepath.Join(sshDir, "id_rsa")

	if _, err := os.Stat(rsaKeyPath); os.IsNotExist(err) {
		return SSHDiagnosticResult{
			Name:    "Default SSH Key (id_rsa)",
			Status:  "pass",
			Message: "No id_rsa file exists",
			Details: "ssh-copy-id will not default to RSA key",
		}
	}

	// Get file type information
	cmd := exec.CommandContext(ctx, "file", rsaKeyPath)
	fileOutput, fileErr := cmd.CombinedOutput()

	// Get file listing
	cmd2 := exec.CommandContext(ctx, "ls", "-la", rsaKeyPath+"*")
	lsOutput, lsErr := cmd2.CombinedOutput()

	var details strings.Builder
	if fileErr == nil {
		details.WriteString("File type: " + strings.TrimSpace(string(fileOutput)) + "\n")
	}
	if lsErr == nil {
		details.WriteString("Listing:\n" + strings.TrimSpace(string(lsOutput)))
	}

	return SSHDiagnosticResult{
		Name:    "Default SSH Key (id_rsa)",
		Status:  "warn",
		Message: "id_rsa exists (ssh-copy-id will prefer this)",
		Details: details.String(),
	}
}

// CheckSSHConfigIncludes checks /etc/ssh/ssh_config.d/ for custom configurations
func CheckSSHConfigIncludes(rc *eos_io.RuntimeContext) SSHDiagnosticResult {
	ctx, span := telemetry.Start(rc.Ctx, "ssh.CheckSSHConfigIncludes")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Debug("Checking SSH config includes")

	configDir := "/etc/ssh/ssh_config.d"

	// Check if directory exists
	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		return SSHDiagnosticResult{
			Name:    "SSH Config Includes",
			Status:  "skip",
			Message: "Directory doesn't exist",
			Details: configDir + " not found",
		}
	}

	// List directory contents
	cmd := exec.CommandContext(ctx, "ls", "-la", configDir)
	lsOutput, lsErr := cmd.CombinedOutput()

	var details strings.Builder
	if lsErr == nil {
		details.WriteString("Directory listing:\n")
		details.WriteString(strings.TrimSpace(string(lsOutput)) + "\n\n")
	}

	// Read contents of any config files
	files, err := filepath.Glob(filepath.Join(configDir, "*"))
	if err == nil && len(files) > 0 {
		details.WriteString("Config file contents:\n")
		for _, file := range files {
			info, err := os.Stat(file)
			if err == nil && info.Mode().IsRegular() {
				content, err := os.ReadFile(file)
				if err == nil {
					details.WriteString(fmt.Sprintf("\n--- %s ---\n", filepath.Base(file)))
					details.WriteString(string(content))
					details.WriteString("\n")
				}
			}
		}
	}

	return SSHDiagnosticResult{
		Name:    "SSH Config Includes",
		Status:  "pass",
		Message: "Checked /etc/ssh/ssh_config.d/",
		Details: details.String(),
	}
}

// CheckSSHKeySelectionOrder tests what SSH would actually use
func CheckSSHKeySelectionOrder(rc *eos_io.RuntimeContext) SSHDiagnosticResult {
	ctx, span := telemetry.Start(rc.Ctx, "ssh.CheckSSHKeySelectionOrder")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Debug("Checking SSH key selection order")

	// Use ssh -v to see which keys SSH will attempt
	cmd := exec.CommandContext(ctx, "ssh", "-v", "-o", "PreferredAuthentications=publickey", "localhost", "exit")
	output, _ := cmd.CombinedOutput() // Ignore error, we're just parsing verbose output

	// Extract "Will attempt key" lines
	var keyAttempts []string
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "Will attempt key") {
			keyAttempts = append(keyAttempts, strings.TrimSpace(line))
		}
	}

	if len(keyAttempts) == 0 {
		return SSHDiagnosticResult{
			Name:    "SSH Key Selection Order",
			Status:  "warn",
			Message: "Could not determine key order",
			Details: "No 'Will attempt key' lines found in ssh -v output",
		}
	}

	// Limit to first 10 keys
	if len(keyAttempts) > 10 {
		keyAttempts = keyAttempts[:10]
	}

	return SSHDiagnosticResult{
		Name:    "SSH Key Selection Order",
		Status:  "pass",
		Message: fmt.Sprintf("SSH will try %d key(s) in order", len(keyAttempts)),
		Details: strings.Join(keyAttempts, "\n"),
	}
}

// CheckSSHCopyIDKeySelection checks what ssh-copy-id would use
func CheckSSHCopyIDKeySelection(rc *eos_io.RuntimeContext, target string) SSHDiagnosticResult {
	ctx, span := telemetry.Start(rc.Ctx, "ssh.CheckSSHCopyIDKeySelection")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Debug("Checking ssh-copy-id key selection", zap.String("target", target))

	if target == "" {
		return SSHDiagnosticResult{
			Name:    "ssh-copy-id Key Selection",
			Status:  "skip",
			Message: "No target specified",
			Details: "Provide target (user@host) to test ssh-copy-id key selection",
		}
	}

	// Use ssh-copy-id -n (dry-run) to see what key it would use
	cmd := exec.CommandContext(ctx, "ssh-copy-id", "-n", target)
	output, _ := cmd.CombinedOutput() // Ignore error, we're just parsing output

	// Extract "Source of key" or similar lines
	var keySource string
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "Source of key") || strings.Contains(line, "key") {
			keySource += strings.TrimSpace(line) + "\n"
		}
	}

	if keySource == "" {
		keySource = string(output) // Include all output if we can't find specific lines
	}

	return SSHDiagnosticResult{
		Name:    "ssh-copy-id Key Selection",
		Status:  "pass",
		Message: "Tested ssh-copy-id key selection",
		Details: strings.TrimSpace(keySource),
	}
}

// RunClientDiagnostics runs all client-side SSH diagnostics
func RunClientDiagnostics(rc *eos_io.RuntimeContext) ([]SSHDiagnosticResult, error) {
	ctx, span := telemetry.Start(rc.Ctx, "ssh.RunClientDiagnostics")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Running client-side SSH diagnostics")

	var results []SSHDiagnosticResult

	// Check for SSH keys
	keyCheck := CheckClientSSHKeys(rc)
	results = append(results, keyCheck)

	// If keys exist, get fingerprint and content
	if keyCheck.Status == "pass" {
		homeDir, _ := os.UserHomeDir()
		sshDir := filepath.Join(homeDir, ".ssh")

		// Try ED25519 first, fall back to RSA
		pubKeyPaths := []string{
			filepath.Join(sshDir, "id_ed25519.pub"),
			filepath.Join(sshDir, "id_rsa.pub"),
			filepath.Join(sshDir, "id_ecdsa.pub"),
		}

		for _, pubKeyPath := range pubKeyPaths {
			if _, err := os.Stat(pubKeyPath); err == nil {
				results = append(results, GetSSHKeyFingerprint(rc, pubKeyPath))
				results = append(results, GetSSHPublicKeyContent(rc, pubKeyPath))
				break // Only process the first found key
			}
		}
	}

	// Check SSH agent
	results = append(results, CheckSSHAgent(rc))

	// SSH Key Discovery diagnostics
	results = append(results, CheckAllSSHKeys(rc))
	results = append(results, CheckSSHSymlinks(rc))
	results = append(results, CheckDefaultSSHKey(rc))
	results = append(results, CheckSSHConfigIncludes(rc))
	results = append(results, CheckSSHKeySelectionOrder(rc))

	logger.Info("Client-side diagnostics completed", zap.Int("results", len(results)))
	return results, nil
}

// RunClientDiagnosticsWithTarget runs client diagnostics including ssh-copy-id test
func RunClientDiagnosticsWithTarget(rc *eos_io.RuntimeContext, target string) ([]SSHDiagnosticResult, error) {
	ctx, span := telemetry.Start(rc.Ctx, "ssh.RunClientDiagnosticsWithTarget")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Running client-side SSH diagnostics with target", zap.String("target", target))

	// Run standard client diagnostics
	results, err := RunClientDiagnostics(rc)
	if err != nil {
		return nil, err
	}

	// Add ssh-copy-id key selection check if target provided
	if target != "" {
		results = append(results, CheckSSHCopyIDKeySelection(rc, target))
	}

	logger.Info("Client-side diagnostics with target completed", zap.Int("results", len(results)))
	return results, nil
}

// RunServerDiagnostics runs server-side SSH diagnostics over SSH
func RunServerDiagnostics(rc *eos_io.RuntimeContext, creds *SSHCredentials) ([]SSHDiagnosticResult, error) {
	ctx, span := telemetry.Start(rc.Ctx, "ssh.RunServerDiagnostics")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Running server-side SSH diagnostics",
		zap.String("host", creds.Host),
		zap.String("user", creds.User))

	var results []SSHDiagnosticResult

	// Helper function to run SSH command
	runSSHCommand := func(name, description, command string) SSHDiagnosticResult {
		args := []string{
			"-o", "BatchMode=yes",
			"-o", "ConnectTimeout=5",
			"-o", "StrictHostKeyChecking=no",
			"-p", creds.Port,
		}

		if creds.KeyPath != "" {
			args = append(args, "-i", creds.KeyPath)
		}

		target := fmt.Sprintf("%s@%s", creds.User, creds.Host)
		args = append(args, target, command)

		cmd := exec.CommandContext(ctx, "ssh", args...)
		output, err := cmd.CombinedOutput()

		if err != nil {
			return SSHDiagnosticResult{
				Name:    name,
				Status:  "fail",
				Message: description + " - Failed",
				Details: fmt.Sprintf("Command: %s\nError: %v\nOutput: %s", command, err, string(output)),
			}
		}

		return SSHDiagnosticResult{
			Name:    name,
			Status:  "pass",
			Message: description + " - OK",
			Details: strings.TrimSpace(string(output)),
		}
	}

	// Check ~/.ssh directory permissions
	results = append(results, runSSHCommand(
		"SSH Directory Permissions",
		"~/.ssh directory permissions",
		"ls -ld ~/.ssh",
	))

	// Check authorized_keys permissions
	results = append(results, runSSHCommand(
		"Authorized Keys Permissions",
		"~/.ssh/authorized_keys permissions",
		"ls -l ~/.ssh/authorized_keys",
	))

	// Check ownership
	results = append(results, runSSHCommand(
		"SSH Directory Ownership",
		"~/.ssh directory and authorized_keys ownership",
		"ls -ln ~/.ssh ~/.ssh/authorized_keys",
	))

	// Check home directory permissions
	results = append(results, runSSHCommand(
		"Home Directory Permissions",
		"Home directory permissions",
		"ls -ld ~/",
	))

	// Check authorized_keys content (count keys)
	results = append(results, runSSHCommand(
		"Authorized Keys Count",
		"Number of keys in authorized_keys",
		"wc -l ~/.ssh/authorized_keys 2>/dev/null || echo '0 (file not found)'",
	))

	// Check authorized_keys first key fingerprint
	results = append(results, runSSHCommand(
		"Authorized Keys Fingerprint",
		"First key fingerprint in authorized_keys",
		"ssh-keygen -lf ~/.ssh/authorized_keys 2>/dev/null | head -1 || echo 'No keys or file not found'",
	))

	// Check sshd_config for PubkeyAuthentication
	results = append(results, runSSHCommand(
		"PubkeyAuthentication Setting",
		"SSH daemon PubkeyAuthentication setting",
		"sudo grep -i '^PubkeyAuthentication' /etc/ssh/sshd_config || echo 'Not set (default: yes)'",
	))

	// Check sshd_config for AuthorizedKeysFile
	results = append(results, runSSHCommand(
		"AuthorizedKeysFile Setting",
		"SSH daemon AuthorizedKeysFile setting",
		"sudo grep -i '^AuthorizedKeysFile' /etc/ssh/sshd_config || echo 'Not set (default: .ssh/authorized_keys)'",
	))

	// Get recent SSH logs (try both journalctl and /var/log/auth.log)
	sshLogsResult := runSSHCommand(
		"Recent SSH Logs",
		"Recent SSH authentication logs",
		"sudo journalctl -u ssh -n 50 --no-pager 2>/dev/null || sudo tail -50 /var/log/auth.log 2>/dev/null | grep -i ssh || echo 'Logs not accessible'",
	)
	results = append(results, sshLogsResult)

	logger.Info("Server-side diagnostics completed", zap.Int("results", len(results)))
	return results, nil
}

// RunFullSSHDiagnostics runs both client and server diagnostics
func RunFullSSHDiagnostics(rc *eos_io.RuntimeContext, sshPath string, keyPath string) (*SSHDiagnosticReport, error) {
	ctx, span := telemetry.Start(rc.Ctx, "ssh.RunFullSSHDiagnostics")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Running full SSH diagnostics", zap.String("target", sshPath))

	report := &SSHDiagnosticReport{
		Timestamp:  time.Now(),
		TargetHost: sshPath,
	}

	// Run client diagnostics with target (includes ssh-copy-id key selection)
	clientResults, err := RunClientDiagnosticsWithTarget(rc, sshPath)
	if err != nil {
		return nil, fmt.Errorf("client diagnostics failed: %w", err)
	}
	report.ClientResults = clientResults

	// If SSH path provided, run server diagnostics
	if sshPath != "" {
		creds, err := ParseSSHPath(sshPath)
		if err != nil {
			return nil, fmt.Errorf("invalid SSH path: %w", err)
		}

		// Use provided key path or select one
		if keyPath != "" {
			creds.KeyPath = keyPath
		} else {
			// Try to find a key automatically
			homeDir, _ := os.UserHomeDir()
			sshDir := filepath.Join(homeDir, ".ssh")
			keyPaths := []string{
				filepath.Join(sshDir, "id_ed25519"),
				filepath.Join(sshDir, "id_rsa"),
				filepath.Join(sshDir, "id_ecdsa"),
			}

			for _, kp := range keyPaths {
				if _, err := os.Stat(kp); err == nil {
					creds.KeyPath = kp
					break
				}
			}
		}

		serverResults, err := RunServerDiagnostics(rc, creds)
		if err != nil {
			logger.Warn("Server diagnostics failed", zap.Error(err))
			// Don't fail the entire operation, just report the error
			report.ServerResults = []SSHDiagnosticResult{{
				Name:    "Server Diagnostics",
				Status:  "fail",
				Message: "Failed to connect to server",
				Details: err.Error(),
			}}
		} else {
			report.ServerResults = serverResults
		}
	}

	logger.Info("Full SSH diagnostics completed",
		zap.Int("client_results", len(report.ClientResults)),
		zap.Int("server_results", len(report.ServerResults)))

	return report, nil
}
