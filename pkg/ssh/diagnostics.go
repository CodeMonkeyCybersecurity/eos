package ssh

import (
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
	expectedPerms := os.FileMode(0600)
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