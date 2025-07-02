package ssh

import (
	"fmt"
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