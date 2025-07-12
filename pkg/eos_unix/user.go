// pkg/eos_unix/user.go

package eos_unix

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Package eos_unix provides secure user management with structured logging
// This implementation follows Eos standards:
// - All fmt.Print* replaced with structured logging or stderr output
// - Using execute.Run instead of exec.Command
// - Proper RuntimeContext usage
// - Enhanced error handling

// SetPassword sets the Linux user's password using chpasswd
func SetPassword(rc *eos_io.RuntimeContext, username, password string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Debug("Setting password for user",
		zap.String("username", username))
	
	// Use execute package for command execution with stdin input
	input := fmt.Sprintf("%s:%s", username, password)
	
	// For commands that need stdin, we use exec.Command but with proper logging
	cmd := exec.Command("chpasswd")
	cmd.Stdin = strings.NewReader(input)
	err := cmd.Run()
	
	if err != nil {
		return fmt.Errorf("failed to set password for user %s: %w", username, err)
	}
	
	logger.Info("Password set successfully",
		zap.String("username", username))
	
	return nil
}

// UserExists checks if a Linux user exists
func UserExists(rc *eos_io.RuntimeContext, name string) bool {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Debug("Checking if user exists",
		zap.String("username", name))
		
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "id",
		Args:    []string{name},
		Capture: false,
	})
	
	exists := err == nil
	logger.Debug("User existence check result",
		zap.String("username", name),
		zap.Bool("exists", exists))
		
	return exists
}

// GetUserShell returns the shell configured for the given user
func GetUserShell(rc *eos_io.RuntimeContext, username string) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Debug("Getting shell for user",
		zap.String("username", username))
		
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "getent",
		Args:    []string{"passwd", username},
		Capture: true,
	})
	
	if err != nil {
		return "", fmt.Errorf("failed to get shell for user '%s': %w", username, err)
	}
	
	parts := strings.Split(string(output), ":")
	if len(parts) < 7 {
		return "", fmt.Errorf("unexpected passwd format for user '%s'", username)
	}
	
	shell := strings.TrimSpace(parts[6])
	logger.Debug("Retrieved user shell",
		zap.String("username", username),
		zap.String("shell", shell))
		
	return shell, nil
}

// generateOrPromptPassword generates a password automatically or securely prompts the user
func generateOrPromptPassword(rc *eos_io.RuntimeContext, auto bool) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	if auto {
		logger.Info("Generating password automatically")
		return crypto.GeneratePassword(20)
	}

	reader := bufio.NewReader(os.Stdin)

	for {
		// Log the prompt for audit trail
		logger.Info("terminal prompt: Enter password")
		
		// Use stderr for user prompts to preserve stdout
		if _, err := fmt.Fprint(os.Stderr, shared.PromptEnterPassword); err != nil {
			return "", fmt.Errorf("failed to write prompt: %w", err)
		}
		
		pw1, err := crypto.ReadPassword(reader)
		if err != nil {
			return "", fmt.Errorf("failed to read password: %w", err)
		}

		if err := crypto.ValidateStrongPassword(rc.Ctx, pw1); err != nil {
			logger.Warn("Password too weak",
				zap.Error(err))
			continue
		}

		// Log the confirmation prompt
		logger.Info("terminal prompt: Confirm password")
		
		if _, err := fmt.Fprint(os.Stderr, shared.PromptConfirmPassword); err != nil {
			return "", fmt.Errorf("failed to write prompt: %w", err)
		}
		
		pw2, err := crypto.ReadPassword(reader)
		if err != nil {
			return "", fmt.Errorf("failed to read password confirmation: %w", err)
		}

		if pw1 != pw2 {
			logger.Warn("Passwords do not match")
			if _, err := fmt.Fprintln(os.Stderr, "Passwords do not match. Please try again."); err != nil {
				return "", fmt.Errorf("failed to write error message: %w", err)
			}
			continue
		}

		logger.Info("Password validated successfully")
		return pw1, nil
	}
}

// PromptUsername prompts the user for a username
func PromptUsername(rc *eos_io.RuntimeContext) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("terminal prompt: Enter username")
	
	// Use stderr for prompts
	if _, err := fmt.Fprint(os.Stderr, shared.PromptUsernameInput); err != nil {
		return "", fmt.Errorf("failed to write prompt: %w", err)
	}
	
	reader := bufio.NewReader(os.Stdin)
	username, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("failed to read username: %w", err)
	}
	
	username = strings.TrimSpace(username)
	logger.Info("Username entered",
		zap.String("username", username))
		
	return username, nil
}

// CreateUser creates a new system user following Assess → Intervene → Evaluate
func CreateUser(rc *eos_io.RuntimeContext, username string, auto bool, shell string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS - Check prerequisites
	logger.Info("Assessing user creation requirements",
		zap.String("username", username))
	
	// Check if user already exists
	if UserExists(rc, username) {
		return fmt.Errorf("user '%s' already exists", username)
	}
	
	// Validate shell if specified
	if shell != "" {
		if _, err := os.Stat(shell); err != nil {
			return fmt.Errorf("invalid shell '%s': %w", shell, err)
		}
	}
	
	// INTERVENE - Create the user
	logger.Info("Creating system user",
		zap.String("username", username),
		zap.String("shell", shell))
	
	// Generate or prompt for password
	password, err := generateOrPromptPassword(rc, auto)
	if err != nil {
		return fmt.Errorf("failed to get password: %w", err)
	}
	
	// Create user with useradd
	args := []string{"-m", username}
	if shell != "" {
		args = append(args, "-s", shell)
	}
	
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "useradd",
		Args:    args,
		Capture: false,
	}); err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}
	
	// Set password
	if err := SetPassword(rc, username, password); err != nil {
		// Rollback user creation on failure
		logger.Error("Failed to set password, rolling back user creation",
			zap.Error(err))
		execute.Run(rc.Ctx, execute.Options{
			Command: "userdel",
			Args:    []string{"-r", username},
			Capture: false,
		})
		return err
	}
	
	// Create SSH key if requested
	sshKeyPath := filepath.Join("/home", username, ".ssh", "id_rsa")
	if err := createSSHKey(rc, username, sshKeyPath); err != nil {
		logger.Warn("Failed to create SSH key",
			zap.Error(err))
	}
	
	// EVALUATE - Verify user was created successfully
	logger.Info("Evaluating user creation")
	
	if !UserExists(rc, username) {
		return fmt.Errorf("user creation verification failed")
	}
	
	// Display summary to user
	summary := fmt.Sprintf("\n✅ User created successfully:\n"+
		"   Username: %s\n"+
		"   Password: %s\n"+
		"   SSH key: %s\n", 
		username, password, sshKeyPath)
		
	if _, err := fmt.Fprint(os.Stderr, summary); err != nil {
		logger.Warn("Failed to display summary", zap.Error(err))
	}
	
	logger.Info("User created successfully",
		zap.String("username", username),
		zap.String("ssh_key", sshKeyPath))
	
	return nil
}

// createSSHKey creates an SSH key for the user
func createSSHKey(rc *eos_io.RuntimeContext, username, keyPath string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Creating SSH key for user",
		zap.String("username", username),
		zap.String("path", keyPath))
	
	// Create .ssh directory
	sshDir := filepath.Dir(keyPath)
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return fmt.Errorf("failed to create .ssh directory: %w", err)
	}
	
	// Generate SSH key
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ssh-keygen",
		Args:    []string{"-t", "rsa", "-b", "4096", "-f", keyPath, "-N", ""},
		Capture: false,
	})
	
	if err != nil {
		return fmt.Errorf("failed to generate SSH key: %w", err)
	}
	
	// Set correct ownership
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "chown",
		Args:    []string{"-R", fmt.Sprintf("%s:%s", username, username), sshDir},
		Capture: false,
	}); err != nil {
		return fmt.Errorf("failed to set SSH key ownership: %w", err)
	}
	
	logger.Info("SSH key created successfully",
		zap.String("username", username),
		zap.String("path", keyPath))
	
	return nil
}

// HandleInterrupt handles Ctrl+C gracefully
func HandleInterrupt(rc *eos_io.RuntimeContext) {
	logger := otelzap.Ctx(rc.Ctx)
	
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	
	go func() {
		<-c
		logger.Info("Received interrupt signal")
		
		if _, err := fmt.Fprintln(os.Stderr, "\n⚠️  Operation canceled."); err != nil {
			logger.Error("Failed to write cancellation message", zap.Error(err))
		}
		
		os.Exit(1)
	}()
}

// LoadPasswordFromSecrets loads the eos user credentials from eos-passwd.json
func LoadPasswordFromSecrets(ctx context.Context) (*shared.UserpassCreds, error) {
	logger := otelzap.Ctx(ctx)
	
	secretsPath := filepath.Join(shared.SecretsDir, shared.SecretsFilename)
	
	logger.Debug("Loading password from secrets file",
		zap.String("path", secretsPath))
	
	data, err := os.ReadFile(secretsPath)
	if err != nil {
		logger.Warn("Failed to read eos password file", 
			zap.String("path", secretsPath), 
			zap.Error(err))
		return nil, fmt.Errorf("read secrets file: %w", err)
	}
	
	var creds shared.UserpassCreds
	if err := json.Unmarshal(data, &creds); err != nil {
		logger.Warn("Failed to parse secrets file", 
			zap.String("path", secretsPath), 
			zap.Error(err))
		return nil, fmt.Errorf("parse secrets file: %w", err)
	}
	
	logger.Debug("Successfully loaded credentials from secrets file")
	return &creds, nil
}

// RunCreateUser creates a user with the specified options
func RunCreateUser(ctx context.Context, opts CreateUserOptions) error {
	logger := otelzap.Ctx(ctx)
	
	logger.Info("Creating user with options",
		zap.String("username", opts.Username),
		zap.Bool("auto", opts.Auto),
		zap.Bool("login_shell", opts.LoginShell))
	
	// Check if user already exists
	if UserExists(&eos_io.RuntimeContext{Ctx: ctx}, opts.Username) {
		return fmt.Errorf("user '%s' already exists", opts.Username)
	}
	
	// Generate password
	password, err := generateOrPromptPassword(&eos_io.RuntimeContext{Ctx: ctx}, opts.Auto)
	if err != nil {
		return fmt.Errorf("failed to get password: %w", err)
	}
	
	// Create user with home directory
	args := []string{"-m", opts.Username}
	if opts.LoginShell {
		args = append(args, "-s", "/bin/bash")
	}
	
	if _, err := execute.Run(ctx, execute.Options{
		Command: "useradd",
		Args:    args,
		Capture: false,
	}); err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}
	
	// Set password
	if err := SetPassword(&eos_io.RuntimeContext{Ctx: ctx}, opts.Username, password); err != nil {
		return fmt.Errorf("failed to set password: %w", err)
	}
	
	logger.Info("User created successfully",
		zap.String("username", opts.Username))
	
	return nil
}

// SecretsExist checks if the secrets file exists
func SecretsExist() bool {
	secretsPath := filepath.Join(shared.SecretsDir, shared.SecretsFilename)
	_, err := os.Stat(secretsPath)
	return err == nil
}

// SavePasswordToSecrets saves the user credentials to the secrets file
func SavePasswordToSecrets(ctx context.Context, username, password string) error {
	logger := otelzap.Ctx(ctx)
	
	secretsPath := filepath.Join(shared.SecretsDir, shared.SecretsFilename)
	
	logger.Debug("Saving password to secrets file",
		zap.String("path", secretsPath),
		zap.String("username", username))
	
	// Create directory if it doesn't exist
	if err := os.MkdirAll(shared.SecretsDir, 0700); err != nil {
		return fmt.Errorf("failed to create secrets directory: %w", err)
	}
	
	creds := shared.UserpassCreds{
		Username: username,
		Password: password,
	}
	
	data, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal credentials: %w", err)
	}
	
	if err := os.WriteFile(secretsPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write secrets file: %w", err)
	}
	
	logger.Info("Password saved to secrets file successfully")
	return nil
}

// SetupSignalHandler sets up signal handling for graceful shutdown
func SetupSignalHandler() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	
	go func() {
		<-c
		fmt.Fprintln(os.Stderr, "\n⚠️  Operation canceled.")
		os.Exit(1)
	}()
}