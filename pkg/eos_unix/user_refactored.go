// pkg/eos_unix/user_refactored.go

package eos_unix

import (
	"bufio"
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

// TODO: This is a refactored version of user.go following Eos standards:
// - All fmt.Print* replaced with structured logging or stderr output
// - Using execute.Run instead of exec.Command
// - Proper RuntimeContext usage
// - Enhanced error handling

// SetPasswordRefactored sets the Linux user's password using chpasswd
func SetPasswordRefactored(rc *eos_io.RuntimeContext, username, password string) error {
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

// UserExistsRefactored checks if a Linux user exists
func UserExistsRefactored(rc *eos_io.RuntimeContext, name string) bool {
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

// GetUserShellRefactored returns the shell configured for the given user
func GetUserShellRefactored(rc *eos_io.RuntimeContext, username string) (string, error) {
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

// generateOrPromptPasswordRefactored generates a password automatically or securely prompts the user
func generateOrPromptPasswordRefactored(rc *eos_io.RuntimeContext, auto bool) (string, error) {
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

// PromptUsernameRefactored prompts the user for a username
func PromptUsernameRefactored(rc *eos_io.RuntimeContext) (string, error) {
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

// CreateUserRefactored creates a new system user following Assess → Intervene → Evaluate
func CreateUserRefactored(rc *eos_io.RuntimeContext, username string, auto bool, shell string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS - Check prerequisites
	logger.Info("Assessing user creation requirements",
		zap.String("username", username))
	
	// Check if user already exists
	if UserExistsRefactored(rc, username) {
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
	password, err := generateOrPromptPasswordRefactored(rc, auto)
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
	if err := SetPasswordRefactored(rc, username, password); err != nil {
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
	if err := createSSHKeyRefactored(rc, username, sshKeyPath); err != nil {
		logger.Warn("Failed to create SSH key",
			zap.Error(err))
	}
	
	// EVALUATE - Verify user was created successfully
	logger.Info("Evaluating user creation")
	
	if !UserExistsRefactored(rc, username) {
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

// createSSHKeyRefactored creates an SSH key for the user
func createSSHKeyRefactored(rc *eos_io.RuntimeContext, username, keyPath string) error {
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

// HandleInterruptRefactored handles Ctrl+C gracefully
func HandleInterruptRefactored(rc *eos_io.RuntimeContext) {
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