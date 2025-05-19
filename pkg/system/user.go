// pkg/system/user.go

package system

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"go.uber.org/zap"
)

// SetPassword sets the Linux user's password using chpasswd.
func SetPassword(username, password string) error {
	cmd := exec.Command("chpasswd")
	cmd.Stdin = strings.NewReader(fmt.Sprintf("%s:%s", username, password))
	return cmd.Run()
}

// SecretsExist returns true if the eos-passwd.json file exists
func SecretsExist() bool {
	_, err := os.Stat(filepath.Join(shared.SecretsDir, shared.SecretsFilename))
	return err == nil
}

// UserExists checks if a Linux user exists.
func UserExists(name string) bool {
	return exec.Command("id", name).Run() == nil
}

// GetUserShell returns the shell configured for the given user.
func GetUserShell(username string) (string, error) {
	cmd := exec.Command("getent", "passwd", username)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get shell for user '%s': %w", username, err)
	}
	parts := strings.Split(string(out), ":")
	if len(parts) < 7 {
		return "", fmt.Errorf("unexpected passwd format for user '%s'", username)
	}
	return strings.TrimSpace(parts[6]), nil
}

// generateOrPromptPassword generates a password automatically or securely prompts the user.
func generateOrPromptPassword(auto bool) (string, error) {
	if auto {
		return crypto.GeneratePassword(20)
	}

	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print(shared.PromptEnterPassword)
		pw1, err := crypto.ReadPassword(reader)
		if err != nil {
			return "", fmt.Errorf("failed to read password: %w", err)
		}

		if err := crypto.ValidateStrongPassword(pw1); err != nil {
			zap.L().Warn("❌ Password too weak", zap.Error(err))
			continue
		}

		fmt.Print(shared.PromptConfirmPassword)
		pw2, err := crypto.ReadPassword(reader)
		if err != nil {
			return "", fmt.Errorf("failed to read confirmation password: %w", err)
		}

		if pw1 != pw2 {
			zap.L().Warn("❌ Passwords do not match")
			continue
		}

		return pw1, nil
	}
}

// promptUsername safely prompts the user to enter a username, defaulting to eos.
func promptUsername() string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(shared.PromptUsernameInput)
	input, _ := reader.ReadString('\n')
	if trimmed := strings.TrimSpace(input); trimmed != "" {
		return trimmed
	}
	return shared.EosID
}

// LoadPasswordFromSecrets loads the eos user credentials from JSON using shared.UserpassCreds.
// LoadPasswordFromSecrets loads the eos user credentials from eos-passwd.json.
func LoadPasswordFromSecrets() (*shared.UserpassCreds, error) {
	secretsPath := filepath.Join(shared.SecretsDir, shared.SecretsFilename)

	data, err := os.ReadFile(secretsPath)
	if err != nil {
		zap.L().Warn("❌ Failed to read eos password file", zap.String("path", secretsPath), zap.Error(err))
		return nil, fmt.Errorf("read secrets file: %w", err)
	}

	var creds shared.UserpassCreds
	if err := json.Unmarshal(data, &creds); err != nil {
		zap.L().Warn("❌ Failed to parse eos password JSON", zap.String("path", secretsPath), zap.Error(err))
		return nil, fmt.Errorf("unmarshal secrets: %w", err)
	}

	if creds.Username == "" || creds.Password == "" {
		zap.L().Warn("❌ Loaded eos credentials are incomplete", zap.Any("creds", creds))
		return nil, fmt.Errorf("incomplete credentials loaded from %s", secretsPath)
	}

	zap.L().Info("✅ Loaded eos credentials successfully", zap.String("username", creds.Username))
	return &creds, nil
}

// SavePasswordToSecrets saves the eos user credentials as JSON using shared.UserpassCreds.
func SavePasswordToSecrets(username, password string) error {
	secretsPath := filepath.Join(shared.SecretsDir, shared.SecretsFilename)

	creds := shared.UserpassCreds{
		Username: username,
		Password: password,
	}

	data, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal credentials: %w", err)
	}

	if err := os.MkdirAll(shared.SecretsDir, 0700); err != nil {
		return fmt.Errorf("could not create secrets directory: %w", err)
	}

	if err := os.WriteFile(secretsPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write credentials to file: %w", err)
	}

	zap.L().Info("🔐 eos credentials saved", zap.String("path", secretsPath))
	return nil
}

func RunCreateUser(opts CreateUserOptions) error {
	SetupSignalHandler()

	if os.Geteuid() != 0 {
		return errors.New("please run as root or with sudo")
	}

	username := opts.Username
	if !opts.Auto {
		input := interaction.PromptInput("Enter new username", "eos")
		if input != "" {
			username = input
		}
	}

	if UserExists(username) {
		zap.L().Warn("User already exists", zap.String("username", username))
		return nil
	}

	shell := "/usr/sbin/nologin"
	if opts.LoginShell {
		zap.L().Info("Creating user with login shell")
		shell = "/bin/bash"
	} else {
		zap.L().Info("Creating system user with no login shell")
	}

	zap.L().Info("Creating user", zap.String("username", username))
	if err := execute.RunSimple("useradd", "-m", "-s", shell, username); err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	var password string
	if opts.Auto {
		pw, err := crypto.GeneratePassword(20)
		if err != nil {
			return err
		}
		password = pw
	} else {
		pw1, err := interaction.PromptSecret("Enter password")
		if err != nil {
			return err
		}
		pw2, err := interaction.PromptSecret("Confirm password")
		if err != nil {
			return err
		}
		if strings.TrimSpace(pw1) != strings.TrimSpace(pw2) {
			return errors.New("passwords do not match")
		}
		password = strings.TrimSpace(pw1)
	}

	if err := SetPassword(username, password); err != nil {
		return err
	}

	adminGroup := platform.GuessAdminGroup()
	if !opts.Auto {
		answer := interaction.PromptInput("Should this user have sudo privileges?", "yes")
		if strings.TrimSpace(strings.ToLower(answer)) == "no" {
			adminGroup = ""
		}
	}
	if adminGroup != "" {
		zap.L().Info("Granting admin privileges", zap.String("group", adminGroup))
		if err := execute.RunSimple("usermod", "-aG", adminGroup, username); err != nil {
			return fmt.Errorf("error adding to admin group: %w", err)
		}
	}

	if err := CreateSSHKeys(username); err != nil {
		return err
	}

	fmt.Println("✅ User created:", username)
	fmt.Println("🔐 Password:", password)
	fmt.Println("📁 SSH key:", "/home/"+username+"/.ssh/id_rsa")

	return nil
}

func SetupSignalHandler() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Println("\n❌ Operation canceled.")
		os.Exit(1)
	}()
}
