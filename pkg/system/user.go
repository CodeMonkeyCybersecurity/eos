// pkg/system/user.go

package system

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
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
