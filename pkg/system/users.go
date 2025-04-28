package system

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"go.uber.org/zap"
)

// SetPassword sets the Linux user's password using chpasswd.
func SetPassword(username, password string) error {
	cmd := exec.Command("chpasswd")
	cmd.Stdin = strings.NewReader(fmt.Sprintf("%s:%s", username, password))
	return cmd.Run()
}

// EnsureEosUser creates or validates the eos system user.
func EnsureEosUser(auto bool, loginShell bool, log *zap.Logger) error {
	username := shared.EosID

	// Check if user already exists
	if UserExists(username) {
		log.Info("✅ eos user exists", zap.String("user", username))

		_, err := user.Lookup(username)
		if err != nil {
			return fmt.Errorf("failed to lookup user '%s': %w", username, err)
		}
		shell, err := GetUserShell(username)
		if err != nil {
			return err
		}
		if !strings.Contains(shell, "nologin") {
			return fmt.Errorf("user '%s' has shell access: %s (expected /usr/sbin/nologin)", username, shell)
		}

		log.Info("✅ eos user has no shell access")
		log.Info("✅ eos user validation complete")
		return nil
	}

	log.Warn("👤 eos user not found — creating...")

	// Interactive username override (optional)
	if !auto {
		username = promptUsername()
	}

	// Determine login shell
	shell := "/usr/sbin/nologin"
	if loginShell {
		shell = "/bin/bash"
	}

	if err := execute.Execute("useradd", "-m", "-s", shell, username); err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	password, err := generateOrPromptPassword(auto, log)
	if err != nil {
		return fmt.Errorf("password generation failed: %w", err)
	}

	if err := SetPassword(username, password); err != nil {
		return fmt.Errorf("failed to set password for user '%s': %w", username, err)
	}

	if err := EnsureSudoersEntryForEos(log, auto); err != nil {
		return fmt.Errorf("failed to configure sudo access: %w", err)
	}

	if err := SavePasswordToSecrets(username, password, log); err != nil {
		log.Warn("⚠️ Could not save password to disk", zap.Error(err))
	}

	if !SecretsExist() && UserExists(shared.EosID) {
		log.Warn("EOS password file missing — generating replacement password")

		newPass, err := crypto.GeneratePassword(20)
		if err != nil {
			return fmt.Errorf("failed to generate replacement password: %w", err)
		}

		if err := SetPassword(shared.EosID, newPass); err != nil {
			return fmt.Errorf("failed to set replacement password for eos user: %w", err)
		}

		if err := SavePasswordToSecrets(shared.EosID, newPass, log); err != nil {
			return fmt.Errorf("failed to save replacement password: %w", err)
		}

		log.Info("✅ Replacement eos credentials generated and saved")
	}

	// Memory hygiene (zero password string)
	passwordBytes := []byte(password)
	crypto.SecureZero(passwordBytes)

	log.Info("✅ eos user created and configured", zap.String("username", username))
	return nil
}

// SecretsExist returns true if the eos-passwd.json file exists
func SecretsExist() bool {
	_, err := os.Stat(filepath.Join(shared.SecretsDir, shared.SecretsFilename))
	return err == nil
}

// RepairEosSecrets generates a new strong password and saves it securely.
func RepairEosSecrets(log *zap.Logger) error {
	password, err := crypto.GeneratePassword(20)
	if err != nil {
		return fmt.Errorf("generate password: %w", err)
	}
	if err := SetPassword(shared.EosID, password); err != nil {
		return fmt.Errorf("set password: %w", err)
	}
	if err := SavePasswordToSecrets(shared.EosID, password, log); err != nil {
		return fmt.Errorf("save password: %w", err)
	}

	log.Info("✅ Regenerated eos credentials successfully", zap.String("user", shared.EosID))
	return nil
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
func generateOrPromptPassword(auto bool, log *zap.Logger) (string, error) {
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

		if err := crypto.ValidateStrongPassword(pw1, log); err != nil {
			log.Warn("❌ Password too weak", zap.Error(err))
			continue
		}

		fmt.Print(shared.PromptConfirmPassword)
		pw2, err := crypto.ReadPassword(reader)
		if err != nil {
			return "", fmt.Errorf("failed to read confirmation password: %w", err)
		}

		if pw1 != pw2 {
			log.Warn("❌ Passwords do not match")
			continue
		}

		return pw1, nil
	}
}

// EnsureSudoersEntryForEos ensures a sudoers entry exists for the eos user.
func EnsureSudoersEntryForEos(log *zap.Logger, auto bool) error {
	const path = shared.SudoersEosPath
	const entry = shared.SudoersEosEntry

	log.Info("🔍 Checking for existing sudoers entry", zap.String("path", path))
	if _, err := os.Stat(path); err == nil {
		log.Info("✅ Sudoers file for eos already exists", zap.String("path", path))
		return nil
	}

	if !auto {
		reader := bufio.NewReader(os.Stdin)
		resp, err := interaction.ReadLine(reader, "Create sudoers entry for eos? (y/N)", log)
		if err != nil {
			log.Warn("❌ Failed to read sudoers prompt", zap.Error(err))
			return err
		}
		if strings.ToLower(resp) != "y" {
			log.Warn("⚠️ User declined to write sudoers file")
			return nil
		}
	}

	log.Info("✍️  Writing sudoers entry", zap.String("path", path))
	if err := os.WriteFile(path, []byte(entry+"\n"), 0440); err != nil {
		return fmt.Errorf("write sudoers entry: %w", err)
	}

	log.Info("✅ Sudoers entry written successfully", zap.String("path", path))

	log.Info("🧪 Validating sudoers file with visudo -c")
	if err := exec.Command("visudo", "-c").Run(); err != nil {
		log.Warn("❌ Sudoers file validation failed", zap.Error(err))
		return fmt.Errorf("sudoers validation failed")
	}

	log.Info("✅ Sudoers file is valid")
	return nil
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
func LoadPasswordFromSecrets(log *zap.Logger) (*shared.UserpassCreds, error) {
	secretsPath := filepath.Join(shared.SecretsDir, shared.SecretsFilename)

	data, err := os.ReadFile(secretsPath)
	if err != nil {
		log.Warn("❌ Failed to read eos password file", zap.String("path", secretsPath), zap.Error(err))
		return nil, fmt.Errorf("read secrets file: %w", err)
	}

	var creds shared.UserpassCreds
	if err := json.Unmarshal(data, &creds); err != nil {
		log.Warn("❌ Failed to parse eos password JSON", zap.String("path", secretsPath), zap.Error(err))
		return nil, fmt.Errorf("unmarshal secrets: %w", err)
	}

	if creds.Username == "" || creds.Password == "" {
		log.Warn("❌ Loaded eos credentials are incomplete", zap.Any("creds", creds))
		return nil, fmt.Errorf("incomplete credentials loaded from %s", secretsPath)
	}

	log.Info("✅ Loaded eos credentials successfully", zap.String("username", creds.Username))
	return &creds, nil
}

// SavePasswordToSecrets saves the eos user credentials as JSON using shared.UserpassCreds.
func SavePasswordToSecrets(username, password string, log *zap.Logger) error {
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

	log.Info("🔐 eos credentials saved", zap.String("path", secretsPath))
	return nil
}

func ValidateSudoAccess(log *zap.Logger) error {
	cmd := exec.Command("sudo", "-u", shared.EosID, "cat", shared.VaultAgentTokenPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Warn("❌ sudo -u eos failed", zap.Error(err), zap.String("output", string(out)))
		return fmt.Errorf("sudo check failed")
	}
	log.Info("✅ sudo test succeeded")
	return nil
}
