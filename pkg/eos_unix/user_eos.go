// pkg/unix/user_eos.go

package eos_unix

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"go.uber.org/zap"
)

// EnsureEosUser creates or validates the 'eos' Linux system user, configures its shell,
// sets a password, and prepares sudoers and credentials.
func EnsureEosUser(auto bool, loginShell bool) error {
	username := shared.EosID

	// Check if user already exists
	if UserExists(username) {
		zap.L().Info("✅ eos user exists", zap.String("user", username))

		_, err := user.Lookup(username)
		if err != nil {
			return fmt.Errorf("failed to lookup user '%s': %w", username, err)
		}
		shell, err := GetUserShell(username)
		if err != nil {
			return err
		}
		if !strings.Contains(shell, "nologin") {
			zap.L().Warn("❌ eos user has shell access, which is unexpected", zap.String("shell", shell))
			return fmt.Errorf("user '%s' has shell access: %s (expected /usr/sbin/nologin)", username, shell)
		}

		zap.L().Info("✅ eos user has no shell access")
		zap.L().Info("✅ eos user validation complete")
		return nil
	}

	zap.L().Warn("👤 eos user not found — creating...")

	// Interactive username override (optional)
	if !auto {
		username = promptUsername()
	}

	// Determine login shell
	shell := shared.EosShellNoLogin
	if loginShell {
		shell = shared.EosShellBash
	}

	if err := execute.RunSimple("useradd", "-m", "-s", shell, username); err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	password, err := generateOrPromptPassword(auto)
	if err != nil {
		return fmt.Errorf("password generation failed: %w", err)
	}

	if err := SetPassword(username, password); err != nil {
		return fmt.Errorf("failed to set password for user '%s': %w", username, err)
	}

	if err := EnsureSudoersEntryForEos(auto); err != nil {
		return fmt.Errorf("failed to configure sudo access: %w", err)
	}

	if err := SavePasswordToSecrets(username, password); err != nil {
		zap.L().Warn("⚠️ Could not save password to disk", zap.Error(err))
	}

	userExists := UserExists(shared.EosID)
	if userExists && !SecretsExist() {
		zap.L().Warn("EOS password file missing — generating replacement password")

		newPass, err := crypto.GeneratePassword(20)
		if err != nil {
			return fmt.Errorf("failed to generate replacement password: %w", err)
		}

		if err := SetPassword(shared.EosID, newPass); err != nil {
			return fmt.Errorf("failed to set replacement password for eos user: %w", err)
		}

		if err := SavePasswordToSecrets(shared.EosID, newPass); err != nil {
			return fmt.Errorf("failed to save replacement password: %w", err)
		}

		zap.L().Info("✅ Replacement eos credentials generated and saved")
	}

	// Memory hygiene (zero password string)
	passwordBytes := []byte(password)
	crypto.SecureZero(passwordBytes)

	zap.L().Info("✅ eos user created and configured", zap.String("username", username))
	return nil
}

// RepairEosSecrets generates a new strong password and saves it securely.
func RepairEosSecrets() error {
	password, err := crypto.GeneratePassword(20)
	if err != nil {
		return fmt.Errorf("generate password: %w", err)
	}
	if err := SetPassword(shared.EosID, password); err != nil {
		return fmt.Errorf("set password: %w", err)
	}
	if err := SavePasswordToSecrets(shared.EosID, password); err != nil {
		return fmt.Errorf("save password: %w", err)
	}

	zap.L().Info("✅ Regenerated eos credentials successfully", zap.String("user", shared.EosID))
	return nil
}

func ValidateEosSudoAccess() error {
	cmd := exec.Command("cat", shared.AgentToken)
	out, err := cmd.CombinedOutput()
	if err != nil {
		zap.L().Warn("❌ sudo -u eos failed", zap.Error(err), zap.String("output", string(out)))
		return fmt.Errorf("sudo check failed")
	}
	zap.L().Info("✅ sudo test succeeded")
	return nil
}

// EnsureSudoersEntryForEos ensures a sudoers entry exists for the eos user.
func EnsureSudoersEntryForEos(auto bool) error {
	const path = shared.EosSudoersPath
	const entry = shared.SudoersEosEntry

	zap.L().Info("🔍 Checking for existing sudoers entry", zap.String("path", path))
	if _, err := os.Stat(path); err == nil {
		zap.L().Info("✅ Sudoers file for eos already exists", zap.String("path", path))
		return nil
	}

	if !auto {
		reader := bufio.NewReader(os.Stdin)
		resp, err := interaction.ReadLine(reader, "Create sudoers entry for eos? (y/N)")
		if err != nil {
			zap.L().Warn("❌ Failed to read sudoers prompt", zap.Error(err))
			return err
		}
		if strings.ToLower(resp) != "y" {
			zap.L().Warn("⚠️ User declined to write sudoers file")
			return nil
		}
	}

	zap.L().Info("✍️  Writing sudoers entry", zap.String("path", path))
	if err := os.WriteFile(path, []byte(entry+"\n"), 0440); err != nil {
		return fmt.Errorf("write sudoers entry: %w", err)
	}

	zap.L().Info("✅ Sudoers entry written successfully", zap.String("path", path))

	zap.L().Info("🧪 Validating sudoers file with visudo -c")
	if err := exec.Command("visudo", "-c").Run(); err != nil {
		zap.L().Warn("❌ Sudoers file validation failed", zap.Error(err))
		return fmt.Errorf("sudoers validation failed")
	}

	zap.L().Info("✅ Sudoers file is valid")
	return nil
}

func SetupEosSudoers() error {
	if err := FixEosSudoersFile(); err != nil {
		zap.L().Warn("Failed to write sudoers file", zap.Error(err))
		return err
	}
	zap.L().Info("✅ Added eos to sudoers")
	return nil
}

func CreateEosDirectories() error {
	dirs := []string{shared.EosVarDir, shared.EosLogDir}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0750); err != nil {
			zap.L().Warn("Failed to create directory", zap.String("path", dir), zap.Error(err))
			return err
		}
		zap.L().Info("✅ Directory ready", zap.String("path", dir))
	}
	return nil
}

func CheckEosSudoPermissions() (bool, error) {
	info, err := os.Stat(shared.EosSudoersPath)
	if os.IsNotExist(err) {
		return false, nil
	}
	if info.Mode().Perm() != 0440 {
		return false, fmt.Errorf("wrong permissions: %o", info.Mode().Perm())
	}
	contents, err := os.ReadFile(shared.EosSudoersPath)
	if err != nil {
		return false, err
	}
	if !strings.Contains(string(contents), "eos ALL=(ALL) NOPASSWD: /bin/systemctl") {
		return false, fmt.Errorf("incorrect content")
	}
	return true, nil
}

func FixEosSudoersFile() error {
	sudoersLine := "eos ALL=(ALL) NOPASSWD: /bin/systemctl"
	cmd := exec.Command(fmt.Sprintf("echo '%s' > /etc/sudoers.d/eos", sudoersLine))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to write sudoers file: %w", err)
	}
	cmd = exec.Command("chmod", "440", "/etc/sudoers.d/eos")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set sudoers permissions: %w", err)
	}
	zap.L().Info("✅ Fixed /etc/sudoers.d/eos file and permissions")
	return nil
}

func EnsureEosSudoReady() error {
	if err := CheckNonInteractiveSudo(); err != nil {
		zap.L().Warn("sudo check failed", zap.Error(err))
		if IsInteractive() {
			fmt.Println("Please run:")
			fmt.Println("  sudo -v")
			fmt.Println("Then rerun:")
			fmt.Println("  eos bootstrap")
			return fmt.Errorf("sudo session required")
		}
		return fmt.Errorf("sudo check failed: %w", err)
	}
	return nil
}
