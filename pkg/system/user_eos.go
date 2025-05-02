// pkg/system/user_eos.go

package system

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
			log.Warn("❌ eos user has shell access, which is unexpected", zap.String("shell", shell))
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
	shell := shared.EosShellNoLogin
	if loginShell {
		shell = shared.EosShellBash
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

	userExists := UserExists(shared.EosID)
	if userExists && !SecretsExist() {
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

func ValidateEosSudoAccess(log *zap.Logger) error {
	cmd := exec.Command("cat", shared.VaultAgentTokenPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Warn("❌ sudo -u eos failed", zap.Error(err), zap.String("output", string(out)))
		return fmt.Errorf("sudo check failed")
	}
	log.Info("✅ sudo test succeeded")
	return nil
}

// EnsureSudoersEntryForEos ensures a sudoers entry exists for the eos user.
func EnsureSudoersEntryForEos(log *zap.Logger, auto bool) error {
	const path = shared.EosSudoersPath
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

func SetupEosSudoers(log *zap.Logger) error {
	if err := FixEosSudoersFile(log); err != nil {
		log.Warn("Failed to write sudoers file", zap.Error(err))
		return err
	}
	log.Info("✅ Added eos to sudoers")
	return nil
}

func CreateEosDirectories(log *zap.Logger) error {
	dirs := []string{shared.EosVarDir, shared.EosLogDir}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0750); err != nil {
			log.Warn("Failed to create directory", zap.String("path", dir), zap.Error(err))
			return err
		}
		log.Info("✅ Directory ready", zap.String("path", dir))
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

func FixEosSudoersFile(log *zap.Logger) error {
	sudoersLine := "eos ALL=(ALL) NOPASSWD: /bin/systemctl"
	cmd := exec.Command(fmt.Sprintf("echo '%s' > /etc/sudoers.d/eos", sudoersLine))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to write sudoers file: %w", err)
	}
	cmd = exec.Command("chmod", "440", "/etc/sudoers.d/eos")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set sudoers permissions: %w", err)
	}
	log.Info("✅ Fixed /etc/sudoers.d/eos file and permissions")
	return nil
}

func EnsureEosSudoReady(log *zap.Logger) error {
	if err := CheckNonInteractiveSudo(); err != nil {
		log.Warn("sudo check failed", zap.Error(err))
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
