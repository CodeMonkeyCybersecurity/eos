/* pkg/system/sudoers.go */

package system

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"go.uber.org/zap"
)

// EnsureSudoersEntryForEos ensures that the eos user can run specific privileged commands without being prompted for a password.
//
// This function performs the following steps:
// 1. Checks if the sudoers file `/etc/sudoers.d/eos` already exists.
//   - If it exists, it logs a success message and returns.
//
// 2. If it doesn't exist and `auto` is false, prompts the user to confirm creation.
//   - If the user declines, it logs a warning and exits gracefully.
//
// 3. Writes a sudoers entry allowing `eos` to:
//   - Run `systemctl start vault*`
//   - Read `	VaultAgentTokenPath = filepath.Join(EosRunDir, "vault_agent_eos.token")`
//   - Without a password prompt (NOPASSWD).
//
// 4. Sets the file permissions to `0440` (required by sudo).
// 5. Validates the sudoers file with `visudo -c` to ensure syntax is correct.
//   - If validation fails, it warns and returns an error.
//
// This function should be called during system setup or from `EnsureEosUser(...)` when needed.
func EnsureSudoersEntryForEos(log *zap.Logger, auto bool) error {
	const path = shared.SudoersEosPath
	const entry = shared.SudoersEosEntry

	log.Info("🔍 Checking for existing sudoers entry", zap.String("path", path))
	if _, err := os.Stat(path); err == nil {
		log.Info("✅ Sudoers file for eos already exists", zap.String("path", path))
		return nil
	}

	// Step 2: Prompt if not auto
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
