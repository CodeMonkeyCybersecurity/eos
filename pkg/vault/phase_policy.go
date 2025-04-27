// pkg/vault/phase_policy

package vault

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

// Make this the go-to for Step 2. Keep EnsureVault(...) clean by calling this inline.
func EnsureVaultUserLifecycle(log *zap.Logger, client *api.Client) error {
	if err := system.EnsureEosUser(true, false, log); err != nil {
		return err
	}
	if err := EnsureVaultDirs(log); err != nil {
		return err
	}
	if err := system.EnsureSudoersEntryForEos(log, true); err != nil {
		return err
	}
	if err := EnsureVaultAuthMethods(client, log); err != nil {
		return err
	}

	if err := TestSudoAccess(log); err != nil {
		return err

	}
	_, _, err := EnsureAppRole(client, log, DefaultAppRoleOptions())
	return err
}

/**/

/**/

/**/
func readAppRoleCredsFromDisk(log *zap.Logger) (string, string, error) {
	roleIDBytes, err := os.ReadFile(shared.RoleIDPath)
	if err != nil {
		return "", "", fmt.Errorf("read role_id from disk: %w", err)
	}
	secretIDBytes, err := os.ReadFile(shared.SecretIDPath)
	if err != nil {
		return "", "", fmt.Errorf("read secret_id from disk: %w", err)
	}
	roleID := strings.TrimSpace(string(roleIDBytes))
	secretID := strings.TrimSpace(string(secretIDBytes))

	log.Info("📄 Loaded AppRole credentials from disk",
		zap.String("role_id_path", shared.RoleIDPath),
		zap.String("secret_id_path", shared.SecretIDPath),
	)
	return roleID, secretID, nil
}

/**/

/**/

/**/

/**/
func TestSudoAccess(log *zap.Logger) error {
	cmd := exec.Command("sudo", "-u", shared.EosID, "cat", shared.VaultAgentTokenPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Warn("❌ sudo -u eos failed", zap.Error(err), zap.String("output", string(out)))
		return fmt.Errorf("sudo check failed")
	}
	log.Info("✅ sudo test succeeded")
	return nil
}

/**/
